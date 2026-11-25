//! routerctl — command client for dpdk-tunnel-router.
//!
//! The client has no configuration database of its own.  It has two modes:
//!
//! * **read mode** — `show` commands and navigation;
//! * **configuration mode** — `set` / `delete` edit a candidate held by the
//!   core session, and `save` installs and persists it.
//!
//! A one-shot `routerctl set ...` is a convenience transaction: it enters
//! configuration mode, edits, saves, and leaves.  Interactive use exposes the
//! modes explicitly.

use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_SOCKET: &str = "run/ctl.sock";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Read,
    Config,
}

struct Args {
    socket: PathBuf,
    command: Option<String>,
    file: Option<PathBuf>,
    quiet: bool,
}

fn usage(prog: &str) {
    eprintln!(
        "Usage: {prog} [--socket PATH] [--file FILE] [--quiet] [command ...]\n\
         \n\
         Interactive use starts in read mode:\n\
         \x20 router> configure\n\
         \x20 router(config)> set interfaces ethernet eth0 address 192.0.2.1/24\n\
         \x20 router(config)> save\n\
         \x20 router(config)> exit\n\
         \x20 router> show interfaces\n\
         \n\
         Read mode accepts show/help/configure/exit.  Configuration mode\n\
         accepts set, delete/del, save/commit, discard/rollback, show and\n\
         read/exit.  Exiting with unsaved changes is refused; use save or\n\
         discard first.\n\
         \n\
         Debug capture (available in both modes):\n\
         \x20 {prog} tcpdump start interface eth0 -w /tmp/eth0.pcap -c 100\n\
         \x20 {prog} tcpdump status\n\
         \x20 {prog} tcpdump stop\n\
         \n\
         One-shot set/delete is a complete configure + save transaction.\n\
         --file applies a command file as one configure + save transaction.\n\
         \n\
         Examples:\n\
         \x20 {prog} show status\n\
         \x20 {prog} set interfaces ethernet eth0 address 192.0.2.1/24\n\
         \x20 {prog} --file router.conf\n"
    );
}

fn parse_args() -> Result<Args, String> {
    let mut args = env::args();
    let prog = args.next().unwrap_or_else(|| "routerctl".into());
    let mut socket = env::var_os("ROUTERCTL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    let mut rest = Vec::new();
    let mut file = None;
    let mut quiet = false;
    while let Some(a) = args.next() {
        // Global options are only recognized before the command.  After the
        // first command word everything (including -s/-i/-w) is forwarded.
        if !rest.is_empty() {
            rest.push(a);
            continue;
        }
        match a.as_str() {
            "--socket" | "-s" => {
                socket = PathBuf::from(args.next().ok_or("--socket requires a path")?);
            }
            "--file" | "-f" => {
                file = Some(PathBuf::from(args.next().ok_or("--file requires a path")?));
            }
            "--quiet" | "-q" => quiet = true,
            "--" => {
                rest.extend(args);
                break;
            }
            "--help" | "-h" => {
                usage(&prog);
                std::process::exit(0);
            }
            _ if a.starts_with('-') && rest.is_empty() => {
                return Err(format!("unknown option '{a}'"));
            }
            _ => rest.push(a),
        }
    }
    Ok(Args {
        socket,
        command: if rest.is_empty() {
            None
        } else {
            Some(rest.join(" "))
        },
        file,
        quiet,
    })
}

/// Resolve a relative `tcpdump -w FILE` path against the CLI's cwd, so the
/// captured file lands where the operator invoked routerctl rather than
/// wherever the core daemon happens to run.
fn absolutize_capture_path(command: &str) -> String {
    let words: Vec<&str> = command.split_whitespace().collect();
    if words.is_empty() || (words[0] != "tcpdump" && words[0] != "capture") {
        return command.to_string();
    }
    let mut out: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    for i in 0..words.len() {
        if words[i] == "filter" {
            break;
        }
        if words[i] == "-w" || words[i] == "file" || words[i] == "output" {
            if i + 1 < words.len() {
                let path = Path::new(words[i + 1]);
                if !path.is_absolute() {
                    if let Ok(cwd) = env::current_dir() {
                        out[i + 1] = cwd.join(path).to_string_lossy().into_owned();
                    }
                }
            }
            break;
        }
    }
    out.join(" ")
}

struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Client {
    fn connect(path: &PathBuf) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        let writer = stream.try_clone()?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
        })
    }

    fn execute(&mut self, command: &str) -> io::Result<Response> {
        let command = absolutize_capture_path(command);
        self.writer.write_all(command.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        let mut header = String::new();
        // The protocol is a single short status line.
        let mut byte = [0u8; 1];
        loop {
            let n = self.reader.read(&mut byte)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "router closed the control socket",
                ));
            }
            if byte[0] == b'\n' {
                break;
            }
            header.push(byte[0] as char);
            if header.len() > 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed response",
                ));
            }
        }
        let mut parts = header.split_whitespace();
        let status = parts.next().unwrap_or("");
        let len: usize = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad length"))?;
        if len > 16 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        let mut body = vec![0u8; len];
        self.reader.read_exact(&mut body)?;
        Ok(Response {
            ok: status == "OK",
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }
}

struct Response {
    ok: bool,
    body: String,
}

fn print_response(resp: &Response, quiet: bool, err: &mut impl Write) -> bool {
    if resp.ok {
        if !quiet {
            print!("{}", resp.body);
            let _ = io::stdout().flush();
        }
        true
    } else {
        let _ = err.write_all(resp.body.as_bytes());
        let _ = err.flush();
        false
    }
}

fn run_line(client: &mut Client, line: &str, quiet: bool) -> bool {
    match client.execute(line) {
        Ok(resp) => print_response(&resp, quiet, &mut io::stderr()),
        Err(e) => {
            eprintln!("routerctl: {e}");
            false
        }
    }
}

fn print_error_body(resp: &Response) {
    eprint!("{}", resp.body);
    if !resp.body.ends_with('\n') {
        eprintln!();
    }
}

fn first_word(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

fn is_edit_command(line: &str) -> bool {
    matches!(first_word(line), "set" | "delete" | "del")
}

fn is_mode_command(line: &str) -> bool {
    matches!(
        first_word(line),
        "configure"
            | "config"
            | "read"
            | "exit"
            | "end"
            | "quit"
            | "save"
            | "commit"
            | "discard"
            | "rollback"
    )
}

/// Run a batch as one candidate transaction: configure, edits, save, exit.
fn run_transaction(client: &mut Client, commands: &[String], quiet: bool) -> bool {
    match client.execute("configure") {
        Ok(resp) if resp.ok => {}
        Ok(resp) => {
            print_error_body(&resp);
            return false;
        }
        Err(e) => {
            eprintln!("routerctl: {e}");
            return false;
        }
    }
    for command in commands {
        match client.execute(command) {
            Ok(resp) if resp.ok => {}
            Ok(resp) => {
                print_error_body(&resp);
                let _ = client.execute("discard");
                let _ = client.execute("exit");
                return false;
            }
            Err(e) => {
                eprintln!("routerctl: {e}");
                return false;
            }
        }
    }
    match client.execute("save") {
        Ok(resp) if resp.ok => {
            if !quiet {
                print!("{}", resp.body);
                let _ = io::stdout().flush();
            }
        }
        Ok(resp) => {
            print_error_body(&resp);
            let _ = client.execute("discard");
            let _ = client.execute("exit");
            return false;
        }
        Err(e) => {
            eprintln!("routerctl: {e}");
            return false;
        }
    }
    let _ = client.execute("exit");
    true
}

fn read_file_commands(path: &PathBuf) -> Result<Vec<String>, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut commands = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| e.to_string())?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if is_mode_command(line) {
            return Err(format!(
                "{}: mode command '{line}' is not allowed in --file",
                path.display()
            ));
        }
        commands.push(line.to_string());
    }
    Ok(commands)
}

fn interactive(client: &mut Client, quiet: bool) -> bool {
    let stdin = io::stdin();
    let mut mode = Mode::Read;
    let mut ok = true;
    loop {
        print!(
            "{}",
            match mode {
                Mode::Read => "router> ",
                Mode::Config => "router(config)> ",
            }
        );
        let _ = io::stdout().flush();
        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match (mode, first_word(line)) {
            (Mode::Read, "quit" | "exit" | "end") => break,
            (Mode::Config, "quit") => {
                // Refuse to throw away a candidate silently.
                match client.execute("exit") {
                    Ok(resp) if resp.ok => {
                        mode = Mode::Read;
                        break;
                    }
                    Ok(resp) => print_error_body(&resp),
                    Err(e) => eprintln!("routerctl: {e}"),
                }
            }
            (Mode::Config, "read" | "exit" | "end") => match client.execute(line) {
                Ok(resp) if resp.ok => {
                    if !quiet {
                        print!("{}", resp.body);
                        let _ = io::stdout().flush();
                    }
                    mode = Mode::Read;
                }
                Ok(resp) => print_error_body(&resp),
                Err(e) => eprintln!("routerctl: {e}"),
            },
            (Mode::Read, "configure" | "config") => match client.execute(line) {
                Ok(resp) if resp.ok => {
                    if !quiet {
                        print!("{}", resp.body);
                        let _ = io::stdout().flush();
                    }
                    mode = Mode::Config;
                }
                Ok(resp) => print_error_body(&resp),
                Err(e) => eprintln!("routerctl: {e}"),
            },
            _ => {
                if !run_line(client, line, quiet) {
                    ok = false;
                }
            }
        }
    }
    if mode == Mode::Config {
        // EOF / read error while still in configuration mode: ask the core
        // whether the candidate is clean instead of discarding silently.
        if let Ok(resp) = client.execute("exit") {
            if !resp.ok {
                print_error_body(&resp);
                ok = false;
            }
        }
    }
    ok
}

fn stdin_script(client: &mut Client, quiet: bool) -> bool {
    let stdin = io::stdin();
    let mut ok = true;
    let mut exited = false;
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("routerctl: {e}");
                return false;
            }
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "quit" {
            // Refuse to silently discard a dirty candidate.
            exited = true;
            if let Ok(resp) = client.execute("exit") {
                if !resp.ok {
                    print_error_body(&resp);
                    ok = false;
                }
            }
            break;
        }
        if !run_line(client, line, quiet) {
            ok = false;
        }
    }
    // A piped script that ends in configuration mode without save/discard
    // must not exit with success.
    if !exited {
        if let Ok(resp) = client.execute("exit") {
            if !resp.ok {
                print_error_body(&resp);
                ok = false;
            }
        }
    }
    ok
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("routerctl: {e}");
            usage("routerctl");
            return ExitCode::from(2);
        }
    };
    let mut client = match Client::connect(&args.socket) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "routerctl: cannot connect to {}: {e}",
                args.socket.display()
            );
            return ExitCode::FAILURE;
        }
    };

    if let Some(command) = args.command {
        if command == "configure" || command == "config" {
            eprintln!(
                "routerctl: configuration mode is interactive; run 'routerctl' \
                 or use --file for a batch transaction"
            );
            return ExitCode::from(2);
        }
        if is_edit_command(&command) {
            return if run_transaction(&mut client, &[command], args.quiet) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        return if run_line(&mut client, &command, args.quiet) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    if let Some(path) = args.file {
        let commands = match read_file_commands(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("routerctl: {e}");
                return ExitCode::FAILURE;
            }
        };
        return if run_transaction(&mut client, &commands, args.quiet) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let stdin = io::stdin();
    let ok = if stdin.is_terminal() {
        interactive(&mut client, args.quiet)
    } else {
        stdin_script(&mut client, args.quiet)
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
