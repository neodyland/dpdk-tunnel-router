//! routerctl — thin command client for dpdk-tunnel-router.
//!
//! The binary intentionally contains no router state: every line is sent to
//! the C core over a Unix socket, which owns configuration, data-plane
//! objects, persistence, and validation.

use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_SOCKET: &str = "run/ctl.sock";

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
         With no command, routerctl reads commands from stdin.  On a terminal\n\
         it starts a small interactive shell.  Each command is executed by\n\
         the router core; the CLI keeps no state.\n\
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
        return if run_line(&mut client, &command, args.quiet) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let mut ok = true;
    if let Some(path) = args.file {
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("routerctl: {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("routerctl: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !run_line(&mut client, line, args.quiet) {
                ok = false;
            }
        }
        return if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        loop {
            print!("router# ");
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
            if line == "quit" || line == "exit" {
                break;
            }
            if !run_line(&mut client, line, args.quiet) {
                ok = false;
            }
        }
    } else {
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("routerctl: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !run_line(&mut client, line, args.quiet) {
                ok = false;
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
