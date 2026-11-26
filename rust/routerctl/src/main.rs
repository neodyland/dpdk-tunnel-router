//! routerctl — command client for dpdk-tunnel-router.
//!
//! The client has no configuration database of its own.  It has two modes:
//!
//! * **read mode** — `show` commands and navigation;
//! * **configuration mode** — `set` / `delete` edit a candidate held by the
//!   core session; `commit` applies it to the running data plane and `save`
//!   persists the running configuration.
//!
//! A one-shot `routerctl set ...` is a convenience transaction: it enters
//! configuration mode, edits, commits, saves, and leaves.  Interactive use
//! exposes the modes explicitly.

use std::env;
use std::ffi::c_void;
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
         \x20 router(config)> commit\n\
         \x20 router(config)> save\n\
         \x20 router(config)> exit\n\
         \x20 router> show interfaces\n\
         \n\
         Read mode accepts show/help/configure/exit.  Configuration mode\n\
         accepts set, delete/del, commit, save, discard/rollback, show and\n\
         read/exit.  commit applies the candidate to the running data plane;\n\
         save writes the running configuration to disk.\n\
         Exiting with uncommitted or unsaved changes is refused.\n\
         \n\
         Context help: end a command with ? or use 'help <path>'.\n\
         \x20 {prog} set interfaces ethernet eth1 '?'\n\
         \n\
         Interactive line editing: Up/Down history, Left/Right/Home/End,\n\
         Backspace/Delete, Ctrl-L clear, Ctrl-C cancel, Ctrl-D EOF.\n\
         \n\
         Debug capture (available in both modes):\n\
         \x20 {prog} tcpdump start interface eth0 -w /tmp/eth0.pcap -c 100\n\
         \x20 {prog} tcpdump status\n\
         \x20 {prog} tcpdump stop\n\
         \n\
         One-shot set/delete is a complete configure + commit + save\n\
         transaction.  --file applies a command file the same way.\n\
         \n\
         Examples:\n\
         \x20 {prog} show status\n\
         \x20 {prog} show neighbors\n\
         \x20 {prog} ping 192.0.2.1 count 2\n\
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

fn is_help_command(line: &str) -> bool {
    if first_word(line) == "help" {
        return true;
    }
    let last = line.split_whitespace().last().unwrap_or("");
    last == "?" || (last.len() > 1 && last.ends_with('?'))
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

/// Run a batch as one transaction: configure, edits, commit, save, exit.
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
    for command in ["commit", "save"] {
        match client.execute(command) {
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

// ---------------------------------------------------------------------------
// Small terminal line editor
//
// We deliberately avoid an external crate.  The interactive shell only needs
// history navigation (Up/Down) and basic cursor editing, so a compact Linux
// termios implementation is enough.
// ---------------------------------------------------------------------------

const TCSANOW: i32 = 0;
const ICANON: u32 = 0o000002;
const ECHO: u32 = 0o000010;
const ECHOE: u32 = 0o000020;
const ECHOK: u32 = 0o000040;
const ECHONL: u32 = 0o000100;
const ISIG: u32 = 0o000001;
const IEXTEN: u32 = 0o100000;
const VMIN: usize = 6;
const VTIME: usize = 5;
const POLLIN: i16 = 0x0001;
const HISTORY_MAX: usize = 500;

#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

extern "C" {
    fn isatty(fd: i32) -> i32;
    fn tcgetattr(fd: i32, termios: *mut Termios) -> i32;
    fn tcsetattr(fd: i32, action: i32, termios: *const Termios) -> i32;
    fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
    fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
}

struct RawTerminal {
    original: Termios,
}

impl RawTerminal {
    fn new() -> io::Result<Self> {
        unsafe {
            if isatty(0) != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "stdin is not a terminal",
                ));
            }
            let mut original: Termios = std::mem::zeroed();
            if tcgetattr(0, &mut original) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut raw = original;
            raw.c_lflag &= !(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL | IEXTEN);
            raw.c_cc[VMIN] = 1;
            raw.c_cc[VTIME] = 0;
            if tcsetattr(0, TCSANOW, &raw) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { original })
        }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        unsafe {
            let _ = tcsetattr(0, TCSANOW, &self.original);
        }
    }
}

fn read_byte() -> io::Result<Option<u8>> {
    loop {
        let mut b = 0u8;
        let n = unsafe { read(0, &mut b as *mut u8 as *mut c_void, 1) };
        if n == 1 {
            return Ok(Some(b));
        }
        if n == 0 {
            return Ok(None);
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(e);
    }
}

fn input_ready(timeout_ms: i32) -> bool {
    let mut p = PollFd {
        fd: 0,
        events: POLLIN,
        revents: 0,
    };
    unsafe { poll(&mut p, 1, timeout_ms) > 0 && (p.revents & POLLIN) != 0 }
}

enum Key {
    Char(char),
    Enter,
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    CtrlC,
    CtrlD,
    CtrlL,
    Unknown,
}

fn read_key() -> io::Result<Option<Key>> {
    let Some(b) = read_byte()? else {
        return Ok(None);
    };
    let key = match b {
        0x03 => Key::CtrlC,
        0x04 => Key::CtrlD,
        0x0c => Key::CtrlL,
        b'\r' | b'\n' => Key::Enter,
        0x7f | 0x08 => Key::Backspace,
        0x1b => {
            if !input_ready(25) {
                Key::Unknown
            } else {
                let Some(b1) = read_byte()? else {
                    return Ok(None);
                };
                if b1 != b'[' && b1 != b'O' {
                    Key::Unknown
                } else {
                    let Some(b2) = read_byte()? else {
                        return Ok(None);
                    };
                    match b2 {
                        b'A' => Key::Up,
                        b'B' => Key::Down,
                        b'C' => Key::Right,
                        b'D' => Key::Left,
                        b'H' => Key::Home,
                        b'F' => Key::End,
                        b'3' => {
                            let _ = read_byte()?; // consume '~'
                            Key::Delete
                        }
                        b'1' | b'7' => {
                            let _ = read_byte()?; // consume '~'
                            Key::Home
                        }
                        b'4' | b'8' => {
                            let _ = read_byte()?; // consume '~'
                            Key::End
                        }
                        _ => Key::Unknown,
                    }
                }
            }
        }
        c if c >= 0x20 && c < 0x7f => Key::Char(c as char),
        _ => Key::Unknown,
    };
    Ok(Some(key))
}

fn render_line(prompt: &str, chars: &[char], cursor: usize) -> io::Result<()> {
    let mut out = io::stdout();
    write!(out, "\r\x1b[K{prompt}")?;
    for c in chars {
        write!(out, "{c}")?;
    }
    let tail = chars.len() - cursor;
    if tail > 0 {
        write!(out, "\x1b[{tail}D")?;
    }
    out.flush()
}

fn history_push(history: &mut Vec<String>, line: &str) {
    if line.is_empty() {
        return;
    }
    if history.last().map(|s| s == line).unwrap_or(false) {
        return;
    }
    history.push(line.to_string());
    if history.len() > HISTORY_MAX {
        history.remove(0);
    }
}

fn read_line_raw(prompt: &str, history: &mut Vec<String>) -> io::Result<Option<String>> {
    let mut chars: Vec<char> = Vec::new();
    let mut cursor = 0usize;
    let mut hist_index: Option<usize> = None;
    let mut draft = String::new();
    render_line(prompt, &chars, cursor)?;
    loop {
        let Some(key) = read_key()? else {
            write!(io::stdout(), "\r\n")?;
            return Ok(None);
        };
        match key {
            Key::Enter => {
                write!(io::stdout(), "\r\n")?;
                let line: String = chars.iter().collect();
                history_push(history, &line);
                return Ok(Some(line));
            }
            Key::CtrlC => {
                write!(io::stdout(), "^C\r\n")?;
                return Ok(Some(String::new()));
            }
            Key::CtrlD => {
                if chars.is_empty() {
                    write!(io::stdout(), "\r\n")?;
                    return Ok(None);
                }
                if cursor < chars.len() {
                    chars.remove(cursor);
                }
                hist_index = None;
            }
            Key::CtrlL => {
                write!(io::stdout(), "\x1b[2J\x1b[H")?;
            }
            Key::Char(c) => {
                chars.insert(cursor, c);
                cursor += 1;
                hist_index = None;
            }
            Key::Backspace => {
                if cursor > 0 {
                    chars.remove(cursor - 1);
                    cursor -= 1;
                }
                hist_index = None;
            }
            Key::Delete => {
                if cursor < chars.len() {
                    chars.remove(cursor);
                }
                hist_index = None;
            }
            Key::Left => {
                if cursor > 0 {
                    cursor -= 1;
                }
            }
            Key::Right => {
                if cursor < chars.len() {
                    cursor += 1;
                }
            }
            Key::Home => {
                cursor = 0;
            }
            Key::End => {
                cursor = chars.len();
            }
            Key::Up => {
                if !history.is_empty() {
                    match hist_index {
                        None => {
                            draft = chars.iter().collect();
                            hist_index = Some(history.len() - 1);
                        }
                        Some(i) if i > 0 => hist_index = Some(i - 1),
                        Some(_) => {}
                    }
                    if let Some(i) = hist_index {
                        chars = history[i].chars().collect();
                        cursor = chars.len();
                    }
                }
            }
            Key::Down => match hist_index {
                Some(i) if i + 1 < history.len() => {
                    hist_index = Some(i + 1);
                    chars = history[i + 1].chars().collect();
                    cursor = chars.len();
                }
                Some(_) => {
                    hist_index = None;
                    chars = draft.chars().collect();
                    cursor = chars.len();
                }
                None => {}
            },
            Key::Unknown => {}
        }
        render_line(prompt, &chars, cursor)?;
    }
}

struct LineEditor {
    raw: Option<RawTerminal>,
}

impl LineEditor {
    fn new() -> Self {
        let raw = if io::stdin().is_terminal() {
            RawTerminal::new().ok()
        } else {
            None
        };
        Self { raw }
    }

    fn read_line(&self, prompt: &str, history: &mut Vec<String>) -> io::Result<Option<String>> {
        if self.raw.is_some() {
            return read_line_raw(prompt, history);
        }
        print!("{prompt}");
        io::stdout().flush()?;
        let mut line = String::new();
        let n = io::stdin().read_line(&mut line)?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(line))
    }
}

fn interactive(client: &mut Client, quiet: bool) -> bool {
    let mut mode = Mode::Read;
    let mut ok = true;
    let mut history: Vec<String> = Vec::new();
    let editor = LineEditor::new();
    loop {
        let prompt = match mode {
            Mode::Read => "router> ",
            Mode::Config => "router(config)> ",
        };
        let line = match editor.read_line(prompt, &mut history) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(e) => {
                eprintln!("routerctl: {e}");
                break;
            }
        };
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
        if is_edit_command(&command) && !is_help_command(&command) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termios_layout_is_linux_x86_64() {
        assert_eq!(std::mem::size_of::<Termios>(), 60);
    }

    #[test]
    fn history_push_deduplicates_and_caps() {
        let mut h = Vec::new();
        history_push(&mut h, "show status");
        history_push(&mut h, "show status");
        assert_eq!(h.len(), 1);
        for i in 0..(HISTORY_MAX + 10) {
            history_push(&mut h, &format!("cmd {i}"));
        }
        assert_eq!(h.len(), HISTORY_MAX);
    }
}
