//! Local daemon HTTP/JSON IPC.

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

pub const DEFAULT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 47831);

pub fn serve(listener: TcpListener, db_path: PathBuf) -> Result<()> {
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let db = db_path.clone();
                thread::spawn(move || {
                    if let Err(e) = handle(stream, &db) {
                        eprintln!("daemon request: {e:#}");
                    }
                });
            }
            Err(e) => eprintln!("daemon listener: {e}"),
        }
    }
    Ok(())
}

fn handle(mut stream: TcpStream, db_path: &Path) -> Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    while request.len() < 8192 && !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..n]);
    }
    let line = String::from_utf8_lossy(&request);
    let route = line.lines().next().unwrap_or("");
    let (status, content_type, body) = match route {
        "GET /health HTTP/1.1" | "GET /health HTTP/1.0" => ("200 OK", "application/json", "{\"status\":\"ok\"}".to_owned()),
        "GET /api/reports HTTP/1.1" | "GET /api/reports HTTP/1.0" => {
            let store = crate::store::Store::open(db_path)?;
            let reports = store.latest_reports(crate::model::Severity::Info)?;
            ("200 OK", "application/json", serde_json::to_string(&reports)?)
        }
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found".to_owned()),
    };
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}", body.len())?;
    Ok(())
}

pub fn start(db_path: PathBuf) -> Result<SocketAddr> {
    let listener = TcpListener::bind(DEFAULT_ADDR).with_context(|| format!("binding local daemon at {DEFAULT_ADDR}"))?;
    let addr = listener.local_addr()?;
    thread::Builder::new().name("doubleagent-ipc".into()).spawn(move || {
        if let Err(e) = serve(listener, db_path) {
            eprintln!("daemon server: {e:#}");
        }
    })?;
    Ok(addr)
}

/// Client side: is a DoubleAgent service (daemon or desktop app) listening at `addr`?
pub fn probe(addr: SocketAddr) -> bool {
    agent()
        .get(format!("http://{addr}/health"))
        .call()
        .ok()
        .and_then(|mut response| response.body_mut().read_to_string().ok())
        .is_some_and(|body| body.contains("\"status\":\"ok\""))
}

/// Latest verdicts held by a running service.
pub fn fetch_reports(addr: SocketAddr) -> Result<Vec<crate::model::Report>> {
    agent()
        .get(format!("http://{addr}/api/reports"))
        .call()
        .context("asking the DoubleAgent service for reports")?
        .body_mut()
        .read_json()
        .context("reading the service's reports")
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_millis(1500)))
        .build()
        .into()
}

pub fn write_service_files(directory: &Path, executable: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(directory).with_context(|| format!("creating {}", directory.display()))?;
    let exe = executable.display().to_string();
    #[cfg(target_os = "linux")]
    let files = vec![("doubleagent.service", format!("[Unit]\nDescription=DoubleAgent agent-instruction monitor\nAfter=default.target\n\n[Service]\nType=simple\nExecStart=\"{}\" daemon\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n", exe.replace('\\', "\\\\").replace('"', "\\\"")))];
    #[cfg(target_os = "macos")]
    let files = vec![("com.doubleagent.monitor.plist", format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>com.doubleagent.monitor</string><key>ProgramArguments</key><array><string>{}</string><string>daemon</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n", exe.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")))];
    #[cfg(windows)]
    let files = {
        let vbs_exe = exe.replace('"', "\"\"");
        let runner = format!("Set shell = CreateObject(\"WScript.Shell\")\ncommand = \"\"\"\" & \"{vbs_exe}\" & \"\"\" daemon\nshell.Run command, 0, False\n");
        let script = "$runner = Join-Path $PSScriptRoot 'run-doubleagent-hidden.vbs'\n$action = New-ScheduledTaskAction -Execute \"$env:WINDIR\\System32\\wscript.exe\" -Argument \"//B //NoLogo `\"$runner`\"\"\n$trigger = New-ScheduledTaskTrigger -AtLogOn\n$settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero)\nRegister-ScheduledTask -TaskName 'DoubleAgent' -Action $action -Trigger $trigger -Settings $settings -Description 'Monitor agent instruction files' -Force\n";
        vec![
            ("install-doubleagent-task.ps1", script.to_owned()),
            ("run-doubleagent-hidden.vbs", runner),
        ]
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let files: Vec<(&str, String)> = vec![];
    let mut paths = Vec::new();
    for (name, content) in files {
        let path = directory.join(name);
        std::fs::write(&path, content)?;
        paths.push(path);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    #[test]
    fn local_ipc_serves_health_and_reports_without_html() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("state.db");
        crate::store::Store::open(&db).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let db_for_server = db.clone();
        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().unwrap();
                handle(stream, &db_for_server).unwrap();
            }
        });
        for (path, expected) in [("/health", "{\"status\":\"ok\"}"), ("/api/reports", "[]"), ("/", "404 Not Found")] {
            let mut stream = TcpStream::connect(addr).unwrap();
            write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut response = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => response.extend_from_slice(&chunk[..n]),
                }
            }
            let response = String::from_utf8_lossy(&response);
            assert!(response.contains(expected), "{response}");
        }
        server.join().unwrap();
    }

    #[test]
    fn service_files_are_generated_for_current_platform() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("doubleagent.exe");
        let files = write_service_files(temp.path(), &executable).unwrap();
        #[cfg(windows)]
        {
            assert_eq!(files.len(), 2);
            let task = std::fs::read_to_string(&files[0]).unwrap();
            let runner = std::fs::read_to_string(&files[1]).unwrap();
            assert!(task.contains("wscript.exe"));
            assert!(task.contains("-Hidden"));
            assert!(runner.contains("shell.Run command, 0, False"));
        }
        #[cfg(not(windows))]
        {
            assert_eq!(files.len(), 1);
            let text = std::fs::read_to_string(&files[0]).unwrap();
            assert!(text.contains("daemon"));
        }
    }

    #[test]
    fn client_detects_and_reads_a_running_service() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("state.db");
        crate::store::Store::open(&db).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let _ = serve(listener, db);
        });
        assert!(probe(addr));
        assert!(fetch_reports(addr).unwrap().is_empty());

        let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        assert!(!probe(closed_addr));
    }
}
