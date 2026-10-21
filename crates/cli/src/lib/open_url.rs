//! Best-effort open of a URL in the user's default browser. Port of
//! `packages/cli/src/lib/open-url.ts`. NEVER fails and never blocks: callers always print the
//! URL too, so a headless box can open it manually.

pub fn open_browser(url: &str) {
    let (cmd, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else if cfg!(windows) {
        ("cmd", vec!["/c", "start", "", url])
    } else {
        ("xdg-open", vec![url])
    };
    let _ = std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}
