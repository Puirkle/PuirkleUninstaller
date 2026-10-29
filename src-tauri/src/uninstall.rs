//! Runs a program's own uninstaller, and prepares a forced removal.

use crate::programs::Program;
use crate::util::{expand_env, hidden, powershell};
use crate::{leftovers, reg, winproc};
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub exit_code: Option<u32>,
    pub message: String,
    /// The program is still registered after the uninstaller finished (cancelled or failed).
    pub still_installed: bool,
    pub reboot_required: bool,
}

pub fn run(p: &Program, quiet: bool) -> Result<Outcome, String> {
    if p.kind == "store" {
        return remove_appx(p);
    }
    if p.kind == "portable" && p.uninstall_string.is_none() {
        return Err("This program has no uninstaller. Use Force Removal instead.".into());
    }
    let (file, params) = build_command(p, quiet)?;
    let code = winproc::run_and_wait(&file, &params)?;
    let still_installed = match p.registry_key.as_deref() {
        Some(k) => reg::exists(k),
        // A program found on disk is still there if its main exe still is.
        None => p.icon_path.as_deref().is_some_and(|i| Path::new(&crate::icons::parse_icon_spec(i).0).exists()),
    };
    let reboot_required = matches!(code, 3010 | 1641);
    let message = match code {
        _ if !still_installed && reboot_required => "Uninstalled. Restart Windows to finish removing it.".to_string(),
        _ if !still_installed => "Uninstalled successfully.".to_string(),
        1602 => "The uninstall was cancelled.".to_string(),
        1605 => "Windows Installer reports this product isn't installed. Force Removal can clean up what's left.".to_string(),
        0 => "The uninstaller closed, but the program is still registered.".to_string(),
        c => format!("The uninstaller exited with code {c} and the program is still registered."),
    };
    Ok(Outcome { exit_code: Some(code), message, still_installed, reboot_required })
}

fn build_command(p: &Program, quiet: bool) -> Result<(String, String), String> {
    if let Some(code) = &p.product_code {
        let u = p.uninstall_string.as_deref().unwrap_or("").to_lowercase();
        if u.is_empty() || u.contains("msiexec") {
            let extra = if quiet { " /passive /norestart" } else { "" };
            return Ok(("msiexec.exe".into(), format!("/x {code}{extra}")));
        }
    }
    let cmd = if quiet { p.quiet_uninstall_string.clone().or_else(|| p.uninstall_string.clone()) } else { p.uninstall_string.clone() }
        .ok_or("This program has no uninstaller registered. Use Force Removal instead.")?;
    let (file, mut params) = split_command(&cmd);
    let fp = Path::new(&file);
    if fp.is_absolute() && !fp.exists() {
        return Err(format!("The uninstaller is missing:\n{file}\n\nUse Force Removal to remove what's left."));
    }
    if quiet && p.quiet_uninstall_string.is_none() {
        let stem = fp.file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
        // Inno Setup: unins000.exe
        if stem.len() > 5 && stem.starts_with("unins") && stem[5..].chars().all(|c| c.is_ascii_digit()) {
            params.push_str(" /SILENT /NORESTART");
        }
    }
    Ok((file, params.trim().to_string()))
}

/// Splits an UninstallString into executable and arguments, coping with unquoted paths with spaces.
pub fn split_command(cmd: &str) -> (String, String) {
    let c = expand_env(cmd.trim());
    if let Some(rest) = c.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return (rest[..end].to_string(), rest[end + 1..].trim().to_string());
        }
    }
    for (i, ch) in c.char_indices() {
        if ch == ' ' {
            let cand = &c[..i];
            if Path::new(cand).is_file() || Path::new(&format!("{cand}.exe")).is_file() {
                return (cand.to_string(), c[i + 1..].trim().to_string());
            }
        }
    }
    if Path::new(&c).is_file() {
        return (c, String::new());
    }
    match c.split_once(' ') {
        Some((a, b)) => (a.to_string(), b.trim().to_string()),
        None => (c, String::new()),
    }
}

fn remove_appx(p: &Program) -> Result<Outcome, String> {
    let full = p.package_full_name.as_deref().ok_or("Missing package name.")?;
    powershell(&format!("$ErrorActionPreference='Stop'; Remove-AppxPackage -Package '{}'", full.replace('\'', "''")))?;
    Ok(Outcome { exit_code: Some(0), message: "App removed.".into(), still_installed: false, reboot_required: false })
}

/// Before a forced removal: kill processes running from the program's folders and stop its services.
pub fn prepare_force(p: &Program) -> Vec<String> {
    let dirs = leftovers::install_dirs(p);
    let mut actions: Vec<String> = winproc::kill_in_dirs(&dirs).into_iter().map(|path| format!("Closed {path}")).collect();
    for svc in leftovers::services_in(&dirs) {
        let ok = hidden("sc.exe").args(["stop", &svc]).status().is_ok_and(|s| s.success());
        if ok {
            actions.push(format!("Stopped service {svc}"));
        }
    }
    actions
}
