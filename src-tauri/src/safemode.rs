//! Safe Mode: the supported way to remove self-protected software such as antivirus.
//!
//! In Safe Mode a security product's self-protection driver and services don't load, so its files,
//! services and registry keys can be deleted normally — Force Removal then works. This module
//! detects Safe Mode, restarts the PC into it on request, and makes sure the PC returns to normal
//! Windows afterwards instead of staying stuck in Safe Mode.
//!
//! We change only the boot menu's "safe boot" flag (the same switch as msconfig's "Safe boot"
//! checkbox) and ask Windows to restart. We never touch the antivirus's own protection.

use std::os::windows::process::CommandExt;
use std::process::Command;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CLEANBOOT};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Marks that it was PuirkleUninstaller that turned safe boot on, so we know to turn it back off.
const FLAG_KEY: &str = r"Software\PuirkleUninstaller";

/// True when Windows is currently running in Safe Mode (any variant).
pub fn in_safe_mode() -> bool {
    unsafe { GetSystemMetrics(SM_CLEANBOOT) != 0 }
}

fn bcdedit(args: &[&str]) -> bool {
    Command::new("bcdedit.exe").args(args).creation_flags(CREATE_NO_WINDOW).output().is_ok_and(|o| o.status.success())
}

fn set_flag(on: bool) {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(FLAG_KEY) {
        let _ = key.set_value("SetSafeBoot", &u32::from(on));
    }
}

fn we_set_safe_boot() -> bool {
    crate::reg::open(&format!(r"HKCU\{FLAG_KEY}")).and_then(|k| crate::reg::dword(&k, "SetSafeBoot")) == Some(1)
}

/// Turns the boot menu's safe-boot flag back off, so the next restart is normal Windows.
pub fn clear_safe_boot() {
    bcdedit(&["/deletevalue", "{current}", "safeboot"]);
    set_flag(false);
}

/// Called once at startup: if we're in Safe Mode because of us, clear the flag now so the user is
/// never stranded — opening the app is enough to get back to normal Windows on the next restart.
pub fn clear_on_startup() {
    if in_safe_mode() && we_set_safe_boot() {
        bcdedit(&["/deletevalue", "{current}", "safeboot"]);
        set_flag(false);
    }
}

/// Restarts the PC into Safe Mode so a self-protected program can be removed. Needs administrator
/// rights. The flag is one-off in spirit: the app clears it as soon as it next opens in Safe Mode.
pub fn restart_into_safe_mode() -> Result<(), String> {
    if in_safe_mode() {
        return Err("You're already in Safe Mode.".into());
    }
    if !crate::winproc::is_elevated() {
        return Err("Restart PuirkleUninstaller as administrator first (it needs admin rights to change the boot option).".into());
    }
    set_flag(true);
    if !bcdedit(&["/set", "{current}", "safeboot", "minimal"]) {
        set_flag(false);
        return Err("Windows didn't allow the boot option to change. You can still reach Safe Mode manually: hold Shift and choose Restart, then Troubleshoot → Advanced options → Startup Settings → Restart → 4.".into());
    }
    reboot();
    Ok(())
}

/// Clears safe boot and restarts back into normal Windows.
pub fn restart_normal() -> Result<(), String> {
    clear_safe_boot();
    if !crate::winproc::is_elevated() {
        return Err("Restart PuirkleUninstaller as administrator to restart the PC (the boot option has been cleared, so a normal restart will do it too).".into());
    }
    reboot();
    Ok(())
}

fn reboot() {
    let _ = Command::new("shutdown.exe")
        .args(["/r", "/t", "0", "/c", "PuirkleUninstaller is restarting Windows."])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}
