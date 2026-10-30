//! Enumerating every user account on the PC and the programs installed under each of them.
//!
//! Per-user programs live in each account's `NTUSER.DAT` hive. For the account that is signed in
//! and running this app, that hive is `HKCU`. For other accounts it is only mounted under
//! `HKU\<sid>` while they are signed in; otherwise we load `NTUSER.DAT` from the profile folder
//! with RegLoadKey, read it, and unload it again. Loading hives needs administrator rights.

use crate::programs::Program;
use std::collections::HashMap;
use std::path::Path;

/// A Windows account on this PC.
#[derive(Debug, Clone)]
pub struct UserProfile {
    pub sid: String,
    pub name: String,
    pub profile_dir: String,
}

/// The account running this process, e.g. "Alice".
pub fn current_user() -> String {
    std::env::var("USERNAME").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "This user".into())
}

/// SID of the account running this process, so we can skip reloading our own hive.
fn current_sid() -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut buf = vec![0u64; 64]; // 512 bytes, 8-byte aligned for TOKEN_USER
        let mut len = 0u32;
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), 512, &mut len) != 0;
        CloseHandle(token);
        if !ok {
            return None;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut text = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return None;
        }
        let n = (0..).take_while(|&i| *text.add(i) != 0).count();
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
        LocalFree(text.cast());
        Some(sid)
    }
}

/// Mounts a hive file under `HKU\<mount>` (needs the backup/restore rights of an administrator).
fn load_hive(mount: &str, file: &Path) -> bool {
    use windows_sys::Win32::System::Registry::{RegLoadKeyW, HKEY_USERS};
    crate::unlock::enable_privileges();
    let (m, f) = (crate::util::wide(mount), crate::util::wide(&file.to_string_lossy()));
    unsafe { RegLoadKeyW(HKEY_USERS, m.as_ptr(), f.as_ptr()) == 0 }
}

fn unload_hive(mount: &str) -> bool {
    use windows_sys::Win32::System::Registry::{RegUnLoadKeyW, HKEY_USERS};
    let m = crate::util::wide(mount);
    unsafe { RegUnLoadKeyW(HKEY_USERS, m.as_ptr()) == 0 }
}

/// Real, human user profiles (skips SYSTEM, LOCAL/NETWORK SERVICE and the default profile).
pub fn list_profiles() -> Vec<UserProfile> {
    const LIST: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    let Some(key) = crate::reg::open(LIST) else { return Vec::new() };
    let mut out = Vec::new();
    for sid in crate::reg::subkeys(&key) {
        // Human accounts are S-1-5-21-… ; service SIDs (S-1-5-18/19/20) are shorter and skipped.
        if !sid.starts_with("S-1-5-21-") {
            continue;
        }
        let Ok(sub) = key.open_subkey(&sid) else { continue };
        let Some(dir) = crate::reg::string(&sub, "ProfileImagePath") else { continue };
        let dir = crate::util::expand_env(&dir);
        if !Path::new(&dir).is_dir() {
            continue;
        }
        let name = account_name(&sid).unwrap_or_else(|| leaf(&dir));
        out.push(UserProfile { sid, name, profile_dir: dir });
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

/// Looks up the display account name for a SID via its profile's folder name, falling back to the
/// SID. (A full LookupAccountSid would need extra Win32; the folder name matches in almost all
/// real setups and this is only a label.)
fn account_name(sid: &str) -> Option<String> {
    let key = crate::reg::open(&format!(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"))?;
    let dir = crate::reg::string(&key, "ProfileImagePath")?;
    Some(leaf(&crate::util::expand_env(&dir)))
}

fn leaf(path: &str) -> String {
    path.trim_end_matches('\\').rsplit('\\').next().unwrap_or(path).to_string()
}

/// Every per-user program across all accounts, each tagged with the owning account(s). Entries
/// that several users share (same name and version) are merged, listing all their users.
pub fn list_all_users_programs() -> Vec<Program> {
    let me_sid = current_sid();
    let me = current_user();
    let mut merged: HashMap<String, Program> = HashMap::new();

    for profile in list_profiles() {
        let is_me = me_sid.as_deref() == Some(profile.sid.as_str());
        let programs = if is_me {
            // Already mounted as HKCU; relabel the current user's entries with their real name.
            let mut v = crate::programs::read_user_hive_current();
            for p in &mut v {
                p.users = vec![me.clone()];
            }
            v
        } else {
            with_user_hive(&profile, |hku_sid| crate::programs::read_user_hive(hku_sid, &profile.name))
        };
        for p in programs {
            let key = format!("{}|{}", crate::util::normalize(&p.name), p.version.clone().unwrap_or_default());
            merged
                .entry(key)
                .and_modify(|existing| {
                    for u in &p.users {
                        if !existing.users.contains(u) {
                            existing.users.push(u.clone());
                        }
                    }
                })
                .or_insert(p);
        }
    }
    let mut out: Vec<Program> = merged.into_values().collect();
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

/// Mounts a profile's `NTUSER.DAT` under a temporary `HKU` key, runs `f` with that key's SID
/// path, then unloads it. If the hive is already mounted (user signed in), uses it in place
/// without loading or unloading.
fn with_user_hive<T>(profile: &UserProfile, f: impl FnOnce(&str) -> T) -> T
where
    T: Default,
{
    // Already mounted (the user is signed in)?
    if crate::reg::exists(&format!(r"HKU\{}\SOFTWARE", profile.sid)) {
        return f(&profile.sid);
    }
    let dat = Path::new(&profile.profile_dir).join("NTUSER.DAT");
    if !dat.is_file() {
        return T::default();
    }
    let mount = format!("PuirkleUA_{}", profile.sid.replace('-', "_"));
    if !load_hive(&mount, &dat) {
        return T::default();
    }
    let result = f(&mount);
    // The hive stays in use until every key handle into it is closed; a short retry covers the race.
    for _ in 0..5 {
        if unload_hive(&mount) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    result
}
