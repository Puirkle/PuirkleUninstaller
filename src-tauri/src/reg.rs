//! Thin helpers over winreg using "HKLM\path" style strings.

use winreg::enums::*;
use winreg::{RegKey, RegValue};

pub fn hive(root: &str) -> RegKey {
    match root {
        "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
        "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
        "HKU" => RegKey::predef(HKEY_USERS),
        _ => RegKey::predef(HKEY_CLASSES_ROOT),
    }
}

pub fn split(full: &str) -> (&str, &str) {
    full.split_once('\\').unwrap_or((full, ""))
}

pub fn open(full: &str) -> Option<RegKey> {
    let (root, path) = split(full);
    hive(root).open_subkey(path).ok()
}

pub fn exists(full: &str) -> bool {
    open(full).is_some()
}

pub fn subkeys(key: &RegKey) -> Vec<String> {
    key.enum_keys().filter_map(Result::ok).collect()
}

/// String data of a REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ value.
pub fn text(v: &RegValue) -> Option<String> {
    match v.vtype {
        RegType::REG_SZ | RegType::REG_EXPAND_SZ | RegType::REG_MULTI_SZ => {
            let b: &[u8] = &v.bytes;
            let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            Some(String::from_utf16_lossy(&u).replace('\0', " ").trim().to_string())
        }
        _ => None,
    }
}

pub fn string(key: &RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

pub fn dword(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

/// Default value of `sub` under `key`.
pub fn default_of(key: &RegKey, sub: &str) -> Option<String> {
    string(&key.open_subkey(sub).ok()?, "")
}

/// All string values of a key, joined, lowercase, environment-expanded. Used for path matching.
pub fn all_text(key: &RegKey) -> String {
    let mut out = String::new();
    for (_, v) in key.enum_values().filter_map(Result::ok) {
        if let Some(t) = text(&v) {
            out.push_str(&t);
            out.push(' ');
        }
    }
    crate::util::expand_env(&out).to_lowercase()
}
