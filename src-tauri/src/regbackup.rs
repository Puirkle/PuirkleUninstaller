//! Backing up and restoring whole registry keys with the registry API, so no `reg.exe` is started
//! (security products such as 360 block hidden `reg export/import` as registry tampering).
//!
//! New backups are a JSON tree with every value's exact type and bytes. Backups made by older
//! versions are `.reg` exports; those are parsed here and written back the same way.

use crate::reg;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;
use winreg::enums::{RegType, KEY_READ};
use winreg::{RegKey, RegValue};

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Node {
    /// Full path, e.g. `HKCU\Software\Foo`.
    pub path: String,
    pub values: Vec<Value>,
    pub keys: Vec<Node>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Value {
    pub name: String,
    pub vtype: u32,
    /// base64 of the raw bytes
    pub data: String,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub fn reg_type(n: u32) -> RegType {
    use RegType::*;
    match n {
        0 => REG_NONE,
        1 => REG_SZ,
        2 => REG_EXPAND_SZ,
        4 => REG_DWORD,
        5 => REG_DWORD_BIG_ENDIAN,
        6 => REG_LINK,
        7 => REG_MULTI_SZ,
        8 => REG_RESOURCE_LIST,
        9 => REG_FULL_RESOURCE_DESCRIPTOR,
        10 => REG_RESOURCE_REQUIREMENTS_LIST,
        11 => REG_QWORD,
        _ => REG_BINARY,
    }
}

/// Reads `path` and everything under it.
pub fn read_tree(path: &str) -> Result<Node, String> {
    let (root, sub) = reg::split(path);
    let key = reg::hive(root).open_subkey_with_flags(sub, KEY_READ).map_err(|e| e.to_string())?;
    Ok(read_node(&key, path))
}

fn read_node(key: &RegKey, path: &str) -> Node {
    let values = key
        .enum_values()
        .filter_map(Result::ok)
        .map(|(name, v)| Value { name, vtype: v.vtype as u32, data: b64().encode(&v.bytes) })
        .collect();
    let keys = key
        .enum_keys()
        .filter_map(Result::ok)
        .filter_map(|name| key.open_subkey_with_flags(&name, KEY_READ).ok().map(|k| read_node(&k, &format!(r"{path}\{name}"))))
        .collect();
    Node { path: path.into(), values, keys }
}

/// Saves `path` (and everything under it) to `file` as JSON.
pub fn export(path: &str, file: &Path) -> Result<(), String> {
    let node = read_tree(path)?;
    let json = serde_json::to_string(&node).map_err(|e| e.to_string())?;
    std::fs::write(file, json).map_err(|e| e.to_string())
}

/// Writes a saved tree back. Returns how many values couldn't be written.
fn write_node(node: &Node) -> Result<usize, String> {
    let (root, sub) = reg::split(&node.path);
    let (key, _) = reg::hive(root).create_subkey(sub).map_err(|e| format!("{}: {e}", node.path))?;
    let mut failed = 0;
    for v in &node.values {
        let bytes = b64().decode(&v.data).unwrap_or_default();
        if key.set_raw_value(&v.name, &RegValue { bytes, vtype: reg_type(v.vtype) }).is_err() {
            failed += 1;
        }
    }
    for k in &node.keys {
        failed += write_node(k).unwrap_or(1);
    }
    Ok(failed)
}

/// Restores a key backup: a JSON tree from this version, or a `.reg` export from older ones.
pub fn restore(file: &Path) -> Result<(), String> {
    let nodes = if file.extension().is_some_and(|x| x.eq_ignore_ascii_case("reg")) {
        parse_reg(&read_reg_text(file)?)?
    } else {
        let text = std::fs::read_to_string(file).map_err(|e| e.to_string())?;
        vec![serde_json::from_str::<Node>(&text).map_err(|e| e.to_string())?]
    };
    let mut failed = 0;
    for n in &nodes {
        failed += write_node(n)?;
    }
    if failed > 0 {
        return Err(format!("{failed} value(s) couldn't be written (administrator rights needed for system keys)"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Looking at a key inside the app, so checking a leftover never needs Registry Editor (which
// security products may stop another program from opening).

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    pub path: String,
    pub exists: bool,
    pub values: Vec<ValueView>,
    pub subkeys: Vec<String>,
}

#[derive(Serialize)]
pub struct ValueView {
    pub name: String,
    #[serde(rename = "type")]
    pub vtype: String,
    pub data: String,
}

const VIEW_LIMIT: usize = 500;

/// The values and subkey names of `path`, with each value's data as readable text.
pub fn view(path: &str) -> KeyView {
    let (root, sub) = reg::split(path);
    let Ok(key) = reg::hive(root).open_subkey_with_flags(sub, KEY_READ) else {
        return KeyView { path: path.into(), exists: false, values: Vec::new(), subkeys: Vec::new() };
    };
    let mut values: Vec<ValueView> = key
        .enum_values()
        .filter_map(Result::ok)
        .take(VIEW_LIMIT)
        .map(|(name, v)| {
            let (vtype, data) = describe(&v);
            ValueView { name, vtype: vtype.into(), data }
        })
        .collect();
    values.sort_by_key(|v| (!v.name.is_empty(), v.name.to_lowercase()));
    let mut subkeys: Vec<String> = key.enum_keys().filter_map(Result::ok).take(VIEW_LIMIT).collect();
    subkeys.sort_by_key(|s| s.to_lowercase());
    KeyView { path: path.into(), exists: true, values, subkeys }
}

fn describe(v: &RegValue) -> (&'static str, String) {
    let b: &[u8] = &v.bytes;
    let utf16 = || {
        let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    };
    match v.vtype {
        RegType::REG_SZ => ("REG_SZ", utf16().trim_end_matches('\0').into()),
        RegType::REG_EXPAND_SZ => ("REG_EXPAND_SZ", utf16().trim_end_matches('\0').into()),
        RegType::REG_MULTI_SZ => {
            ("REG_MULTI_SZ", utf16().split('\0').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("  |  "))
        }
        RegType::REG_DWORD if b.len() >= 4 => {
            let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            ("REG_DWORD", format!("0x{n:08x} ({n})"))
        }
        RegType::REG_QWORD if b.len() >= 8 => {
            let n = u64::from_le_bytes(b[..8].try_into().unwrap());
            ("REG_QWORD", format!("0x{n:016x} ({n})"))
        }
        RegType::REG_BINARY => ("REG_BINARY", hex_preview(b)),
        RegType::REG_NONE => ("REG_NONE", hex_preview(b)),
        _ => ("REG_OTHER", hex_preview(b)),
    }
}

fn hex_preview(b: &[u8]) -> String {
    let mut s: String = b.iter().take(64).map(|x| format!("{x:02x} ")).collect();
    if b.len() > 64 {
        s.push_str(&format!("… ({} bytes)", b.len()));
    }
    s.trim_end().into()
}

// ---------------------------------------------------------------------------------------------
// .reg files written by `reg export` (UTF-16 LE, "Windows Registry Editor Version 5.00").

fn read_reg_text(file: &Path) -> Result<String, String> {
    let bytes = std::fs::read(file).map_err(|e| e.to_string())?;
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Ok(String::from_utf16_lossy(&units))
    } else {
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn short_root(path: &str) -> String {
    let (root, rest) = path.split_once('\\').unwrap_or((path, ""));
    let short = match root.to_uppercase().as_str() {
        "HKEY_LOCAL_MACHINE" => "HKLM",
        "HKEY_CURRENT_USER" => "HKCU",
        "HKEY_USERS" => "HKU",
        "HKEY_CLASSES_ROOT" => "HKCR",
        other => return format!("{other}\\{rest}"),
    };
    if rest.is_empty() { short.into() } else { format!("{short}\\{rest}") }
}

/// A quoted .reg string starting at `s[0] == '"'`: (unescaped text, rest after the closing quote).
fn quoted(s: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = s[1..].char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?.1),
            '"' => return Some((out, &s[1 + i + 1..])),
            _ => out.push(c),
        }
    }
    None
}

fn hex_bytes(s: &str) -> Vec<u8> {
    s.split(',').filter_map(|b| u8::from_str_radix(b.trim(), 16).ok()).collect()
}

/// Parses the keys and values of a .reg file into flat nodes (one per `[key]` section).
pub fn parse_reg(text: &str) -> Result<Vec<Node>, String> {
    // Long hex values continue on the next line after a trailing backslash.
    let mut lines: Vec<String> = Vec::new();
    let mut cont = false;
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        if cont {
            lines.last_mut().unwrap().push_str(line.trim_start());
        } else {
            lines.push(line.to_string());
        }
        // Only hex values wrap; a string value's line always ends with its closing quote.
        let last = lines.last_mut().unwrap();
        cont = last.ends_with('\\') && last.contains("=hex");
        if cont {
            last.pop();
        }
    }
    let mut nodes: Vec<Node> = Vec::new();
    for line in lines {
        let l = line.trim();
        if l.is_empty() || l.starts_with(';') || l.starts_with("Windows Registry Editor") || l == "REGEDIT4" {
            continue;
        }
        if l.starts_with("[-") {
            continue; // a deletion; not something a backup restores
        }
        if let Some(path) = l.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            nodes.push(Node { path: short_root(path), ..Default::default() });
            continue;
        }
        let Some(node) = nodes.last_mut() else { continue };
        let (name, rest) = if let Some(r) = l.strip_prefix('@') {
            (String::new(), r)
        } else if l.starts_with('"') {
            quoted(l).ok_or_else(|| format!("Unreadable line in backup: {l}"))?
        } else {
            continue;
        };
        let Some(data) = rest.trim_start().strip_prefix('=') else { continue };
        let data = data.trim();
        let (vtype, bytes): (u32, Vec<u8>) = if data == "-" {
            continue;
        } else if data.starts_with('"') {
            let (s, _) = quoted(data).ok_or_else(|| format!("Unreadable string in backup: {l}"))?;
            (1, s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect())
        } else if let Some(d) = data.strip_prefix("dword:") {
            (4, u32::from_str_radix(d.trim(), 16).map_err(|_| format!("Bad number in backup: {l}"))?.to_le_bytes().to_vec())
        } else if let Some(h) = data.strip_prefix("hex:") {
            (3, hex_bytes(h))
        } else if let Some(h) = data.strip_prefix("hex(") {
            let (t, h) = h.split_once("):").ok_or_else(|| format!("Unreadable value in backup: {l}"))?;
            (u32::from_str_radix(t, 16).unwrap_or(3), hex_bytes(h))
        } else {
            continue;
        };
        node.values.push(Value { name, vtype, data: b64().encode(bytes) });
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reg_exports() {
        let text = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Foo]\r\n\
            @=\"default\"\r\n\"Path\"=\"C:\\\\Program Files\\\\Foo \\\"x\\\"\"\r\n\"Count\"=dword:0000002a\r\n\
            \"Bin\"=hex:01,02,ff\r\n\"Multi\"=hex(7):61,00,00,00,\\\r\n  62,00,00,00,00,00\r\n\
            \"Big\"=hex(b):01,00,00,00,00,00,00,00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Foo\\Sub]\r\n\"x\"=\"y\"\r\n";
        let nodes = parse_reg(text).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].path, r"HKCU\Software\Foo");
        let v = |n: &str| nodes[0].values.iter().find(|v| v.name == n).unwrap();
        let text_of = |v: &Value| {
            let b = b64().decode(&v.data).unwrap();
            String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
        };
        assert_eq!(text_of(v("")), "default\0");
        assert_eq!(text_of(v("Path")), "C:\\Program Files\\Foo \"x\"\0");
        assert_eq!(b64().decode(&v("Count").data).unwrap(), 42u32.to_le_bytes());
        assert_eq!(b64().decode(&v("Bin").data).unwrap(), [1, 2, 255]);
        assert_eq!((v("Multi").vtype, b64().decode(&v("Multi").data).unwrap().len()), (7, 10));
        assert_eq!(v("Big").vtype, 11);
        assert_eq!(nodes[1].path, r"HKCU\Software\Foo\Sub");
    }
}
