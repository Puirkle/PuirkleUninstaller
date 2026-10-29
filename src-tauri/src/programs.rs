//! Enumerates installed programs: classic Win32 entries from the Uninstall registry keys,
//! plus Microsoft Store (AppX/MSIX) packages.

use crate::reg;
use crate::util::{clean_path, date_from_system_time, normalize, powershell, wide};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

pub const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
pub const UNINSTALL_WOW: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Program {
    pub id: String,
    /// "win32" or "store"
    pub kind: String,
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    /// YYYY-MM-DD
    pub install_date: Option<String>,
    pub size_bytes: Option<u64>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub icon_path: Option<String>,
    /// MSI product code, e.g. {XXXXXXXX-...}
    pub product_code: Option<String>,
    /// Full Uninstall key, e.g. HKLM\SOFTWARE\...\Uninstall\Foo
    pub registry_key: Option<String>,
    /// "machine" or "user"
    pub scope: String,
    /// For per-user installs: the Windows account(s) it belongs to. Empty for machine-wide.
    #[serde(default)]
    pub users: Vec<String>,
    /// "64-bit", "32-bit" or ""
    pub arch: String,
    pub system_component: bool,
    pub package_full_name: Option<String>,
    pub package_family_name: Option<String>,
}

pub fn list_all(include_store: bool, all_users: bool) -> Vec<Program> {
    let mut v = list_win32(all_users);
    if include_store {
        v.extend(list_store());
    }
    v
}

/// Machine-wide (HKLM) programs, plus per-user programs: the current account only, or — when
/// `all_users` is set — every account on the PC, each tagged with its owning user(s).
pub fn list_win32(all_users: bool) -> Vec<Program> {
    let machine = [("HKLM", UNINSTALL, "64-bit"), ("HKLM", UNINSTALL_WOW, "32-bit")];
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (root, path, arch) in machine {
        let Some(key) = reg::open(&format!("{root}\\{path}")) else { continue };
        for name in reg::subkeys(&key) {
            let Ok(sub) = key.open_subkey(&name) else { continue };
            let full = format!("{root}\\{path}\\{name}");
            if let Some(p) = read_entry(&sub, &name, full, "machine", arch, Vec::new()) {
                let dedupe = format!("{}|{}", normalize(&p.name), p.version.clone().unwrap_or_default());
                if seen.insert(dedupe) {
                    out.push(p);
                }
            }
        }
    }
    let per_user = if all_users { crate::allusers::list_all_users_programs() } else { read_user_hive_current() };
    for p in per_user {
        // A per-user entry that duplicates a machine-wide one is dropped; its user tag is minor.
        let dedupe = format!("{}|{}", normalize(&p.name), p.version.clone().unwrap_or_default());
        if seen.insert(dedupe) {
            out.push(p);
        }
    }
    out
}

/// Per-user Uninstall entries for the current account (its hive is `HKCU`).
pub fn read_user_hive_current() -> Vec<Program> {
    let me = crate::allusers::current_user();
    let mut out = Vec::new();
    for (path, arch) in [(UNINSTALL, ""), (UNINSTALL_WOW, "32-bit")] {
        let base = format!("HKCU\\{path}");
        let Some(key) = reg::open(&base) else { continue };
        for name in reg::subkeys(&key) {
            let Ok(sub) = key.open_subkey(&name) else { continue };
            let full = format!("{base}\\{name}");
            if let Some(p) = read_entry(&sub, &name, full, "user", arch, vec![me.clone()]) {
                out.push(p);
            }
        }
    }
    out
}

/// Reads the Uninstall entries under one user's loaded hive (`HKU\<sid>`), tagging each with
/// `user`. Used to list per-user programs for accounts other than the current one.
pub fn read_user_hive(hku_sid: &str, user: &str) -> Vec<Program> {
    let mut out = Vec::new();
    for (path, arch) in [(UNINSTALL, ""), (UNINSTALL_WOW, "32-bit")] {
        let base = format!("HKU\\{hku_sid}\\{path}");
        let Some(key) = reg::open(&base) else { continue };
        for name in reg::subkeys(&key) {
            let Ok(sub) = key.open_subkey(&name) else { continue };
            let full = format!("{base}\\{name}");
            if let Some(p) = read_entry(&sub, &name, full, "user", arch, vec![user.to_string()]) {
                out.push(p);
            }
        }
    }
    out
}

fn read_entry(sub: &winreg::RegKey, key_name: &str, full: String, scope: &str, arch: &str, users: Vec<String>) -> Option<Program> {
    let name = reg::string(sub, "DisplayName")?;
    if reg::string(sub, "ParentKeyName").is_some() {
        return None; // updates/patches belonging to another entry
    }
    if let Some(rt) = reg::string(sub, "ReleaseType") {
        if matches!(rt.as_str(), "Update" | "Hotfix" | "Security Update" | "ServicePack") {
            return None;
        }
    }
    let uninstall_string = reg::string(sub, "UninstallString");
    let is_msi = reg::dword(sub, "WindowsInstaller") == Some(1)
        || uninstall_string.as_deref().is_some_and(|u| u.to_lowercase().contains("msiexec"));
    let product_code = if is_msi {
        guid_in(key_name).or_else(|| uninstall_string.as_deref().and_then(guid_in))
    } else {
        None
    };
    let install_location = reg::string(sub, "InstallLocation").map(|p| clean_path(&p)).filter(|p| p.len() > 3);
    let install_date = reg::string(sub, "InstallDate")
        .and_then(|d| format_date(&d))
        .or_else(|| install_location.as_deref().and_then(created_date));
    let icon_path = reg::string(sub, "DisplayIcon")
        .or_else(|| product_code.as_deref().and_then(msi_icon))
        .or_else(|| install_location.as_deref().and_then(|l| icon_in_folder(l, &name)));
    Some(Program {
        id: full.clone(),
        kind: "win32".into(),
        name,
        version: reg::string(sub, "DisplayVersion"),
        publisher: reg::string(sub, "Publisher"),
        install_location,
        install_date,
        size_bytes: reg::dword(sub, "EstimatedSize").filter(|&kb| kb > 0).map(|kb| kb as u64 * 1024),
        uninstall_string,
        quiet_uninstall_string: reg::string(sub, "QuietUninstallString"),
        icon_path,
        product_code,
        registry_key: Some(full),
        scope: scope.into(),
        users,
        arch: arch.into(),
        system_component: reg::dword(sub, "SystemComponent") == Some(1),
        package_full_name: None,
        package_family_name: None,
    })
}

/// Finds a `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` GUID in `s`.
pub fn guid_in(s: &str) -> Option<String> {
    let start = s.find('{')?;
    let cand = s.get(start..start + 38)?;
    let ok = cand.ends_with('}')
        && cand[1..37].char_indices().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() });
    ok.then(|| cand.to_uppercase())
}

fn format_date(d: &str) -> Option<String> {
    let d = d.trim();
    if d.len() != 8 || !d.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut year: i32 = d[..4].parse().ok()?;
    // Some installers write the year in the Thai Buddhist calendar (Gregorian + 543).
    if year > 2400 {
        year -= 543;
    }
    Some(format!("{year:04}-{}-{}", &d[4..6], &d[6..]))
}

/// Icon Windows Installer cached for an MSI product (what Settings > Apps shows).
fn msi_icon(product_code: &str) -> Option<String> {
    let packed = crate::leftovers::pack_guid(product_code);
    [format!(r"HKLM\SOFTWARE\Classes\Installer\Products\{packed}"), format!(r"HKCU\Software\Microsoft\Installer\Products\{packed}")]
        .iter()
        .find_map(|k| reg::open(k).and_then(|key| reg::string(&key, "ProductIcon")))
        .filter(|p| Path::new(&crate::icons::parse_icon_spec(p).0).is_file())
}

/// Best guess at a program's icon from its install folder: an .exe named like the program,
/// otherwise an .ico file, otherwise the only real .exe there.
fn icon_in_folder(dir: &str, name: &str) -> Option<String> {
    let wanted = normalize(name);
    let mut exes = Vec::new();
    let mut ico = None;
    for e in std::fs::read_dir(dir).ok()?.filter_map(Result::ok) {
        let path = e.path();
        let ext = path.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
        let stem = normalize(&path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
        match ext.as_str() {
            "exe" if !["unins", "uninst", "update", "setup", "crash", "helper"].iter().any(|g| stem.starts_with(g)) => {
                if stem.len() >= 3 && (wanted.contains(&stem) || stem.contains(&wanted)) {
                    return Some(path.to_string_lossy().into_owned());
                }
                exes.push(path);
            }
            "ico" => ico = ico.or(Some(path)),
            _ => {}
        }
    }
    ico.or_else(|| (exes.len() == 1).then(|| exes.remove(0))).map(|p| p.to_string_lossy().into_owned())
}

fn created_date(path: &str) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    meta.created().or_else(|_| meta.modified()).ok().map(date_from_system_time)
}

// ---------------------------------------------------------------------------------------------
// Microsoft Store apps

const STORE_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Get-AppxPackage -PackageTypeFilter Main |
  Where-Object { -not $_.IsFramework -and -not $_.NonRemovable -and "$($_.SignatureKind)" -ne 'System' } |
  ForEach-Object { [pscustomobject]@{
    Name = $_.Name; FullName = $_.PackageFullName; Family = $_.PackageFamilyName
    Publisher = $_.Publisher; Version = "$($_.Version)"; Location = $_.InstallLocation } } |
  ConvertTo-Json -Compress
"#;

pub fn list_store() -> Vec<Program> {
    let Ok(json) = powershell(STORE_SCRIPT) else { return Vec::new() };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json.trim()) else { return Vec::new() };
    let items = match val {
        serde_json::Value::Array(a) => a,
        v @ serde_json::Value::Object(_) => vec![v],
        _ => return Vec::new(),
    };
    items.iter().filter_map(store_entry).collect()
}

fn store_entry(v: &serde_json::Value) -> Option<Program> {
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string).filter(|s| !s.is_empty());
    let pkg_name = get("Name")?;
    let full = get("FullName")?;
    let location = get("Location");
    let manifest = location
        .as_deref()
        .and_then(|l| std::fs::read_to_string(Path::new(l).join("AppxManifest.xml")).ok())
        .unwrap_or_default();

    let display = element(&manifest, "DisplayName")
        .and_then(|d| resolve_resource(&d, &full, &pkg_name))
        .unwrap_or_else(|| prettify(&pkg_name));
    let publisher = element(&manifest, "PublisherDisplayName")
        .and_then(|d| resolve_resource(&d, &full, &pkg_name))
        .or_else(|| get("Publisher").map(|p| cert_name(&p)));
    let icon = location.as_deref().and_then(|l| store_logo(&manifest, l));

    Some(Program {
        id: format!("appx:{full}"),
        kind: "store".into(),
        name: display,
        version: get("Version"),
        publisher,
        install_date: location.as_deref().and_then(created_date),
        install_location: location,
        size_bytes: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        icon_path: icon,
        product_code: None,
        registry_key: None,
        scope: "user".into(),
        users: vec![crate::allusers::current_user()],
        arch: String::new(),
        system_component: false,
        package_full_name: Some(full),
        package_family_name: get("Family"),
    })
}

fn element(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))?;
    Some(xml[start..start + end].trim().to_string()).filter(|s| !s.is_empty())
}

fn attribute(xml: &str, attr: &str) -> Option<String> {
    let key = format!("{attr}=\"");
    let start = xml.find(&key)? + key.len();
    let end = xml[start..].find('"')?;
    Some(xml[start..start + end].to_string())
}

/// Resolves `ms-resource:` strings through SHLoadIndirectString.
fn resolve_resource(value: &str, full_name: &str, pkg_name: &str) -> Option<String> {
    let Some(res) = value.strip_prefix("ms-resource:") else { return Some(value.to_string()) };
    let uri = if res.starts_with("//") {
        format!("ms-resource:{res}")
    } else if res.starts_with('/') {
        format!("ms-resource://{pkg_name}{res}")
    } else {
        format!("ms-resource://{pkg_name}/resources/{res}")
    };
    let source = wide(&format!("@{{{full_name}?{uri}}}"));
    let mut buf = [0u16; 512];
    let hr = unsafe {
        windows_sys::Win32::UI::Shell::SHLoadIndirectString(source.as_ptr(), buf.as_mut_ptr(), buf.len() as u32, std::ptr::null())
    };
    let s = crate::util::from_wide(&buf);
    (hr == 0 && !s.is_empty() && !s.starts_with("ms-resource")).then_some(s)
}

#[cfg(test)]
mod tests {
    #[test]
    fn buddhist_years_are_converted() {
        assert_eq!(super::format_date("25690125").as_deref(), Some("2026-01-25"));
        assert_eq!(super::format_date("20261025").as_deref(), Some("2026-10-25"));
    }

    /// `cargo test icons -- --ignored --nocapture`: which icon each program resolves to.
    #[test]
    #[ignore]
    fn icons() {
        for p in super::list_win32(false).iter().filter(|p| !p.system_component) {
            println!("{:<50} {}", p.name, p.icon_path.as_deref().unwrap_or("-"));
        }
    }
}

/// "Microsoft.WindowsCalculator" -> "Windows Calculator"
fn prettify(pkg_name: &str) -> String {
    let base = pkg_name.rsplit('.').next().unwrap_or(pkg_name);
    let mut out = String::new();
    let mut prev_lower = false;
    for c in base.chars() {
        if c.is_uppercase() && prev_lower {
            out.push(' ');
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        out.push(c);
    }
    out
}

/// "CN=Foo Corp, O=Foo Corp, L=..." -> "Foo Corp"
fn cert_name(p: &str) -> String {
    for prefix in ["O=", "CN="] {
        if let Some(part) = p.split(',').map(str::trim).find(|s| s.starts_with(prefix)) {
            return part[prefix.len()..].trim_matches('"').to_string();
        }
    }
    p.to_string()
}

/// Picks the best on-disk variant of the manifest's square logo (files carry scale qualifiers).
fn store_logo(manifest: &str, location: &str) -> Option<String> {
    let rel = attribute(manifest, "Square44x44Logo").or_else(|| element(manifest, "Logo"))?;
    let rel_path = Path::new(location).join(rel.replace('/', "\\"));
    if rel_path.is_file() {
        return Some(rel_path.to_string_lossy().into_owned());
    }
    let dir = rel_path.parent()?;
    let stem = rel_path.file_stem()?.to_string_lossy().to_lowercase();
    let ext = rel_path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mut candidates: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| {
            let l = n.to_lowercase();
            l.starts_with(&format!("{stem}.")) && l.ends_with(&format!(".{ext}"))
        })
        .collect();
    let rank = |n: &str| {
        let l = n.to_lowercase();
        ["targetsize-48_altform-unplated", "targetsize-48", "scale-200", "scale-100"]
            .iter()
            .position(|q| l.contains(q))
            .unwrap_or(9)
    };
    candidates.sort_by_key(|n| rank(n));
    candidates.first().map(|n| dir.join(n).to_string_lossy().into_owned())
}
