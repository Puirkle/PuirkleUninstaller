//! Guidance for self-protected software — mainly antivirus and other security products — that
//! blocks ordinary uninstalls on purpose. We do NOT fight their self-protection or touch drivers.
//! Instead we recognise the product and point the user at the vendor's own removal tool and at
//! Safe Mode, where self-protection does not load and the normal uninstaller / Force Removal work.

use crate::programs::Program;
use crate::util::normalize;
use serde::Serialize;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StubbornInfo {
    pub vendor: String,
    /// The vendor's official removal/cleanup tool page (opened in the browser).
    pub remover_url: Option<String>,
    pub note: String,
}

struct Known {
    vendor: &'static str,
    /// Lowercase alphanumeric vendor terms, matched as whole words against the name and publisher.
    keywords: &'static [&'static str],
    /// Product names of this vendor's security products that don't say "security" or "antivirus".
    products: &'static [&'static str],
    remover_url: Option<&'static str>,
}

/// A program name containing one of these is a security product. A vendor's other tools (cleaners,
/// VPNs, zip tools) don't protect themselves and uninstall normally.
const SECURITY_WORDS: &[&str] = &[
    "security", "secure", "antivirus", "antimalware", "malware", "virus", "protection", "endpoint",
    "firewall", "defender", "safe", "安全", "杀毒", "管家", "pcmanager", "pcmgr",
];

/// Official vendor removal tools. These are the vendor-sanctioned way to remove products whose
/// self-protection blocks a normal uninstall. URLs point at the vendor's own support pages.
const KNOWN: &[Known] = &[
    Known { vendor: "360 Total Security", keywords: &["360totalsecurity", "360safe", "qihoo", "360securitycenter", "360安全"], products: &[], remover_url: Some("https://www.360totalsecurity.com/en/support/") },
    Known { vendor: "Avast", keywords: &["avast"], products: &["avastone"], remover_url: Some("https://www.avast.com/uninstall-utility") },
    Known { vendor: "AVG", keywords: &["avg"], products: &[], remover_url: Some("https://www.avg.com/en-us/utilities") },
    Known { vendor: "Avira", keywords: &["avira"], products: &[], remover_url: Some("https://support.avira.com/") },
    Known { vendor: "McAfee", keywords: &["mcafee"], products: &[], remover_url: Some("https://www.mcafee.com/support/?articleId=TS101331") },
    Known { vendor: "Norton", keywords: &["norton", "symantec"], products: &["norton360"], remover_url: Some("https://support.norton.com/sp/en/us/home/current/solutions/kb20080710133834EN") },
    Known { vendor: "Kaspersky", keywords: &["kaspersky"], products: &["kasperskystandard", "kasperskyplus", "kasperskypremium", "kasperskyfree"], remover_url: Some("https://support.kaspersky.com/common/uninstall/1464") },
    Known { vendor: "Bitdefender", keywords: &["bitdefender"], products: &["bitdefenderagent"], remover_url: Some("https://www.bitdefender.com/consumer/support/answer/2209/") },
    Known { vendor: "ESET", keywords: &["eset", "nod32"], products: &["nod32"], remover_url: Some("https://support.eset.com/en/kb2289") },
    Known { vendor: "Malwarebytes", keywords: &["malwarebytes"], products: &[], remover_url: Some("https://support.malwarebytes.com/hc/en-us/articles/360039023473") },
    Known { vendor: "Trend Micro", keywords: &["trendmicro"], products: &[], remover_url: Some("https://helpcenter.trendmicro.com/en-us/article/tmka-19468") },
    Known { vendor: "Webroot", keywords: &["webroot"], products: &[], remover_url: Some("https://answers.webroot.com/") },
    Known { vendor: "Sophos", keywords: &["sophos"], products: &["sophoshome"], remover_url: Some("https://support.sophos.com/") },
    Known { vendor: "F-Secure", keywords: &["fsecure"], products: &["fsecuretotal"], remover_url: Some("https://www.f-secure.com/en/support") },
    Known { vendor: "Comodo", keywords: &["comodo"], products: &[], remover_url: None },
    Known { vendor: "Baidu", keywords: &["baidu"], products: &[], remover_url: None },
    Known { vendor: "Tencent PC Manager", keywords: &["tencent", "qqpcmgr"], products: &["qqpcmgr"], remover_url: None },
];

/// Lowercase alphanumeric words: "www.360totalsecurity.com" -> ["www", "360totalsecurity", "com"].
fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_lowercase).collect()
}

/// True if `term` is one word of `ws` or several neighbouring words run together ("F-Secure" has
/// "fsecure"), so "eset" never matches inside "reset". Long terms may also sit inside a word.
fn has_term(ws: &[String], term: &str) -> bool {
    if term.len() >= 8 && ws.iter().any(|w| w.contains(term)) {
        return true;
    }
    (0..ws.len()).any(|i| {
        let mut joined = String::new();
        ws[i..].iter().any(|w| {
            joined.push_str(w);
            joined == term || !term.starts_with(joined.as_str())
        }) && joined == term
    })
}

/// The vendor whose self-protected security product this is, if any.
fn find_vendor(name: &str, publisher: &str) -> Option<&'static Known> {
    let joined = normalize(name);
    let (name, publisher) = (words(name), words(publisher));
    KNOWN.iter().find(|k| {
        let vendor = k.keywords.iter().any(|kw| has_term(&name, kw) || has_term(&publisher, kw));
        let product = SECURITY_WORDS.iter().any(|w| joined.contains(w)) || k.products.iter().any(|w| has_term(&name, w));
        vendor && product
    })
}

/// If `p` is a known self-protected security product, returns advice for removing it properly.
pub fn detect(p: &Program) -> Option<StubbornInfo> {
    let hit = find_vendor(&p.name, p.publisher.as_deref().unwrap_or_default())?;
    let has_tool = hit.remover_url.is_some();
    let note = if has_tool {
        format!(
            "{} protects itself so it can't be removed by a normal uninstall. The reliable way is \
             the official {} removal tool. If that isn't an option, restart Windows in Safe Mode \
             (self-protection doesn't load there) and use Uninstall or Force Removal.",
            p.name, hit.vendor
        )
    } else {
        format!(
            "{} protects itself so it can't be removed by a normal uninstall. Turn off its \
             self-protection in its own settings first, or restart Windows in Safe Mode \
             (self-protection doesn't load there) and then use Uninstall or Force Removal.",
            p.name
        )
    };
    Some(StubbornInfo { vendor: hit.vendor.into(), remover_url: hit.remover_url.map(Into::into), note })
}

/// True if the given external URL is one of our curated vendor removal-tool links, so the app
/// only ever opens addresses it shipped, never ones built from registry or program data.
pub fn is_known_remover_url(url: &str) -> bool {
    KNOWN.iter().any(|k| k.remover_url == Some(url))
}

#[cfg(test)]
mod tests {
    use super::find_vendor;

    fn vendor(name: &str, publisher: &str) -> Option<&'static str> {
        find_vendor(name, publisher).map(|k| k.vendor)
    }

    #[test]
    fn security_products_are_recognised() {
        assert_eq!(vendor("360 Total Security", "Qihoo 360"), Some("360 Total Security"));
        assert_eq!(vendor("360安全卫士", "360安全中心"), Some("360 Total Security"));
        assert_eq!(vendor("Norton 360", "Gen Digital Inc."), Some("Norton"));
        assert_eq!(vendor("Kaspersky Standard", "Kaspersky"), Some("Kaspersky"));
        assert_eq!(vendor("ESET NOD32 Antivirus", "ESET, spol. s r.o."), Some("ESET"));
        assert_eq!(vendor("F-Secure SAFE", "F-Secure Corporation"), Some("F-Secure"));
        assert_eq!(vendor("Malwarebytes version 5.1.0", "Malwarebytes"), Some("Malwarebytes"));
        assert_eq!(vendor("Avast Free Antivirus", "Gen Digital Inc."), Some("Avast"));
    }

    #[test]
    fn vendors_other_tools_are_not_flagged() {
        assert_eq!(vendor("CleanPro", "www.360totalsecurity.com"), None);
        assert_eq!(vendor("360 Zip", "Qihoo 360"), None);
        assert_eq!(vendor("AVG TuneUp", "AVG Technologies"), None);
        assert_eq!(vendor("Avast Cleanup Premium", "Gen Digital Inc."), None);
        assert_eq!(vendor("Network Reset Security Tool", "Contoso"), None);
        assert_eq!(vendor("Microsoft Defender for Endpoint", "Microsoft Corporation"), None);
    }
}

#[cfg(test)]
mod download_tests {
    /// `cargo test update_download -- --ignored --nocapture`: fetches a real release installer.
    #[test]
    #[ignore]
    fn update_download() {
        let file = std::env::temp_dir().join("puirkle-download-test.exe");
        let url = "https://github.com/Puirkle/PuirkleUninstaller/releases/download/v0.3.0/PuirkleUninstaller_0.3.0_x64-setup.exe";
        crate::util::download(url, &file).unwrap();
        let len = std::fs::metadata(&file).unwrap().len();
        println!("downloaded {len} bytes");
        let _ = std::fs::remove_file(&file);
        assert!(len > 100 * 1024);
    }
}
