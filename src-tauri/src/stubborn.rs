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
    /// Lowercase alphanumeric keywords matched against the program name and publisher.
    keywords: &'static [&'static str],
    remover_url: Option<&'static str>,
}

/// Official vendor removal tools. These are the vendor-sanctioned way to remove products whose
/// self-protection blocks a normal uninstall. URLs point at the vendor's own support pages.
const KNOWN: &[Known] = &[
    Known { vendor: "360 Total Security", keywords: &["360totalsecurity", "360safe", "qihoo", "360securitycenter"], remover_url: Some("https://www.360totalsecurity.com/en/support/") },
    Known { vendor: "Avast", keywords: &["avast"], remover_url: Some("https://www.avast.com/uninstall-utility") },
    Known { vendor: "AVG", keywords: &["avg"], remover_url: Some("https://www.avg.com/en-us/utilities") },
    Known { vendor: "Avira", keywords: &["avira"], remover_url: Some("https://support.avira.com/") },
    Known { vendor: "McAfee", keywords: &["mcafee"], remover_url: Some("https://www.mcafee.com/support/?articleId=TS101331") },
    Known { vendor: "Norton", keywords: &["norton", "symantec"], remover_url: Some("https://support.norton.com/sp/en/us/home/current/solutions/kb20080710133834EN") },
    Known { vendor: "Kaspersky", keywords: &["kaspersky"], remover_url: Some("https://support.kaspersky.com/common/uninstall/1464") },
    Known { vendor: "Bitdefender", keywords: &["bitdefender"], remover_url: Some("https://www.bitdefender.com/consumer/support/answer/2209/") },
    Known { vendor: "ESET", keywords: &["eset", "nod32"], remover_url: Some("https://support.eset.com/en/kb2289") },
    Known { vendor: "Malwarebytes", keywords: &["malwarebytes"], remover_url: Some("https://support.malwarebytes.com/hc/en-us/articles/360039023473") },
    Known { vendor: "Trend Micro", keywords: &["trendmicro"], remover_url: Some("https://helpcenter.trendmicro.com/en-us/article/tmka-19468") },
    Known { vendor: "Webroot", keywords: &["webroot"], remover_url: Some("https://answers.webroot.com/") },
    Known { vendor: "Sophos", keywords: &["sophos"], remover_url: Some("https://support.sophos.com/") },
    Known { vendor: "F-Secure", keywords: &["fsecure"], remover_url: Some("https://www.f-secure.com/en/support") },
    Known { vendor: "Comodo", keywords: &["comodo"], remover_url: None },
    Known { vendor: "Baidu", keywords: &["baidu"], remover_url: None },
    Known { vendor: "Tencent PC Manager", keywords: &["tencent", "qqpcmgr"], remover_url: None },
];

/// If `p` is a known self-protected security product, returns advice for removing it properly.
pub fn detect(p: &Program) -> Option<StubbornInfo> {
    let name = normalize(&p.name);
    let publisher = p.publisher.as_deref().map(normalize).unwrap_or_default();
    let hit = KNOWN.iter().find(|k| k.keywords.iter().any(|kw| name.contains(kw) || publisher.contains(kw)))?;
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
