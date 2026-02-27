//! Scanner and Security Tool Detection Rules

use crate::rules::{AttackType, Confidence, Rule, RuleBuilder, Severity};
use anyhow::Result;

pub fn rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let all_rules = vec![
        // Vulnerability scanners
        RuleBuilder::new(913100, "Scanner: SQLMap detected")
            .description("Detects SQLMap SQL injection scanner")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(sqlmap|havij|pangolin)")
            .base_score(8)
            .cwe(200)
            .tags(&["scanner", "sqli-scanner"])
            .build()?,
        RuleBuilder::new(913101, "Scanner: Nikto detected")
            .description("Detects Nikto web scanner")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(nikto|wikto)")
            .base_score(8)
            .cwe(200)
            .tags(&["scanner", "web-scanner"])
            .build()?,
        RuleBuilder::new(913102, "Scanner: Nessus detected")
            .description("Detects Nessus vulnerability scanner")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(nessus|openvas)")
            .base_score(8)
            .cwe(200)
            .tags(&["scanner", "vuln-scanner"])
            .build()?,
        RuleBuilder::new(913103, "Scanner: Acunetix detected")
            .description("Detects Acunetix web scanner")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(acunetix|acunetix-wvs)")
            .base_score(8)
            .cwe(200)
            .tags(&["scanner", "web-scanner"])
            .build()?,
        RuleBuilder::new(913104, "Scanner: Burp Suite detected")
            .description("Detects Burp Suite proxy/scanner")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::Medium)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(burp|portswigger)")
            .base_score(6)
            .cwe(200)
            .tags(&["scanner", "proxy"])
            .build()?,
        // Network scanners
        RuleBuilder::new(913110, "Scanner: Nmap detected")
            .description("Detects Nmap network scanner")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::Medium)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(nmap|masscan|zmap)")
            .base_score(6)
            .cwe(200)
            .tags(&["scanner", "network-scanner"])
            .build()?,
        // Directory bruteforcers
        RuleBuilder::new(913120, "Scanner: DirBuster/Gobuster detected")
            .description("Detects directory bruteforce tools")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(dirbuster|gobuster|dirb|feroxbuster|ffuf)")
            .base_score(7)
            .cwe(200)
            .tags(&["scanner", "directory-bruteforce"])
            .build()?,
        // CMS scanners
        RuleBuilder::new(913130, "Scanner: WPScan detected")
            .description("Detects WordPress scanner")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(wpscan|droopescan|joomscan)")
            .base_score(7)
            .cwe(200)
            .tags(&["scanner", "cms-scanner"])
            .build()?,
        // Exploitation frameworks
        RuleBuilder::new(913140, "Scanner: Metasploit detected")
            .description("Detects Metasploit framework")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(metasploit|meterpreter)")
            .base_score(10)
            .cwe(200)
            .tags(&["scanner", "exploitation"])
            .build()?,
        // Bots and crawlers
        RuleBuilder::new(913150, "Scanner: Bad bot User-Agent")
            .description("Detects known bad bot signatures")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::Medium)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"(?i)(python-requests|wget|curl|httpclient|java/)")
            .base_score(4)
            .cwe(200)
            .tags(&["scanner", "bot"])
            .build()?,
        RuleBuilder::new(913151, "Scanner: Empty/missing User-Agent")
            .description("Detects requests with suspicious User-Agent")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::Low)
            .confidence(Confidence::Low)
            .paranoia(3)
            .pattern(r"^-$|^$")
            .base_score(2)
            .cwe(200)
            .tags(&["scanner", "bot"])
            .build()?,
        // Credential stuffing tools
        RuleBuilder::new(913160, "Scanner: Hydra detected")
            .description("Detects Hydra password cracker")
            .attack_type(AttackType::ScannerDetection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(hydra|medusa|patator)")
            .base_score(10)
            .cwe(200)
            .tags(&["scanner", "bruteforce"])
            .build()?,
    ];

    Ok(all_rules
        .into_iter()
        .filter(|r| r.paranoia_level <= paranoia_level)
        .collect())
}
