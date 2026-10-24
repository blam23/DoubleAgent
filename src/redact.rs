//! Secret redaction for anything that leaves the machine (webhook payloads).

use regex::Regex;

pub struct Redactor {
    rules: Vec<(&'static str, Regex)>,
}

impl Redactor {
    pub fn new() -> Self {
        let r = |k, p: &str| (k, Regex::new(p).expect("redaction regex"));
        Self {
            rules: vec![
                r(
                    "private-key",
                    r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                ),
                r("aws-key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
                r(
                    "github-token",
                    r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b",
                ),
                r("anthropic-key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
                r("openai-key", r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}"),
                r("slack-token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
                r("google-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
                r("stripe-key", r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}\b"),
                r("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
                r("url-credentials", r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@"),
                r(
                    "assignment",
                    r#"(?i)\b((api[_-]?key|secret|token|passw(or)?d|pwd|client[_-]?secret|access[_-]?key)\s*[:=]\s*["']?)[^\s"'`]{8,}"#,
                ),
            ],
        }
    }

    pub fn redact(&self, s: &str) -> String {
        let mut out = s.to_string();
        for (kind, re) in &self.rules {
            out = match *kind {
                "url-credentials" => re.replace_all(&out, format!("${{1}}[REDACTED:{kind}]@")).into_owned(),
                "assignment" => re.replace_all(&out, "${1}[REDACTED:secret]".to_string()).into_owned(),
                _ => re.replace_all(&out, format!("[REDACTED:{kind}]")).into_owned(),
            };
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts() {
        let r = Redactor::new();
        let s = r.redact("key AKIAABCDEFGHIJKLMNOP and token=supersecretvalue123 and https://u:p4ss@host/x");
        assert!(!s.contains("AKIAABCDEFGHIJKLMNOP"));
        assert!(!s.contains("supersecretvalue123"));
        assert!(!s.contains("p4ss"));
    }
}
