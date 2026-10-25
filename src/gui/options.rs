//! Editable copy of the configuration for the Options tab.

use doubleagent::config::Config;
use std::path::PathBuf;

/// The config being edited. List-like fields are edited as one entry per line.
#[derive(Clone)]
pub struct Draft {
    pub cfg: Config,
    pub roots: String,
    pub exclude_dirs: String,
    pub trusted_domains: String,
    pub disabled_rules: String,
    pub trusted_remotes: String,
    pub jsonl_path: String,
    pub webhook_url: String,
    pub quarantine_dir: String,
}

fn lines<T: ToString>(items: &[T]) -> String {
    items.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
}

fn split(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_owned).collect()
}

fn optional(text: &str) -> Option<String> {
    Some(text.trim().to_owned()).filter(|t| !t.is_empty())
}

impl Draft {
    pub fn new(cfg: &Config) -> Self {
        Self {
            roots: lines(&cfg.scan.roots.iter().map(|p| p.display()).collect::<Vec<_>>()),
            exclude_dirs: lines(&cfg.scan.exclude_dirs),
            trusted_domains: lines(&cfg.analyzer.trusted_domains),
            disabled_rules: lines(&cfg.analyzer.disabled_rules),
            trusted_remotes: lines(&cfg.provenance.trusted_remotes),
            jsonl_path: cfg.output.jsonl_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            webhook_url: cfg.output.webhook_url.clone().unwrap_or_default(),
            quarantine_dir: cfg
                .policy
                .quarantine_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            cfg: cfg.clone(),
        }
    }

    /// The edited config with the text fields folded back in. Settings the form doesn't
    /// show (custom scoring rules, hook command, ...) are carried through untouched.
    pub fn to_config(&self) -> Config {
        let mut cfg = self.cfg.clone();
        cfg.scan.roots = split(&self.roots).into_iter().map(PathBuf::from).collect();
        cfg.scan.exclude_dirs = split(&self.exclude_dirs);
        cfg.analyzer.trusted_domains = split(&self.trusted_domains);
        cfg.analyzer.disabled_rules = split(&self.disabled_rules);
        cfg.provenance.trusted_remotes = split(&self.trusted_remotes);
        cfg.output.jsonl_path = optional(&self.jsonl_path).map(PathBuf::from);
        cfg.output.webhook_url = optional(&self.webhook_url);
        cfg.policy.quarantine_dir = optional(&self.quarantine_dir).map(PathBuf::from);
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_trims_list_fields() {
        let mut draft = Draft::new(&Config::default());
        assert_eq!(
            draft.to_config().analyzer.trusted_domains,
            Config::default().analyzer.trusted_domains
        );
        draft.roots = " C:\\code \n\n D:\\work ".into();
        draft.webhook_url = "  ".into();
        let cfg = draft.to_config();
        assert_eq!(cfg.scan.roots, [PathBuf::from("C:\\code"), PathBuf::from("D:\\work")]);
        assert_eq!(cfg.output.webhook_url, None);
        assert!(cfg.validate().is_ok());
    }
}
