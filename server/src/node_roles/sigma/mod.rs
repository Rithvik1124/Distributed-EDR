pub mod sigma_detection;
use once_cell::sync::Lazy;
use sigma_rust::Rule;
use std::fs;
use std::env;
use yara_x::{self, Scanner};



fn load_sigma_rules(dir: &str) -> Vec<sigma_rust::Rule> {
    let base = env::var("CARGO_MANIFEST_DIR").unwrap();
    let full_path = format!("{}/src/node_roles/sigma/{}", base, dir);

    let mut rules = Vec::new();

    for entry in std::fs::read_dir(full_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        
        if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("yaml") | Some("yml")
        ) {
            let contents = std::fs::read_to_string(&path).unwrap();
            let rule = sigma_rust::rule_from_yaml(&contents).unwrap();
            rules.push(rule);
        }
    }

    rules
}

pub static SIGMA_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    load_sigma_rules("rules")
});