pub mod yara_detection;
use once_cell::sync::Lazy;
use sigma_rust::Rule;
use std::fs;
use yara_x::{self, Scanner};


pub fn load_yara_rules(yara_rules_dir: &str)-> yara_x::Rules{
    let mut compiler = yara_x::Compiler::new();
    compiler.add_include_dir(yara_rules_dir);

    for entry in fs::read_dir(yara_rules_dir).unwrap() {
        let entry = entry.unwrap(); // entry is now a DirEntry

        let source = std::fs::read_to_string(entry.path()).unwrap();
        compiler.add_source(source.as_str()).unwrap();
    }

    let rules = compiler.build();

    rules


}


pub static YARA_RULES: Lazy<yara_x::Rules> = Lazy::new(|| {
    load_yara_rules("./rules/")
});

