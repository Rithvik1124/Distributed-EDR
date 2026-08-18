use std::fs;
use serde_json::{json,Value};
use std::io::Read;
use once_cell::sync::Lazy;
use crate::node_roles::yara::YARA_RULES;
use yara_x;

#[warn(unused_variables)]

pub fn match_yara_rule(file_dir: &str){
    let mut file = fs::File::open(file_dir).unwrap();    
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    println!("Contents:{:?}",data);
    let mut scanner = yara_x::Scanner::new(&YARA_RULES);
    let results = scanner.scan(&data).unwrap();
    if results.matching_rules().len() == 1{
        println!("Matches");
    }
}


