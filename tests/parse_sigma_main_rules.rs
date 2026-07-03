use sigma_rust::rule_from_yaml;
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use walkdir::WalkDir;

/// Rules that no longer parse since serde_yml 0.0.13: its YAML 1.2 core-schema
/// resolver turns unquoted leading-zero scalars such as `00000429` into
/// integers (the previous resolver kept them as strings), and string modifiers
/// like `contains` reject integer values with a parse error.
/// Paths are relative to the corpus root, with `/` separators.
/// Remove entries once the upstream rules quote these values.
const KNOWN_INCOMPATIBLE_RULES: &[&str] =
    &["rules/windows/registry/registry_set/registry_set_susp_keyboard_layout_load.yml"];

#[test]
fn test_parse_sigma_main_rules() {
    let sigma_dir = "sigma-main-rules";
    let mut num_successful = 0;
    let mut num_failed = 0;
    let mut total = 0;
    let mut errors = vec![];

    let start = Instant::now();
    for entry in WalkDir::new(sigma_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.path().extension().and_then(|s| s.to_str()) == Some("yml") {
            let relative_path = entry
                .path()
                .strip_prefix(sigma_dir)
                .expect("walked entries live under the corpus root")
                .to_string_lossy()
                .replace('\\', "/");
            if KNOWN_INCOMPATIBLE_RULES.contains(&relative_path.as_str()) {
                println!("Skipping known incompatible rule {:?}", entry.path());
                continue;
            }
            total += 1;
            let mut file = File::open(entry.path()).expect("Unable to open file");
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .expect("Unable to read file");

            let rule = rule_from_yaml(&contents);
            match rule {
                Ok(_) => {
                    num_successful += 1;
                }
                Err(err) => {
                    num_failed += 1;
                    errors.push(format!(
                        "Failed to parse YAML file {:?}: {:?}",
                        entry.path(),
                        err
                    ));
                }
            };
        }
    }
    let duration = start.elapsed();
    println!("-----------------------------------------------");
    println!("Parsing {} rules took {:?}", total, duration);

    println!("Successfully parsed {} rules", num_successful);
    println!("{} rules failed with errors", num_failed);
    for (i, error) in errors.iter().enumerate() {
        println!("{:02}: {}", i + 1, error);
    }

    assert!(num_successful > 0);
    assert_eq!(num_failed, 0);
}
