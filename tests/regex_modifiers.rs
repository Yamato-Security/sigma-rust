use sigma_rust::{Event, Rule, rule_from_yaml};

fn regex_rule(modifiers: &str, pattern: &str) -> Rule {
    rule_from_yaml(&format!(
        "title: Regex modifiers\nlogsource: {{}}\ndetection:\n  selection:\n    Message|{modifiers}: '{pattern}'\n  condition: selection\n"
    ))
    .unwrap()
}

#[test]
fn test_regex_submodifiers() {
    for (modifiers, pattern, matching, nonmatching) in [
        ("re|i", "^powershell$", "PowerShell", "PowerShell.exe"),
        ("re|i", "^évil$", "ÉVIL", "evil"),
        (
            "re|m",
            "^needle$",
            "before\nneedle\nafter",
            "before\nNEEDLE\nafter",
        ),
        ("re|s", "^start.end$", "start\nend", "START\nEND"),
    ] {
        let rule = regex_rule(modifiers, pattern);
        assert!(
            rule.is_match(&Event::from([("Message", matching)])),
            "{modifiers} should match {matching:?}"
        );
        assert!(
            !rule.is_match(&Event::from([("Message", nonmatching)])),
            "{modifiers} should not match {nonmatching:?}"
        );
        assert!(!rule.is_match(&Event::new()));

        let plain = regex_rule("re", pattern);
        assert!(
            !plain.is_match(&Event::from([("Message", matching)])),
            "plain re should not match {matching:?}"
        );
    }
}

#[test]
fn test_regex_multiline_and_dotall_are_independent() {
    let multiline = regex_rule("re|m", "^start.end$");
    assert!(multiline.is_match(&Event::from([("Message", "before\nstart-end\nafter")])));
    assert!(!multiline.is_match(&Event::from([("Message", "start\nend")])));

    let dotall = regex_rule("re|s", "^needle$");
    assert!(dotall.is_match(&Event::from([("Message", "needle")])));
    assert!(!dotall.is_match(&Event::from([("Message", "before\nneedle\nafter")])));
}

#[test]
fn test_regex_combined_submodifiers() {
    let matching = Event::from([("Message", "before\nSTART\nEND\nafter")]);
    let nonmatching = Event::from([("Message", "before\nSTART\nSTOP\nafter")]);
    for modifiers in [
        "re|i|m|s",
        "re|i|s|m",
        "re|m|i|s",
        "re|m|s|i",
        "re|s|i|m",
        "re|s|m|i",
        "RE|I|M|S",
        "re|i|i|m|m|s|s",
    ] {
        let rule = regex_rule(modifiers, "^start.end$");
        assert!(rule.is_match(&matching), "{modifiers}");
        assert!(!rule.is_match(&nonmatching), "{modifiers}");
    }

    // All three flags are necessary for this match.
    for modifiers in ["re|m|s", "re|i|s", "re|i|m"] {
        assert!(!regex_rule(modifiers, "^start.end$").is_match(&matching));
    }
}

#[test]
fn test_regex_submodifiers_with_value_lists() {
    for (modifiers, matches_one, matches_both, matches_neither) in [
        ("re|i|m|s", true, true, false),
        ("re|i|m|s|all", false, true, false),
        ("re|all|s|i|m", false, true, false),
        ("re|i|m|s|neq", false, false, true),
        ("re|i|m|s|all|neq", true, false, true),
    ] {
        let rule = rule_from_yaml(&format!(
            "title: Regex value lists\nlogsource: {{}}\ndetection:\n  selection:\n    Message|{modifiers}:\n      - '^start.end$'\n      - '^finish.done$'\n  condition: selection\n"
        ))
        .unwrap();

        for (message, expected) in [
            ("before\nSTART\nEND\nafter", matches_one),
            ("before\nFINISH\nDONE\nafter", matches_one),
            ("before\nSTART\nEND\nFINISH\nDONE\nafter", matches_both),
            ("before\nNOTHING\nafter", matches_neither),
        ] {
            assert_eq!(
                rule.is_match(&Event::from([("Message", message)])),
                expected,
                "{modifiers}: {message:?}"
            );
        }
    }
}

#[test]
fn test_regex_inline_flags() {
    for (modifiers, pattern, message, expected) in [
        ("re", "(?i)^needle$", "NEEDLE", true),
        ("re|m", "(?i)^needle$", "before\nNEEDLE\nafter", true),
        (
            "re|s",
            "(?im)^start.end$",
            "before\nSTART\nEND\nafter",
            true,
        ),
        ("re|i", "(?-i)^needle$", "NEEDLE", false),
        ("re|i", "^(?-i:needle)$", "NEEDLE", false),
        ("re|m", "(?-m)^needle$", "before\nneedle\nafter", false),
        ("re|s", "(?-s)^start.end$", "start\nend", false),
    ] {
        assert_eq!(
            regex_rule(modifiers, pattern).is_match(&Event::from([("Message", message)])),
            expected,
            "{modifiers}: {pattern}"
        );
    }
}
