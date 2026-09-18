use sigma_rust::{Event, Rule, rule_from_yaml};

#[test]
fn test_match_rule_with_keywords() {
    let yaml = r#"title: A rule with keywords
logsource:
    service: test
detection:
    keywords:
        - '* hello world?'
        - '* arch linux?'
        - 'evil'
    condition: keywords
"#;
    let rule: Rule = yaml_serde::from_str(yaml).unwrap();
    let event_1 = Event::from([("a", "this is hello world "), ("os", "is windows")]);
    let event_2 = Event::from([("b", "this is arch linux!"), ("more", "something")]);
    let event_3 = Event::from([("c", "evil"), ("more", "something")]);
    let event_4 = Event::from([("d", "no keyword "), ("d", "no match")]);

    assert!(rule.is_match(&event_1));
    assert!(rule.is_match(&event_2));
    assert!(rule.is_match(&event_3));
    assert!(!rule.is_match(&event_4));
}

#[test]
fn test_match_rule_with_keywords_and_fields() {
    let yaml = r#"title: A rule with keywords
logsource:
    service: test
detection:
    keywords:
        - 'hello world'
        - 'arch linux'
    selection:
        a: test
        b: chuck
    condition: keywords and selection
"#;
    let rule: Rule = yaml_serde::from_str(yaml).unwrap();
    let event_1 = Event::from([("a", "this is hello world "), ("os", "is windows")]);
    let event_2 = Event::from([("a", "test"), ("b", "chuck"), ("c", "hello world")]);
    let event_3 = Event::from([("a", "test"), ("b", "chuck")]);

    assert!(!rule.is_match(&event_1));
    assert!(rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
}

#[test]
fn test_match_field_list() {
    let yaml = r#"
        title: Field list test
        logsource:
        detection:
            selection:
                Image|endswith: '\rundll32.exe'
                OriginalFileName: 'RUNDLL32.EXE'
            filter_main_known_extension:
                - CommandLine|contains:
                      # Note: This aims to cover: single and double quotes in addition to spaces and comma "," usage.
                      - 'test'
                      - 'something'
                  SomeValue: yes
                - CommandLine|endswith:
                      # Note: This aims to cover: single and double quotes in addition to spaces and comma "," usage.
                      - '.cpl'
                      - '.dll'
                      - '.inf'
            condition: selection and 1 of filter_*
    "#;

    let rule: Rule = yaml_serde::from_str(yaml).unwrap();

    let event_1 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
        ("CommandLine", "hello test"),
        ("SomeValue", "yes"),
    ]);
    let event_2 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
        ("CommandLine", "a.dll"),
    ]);
    let event_3 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "nomatch.EXE"),
        ("CommandLine", "a.dll"),
    ]);
    let event_4 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
        ("CommandLine", "hello test"),
    ]);

    assert!(rule.is_match(&event_1));
    assert!(rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
    assert!(!rule.is_match(&event_4));
}

#[test]
fn test_match_bool_fields() {
    let yaml = r#"
    title: Rule with bool field
    logsource:
    detection:
        selection:
            flag: true
        condition: selection
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    let event_1 = Event::from([("flag", true)]);
    let event_2 = Event::from([("flag", false)]);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
}

#[test]
fn test_match_null_fields() {
    let yaml = r#"
    title: Rule with null field
    logsource:
    detection:
        selection:
            - Image|endswith: '\rundll32.exe'
            - OriginalFileName: 'RUNDLL32.EXE'
        filter_main_null:
            CommandLine: null
        condition: selection and not 1 of filter_main_*
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    let event_1 = Event::from([("OriginalFileName", "RUNDLL32.EXE")]);
    let mut event_2 = Event::new();
    event_2.insert("Image", "c:\\rundll32.exe");
    event_2.insert("CommandLine", None);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
}

#[test]
fn test_match_cased_contains_modifier() {
    let yaml = r#"
    title: Rule with cased modifier
    logsource:
    detection:
        selection:
            - File|contains|cased: evil
        condition: selection
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    let event_1 = Event::from([("File", "c:\\evil.exe")]);
    let event_2 = Event::from([("File", "C:\\EVIL.exe")]);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
}

#[test]
fn test_match_cased_windash() {
    let yaml = r#"
    title: Rule with cased modifier
    logsource:
    detection:
        selection:
            - CMD|windash|cased: -force
        condition: selection
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    let event_1 = Event::from([("CMD", "-force")]);
    let event_2 = Event::from([("CMD", "-FORCE")]);
    let event_3 = Event::from([("CMD", "/force")]);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
    assert!(rule.is_match(&event_3));
}

#[test]
fn test_match_exists_modifier() {
    let yaml = r#"
        title: Existential test
        logsource:
        detection:
            selection:
                Image|exists: true
                OriginalFileName|exists: false
            condition: selection
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    let event_1 = Event::from([("Image", "C:\\rundll32.exe")]);
    let event_2 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
    ]);
    let event_3 = Event::from([("SomeField", "SomeValue")]);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
}

#[test]
fn test_match_neq_modifier() {
    // `neq` (Sigma specification v2.1.0) negates the comparison of a single field, so an
    // exclusion can live in the selection itself instead of a separate `not filter` selection.
    let yaml = r#"
        title: Logon from an unexpected source
        logsource:
        detection:
            selection:
                EventID: 4624
                LogonType: 10
                SubjectUserName|endswith|neq: '$'
                IpAddress|cidr|neq:
                    - 10.0.0.0/8
                    - 192.168.0.0/16
            condition: selection
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    let logon = |user: Option<&str>, ip: Option<&str>| {
        let mut event = Event::new();
        event.insert("EventID", 4624);
        event.insert("LogonType", 10);
        if let Some(user) = user {
            event.insert("SubjectUserName", user);
        }
        if let Some(ip) = ip {
            event.insert("IpAddress", ip);
        }
        event
    };
    let event_1 = logon(Some("alice"), Some("203.0.113.7"));
    // A machine account: `SubjectUserName|endswith|neq: '$'` rejects it.
    let event_2 = logon(Some("WS01$"), Some("203.0.113.7"));
    // An internal source: `IpAddress|cidr|neq` rejects any address in one of the ranges.
    let event_3 = logon(Some("alice"), Some("192.168.1.20"));
    // A missing field is different from every value, so the negated fields still match.
    let event_4 = logon(None, None);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
    assert!(rule.is_match(&event_4));
}

#[test]
fn test_match_neq_list_and_all() {
    let yaml = r#"
        title: neq with value lists
        logsource:
        detection:
            not_system_channel:
                Channel|neq:
                    - Security
                    - System
            not_both_keywords:
                CommandLine|contains|all|neq:
                    - '-enc'
                    - '-nop'
            condition: not_system_channel and not_both_keywords
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    // Neither channel value, and only one of the two keywords: both selections hold.
    let event_1 = Event::from([
        ("Channel", "Microsoft-Windows-PowerShell/Operational"),
        ("CommandLine", "powershell -nop -c whoami"),
    ]);
    // With a list, `neq` means "different from all of the values": Security is listed.
    let event_2 = Event::from([
        ("Channel", "Security"),
        ("CommandLine", "powershell -nop -c whoami"),
    ]);
    // `all|neq` is the negation of the AND: both keywords are present, so it fails.
    let event_3 = Event::from([
        ("Channel", "Microsoft-Windows-PowerShell/Operational"),
        ("CommandLine", "powershell -nop -enc AAAA"),
    ]);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
}

#[test]
fn test_match_fieldref_neq_modifier() {
    let yaml = r#"
        title: Parent and child differ
        logsource:
        detection:
            selection:
                Image|fieldref|neq: ParentImage
            condition: selection
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    let event_1 = Event::from([
        ("Image", "C:\\Windows\\System32\\cmd.exe"),
        ("ParentImage", "C:\\Windows\\explorer.exe"),
    ]);
    // Same value: no match.
    let event_2 = Event::from([
        ("Image", "C:\\Windows\\System32\\cmd.exe"),
        ("ParentImage", "C:\\Windows\\System32\\cmd.exe"),
    ]);
    // A missing referenced field counts as different.
    let event_3 = Event::from([("Image", "C:\\Windows\\System32\\cmd.exe")]);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
    assert!(rule.is_match(&event_3));
}

#[test]
fn test_match_neq_equals_condition_not() {
    // `field|neq: value` in a selection is equivalent to `not` on a selection holding
    // `field: value`, including for a missing field.
    let neq_yaml = r#"
        title: neq
        logsource:
        detection:
            selection:
                Channel|contains|neq: Security
            condition: selection
    "#;
    let not_yaml = r#"
        title: not
        logsource:
        detection:
            selection:
                Channel|contains: Security
            condition: not selection
    "#;

    let neq_rule = rule_from_yaml(neq_yaml).unwrap();
    let not_rule = rule_from_yaml(not_yaml).unwrap();
    let events = [
        Event::from([("Channel", "Security")]),
        Event::from([("Channel", "Microsoft-Windows-Security-Auditing")]),
        Event::from([("Channel", "System")]),
        Event::from([("Other", "Security")]),
    ];
    for event in events.iter() {
        assert_eq!(neq_rule.is_match(event), not_rule.is_match(event));
    }
    assert!(!neq_rule.is_match(&events[0]));
    assert!(!neq_rule.is_match(&events[1]));
    assert!(neq_rule.is_match(&events[2]));
    assert!(neq_rule.is_match(&events[3]));
}
