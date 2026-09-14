use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sigma_rust::correlation::*;
use sigma_rust::{Rule, event_from_json, rule_from_yaml};

fn create_test_rule(title: &str) -> Rule {
    let yaml = format!(
        "title: {}\nlogsource:\n  category: test\n  product: test\ndetection:\n  selection:\n    field: value\n  condition: selection",
        title
    );
    rule_from_yaml(&yaml).unwrap()
}
#[test]
fn test_parse_timespan() {
    assert_eq!(
        CorrelationEngine::parse_timespan("30s").unwrap(),
        std::time::Duration::from_secs(30)
    );
    assert_eq!(
        CorrelationEngine::parse_timespan("5m").unwrap(),
        std::time::Duration::from_secs(300)
    );
    assert_eq!(
        CorrelationEngine::parse_timespan("1h").unwrap(),
        std::time::Duration::from_secs(3600)
    );
    assert_eq!(
        CorrelationEngine::parse_timespan("2d").unwrap(),
        std::time::Duration::from_secs(172800)
    );

    // Test invalid formats
    assert!(CorrelationEngine::parse_timespan("").is_err());
    assert!(CorrelationEngine::parse_timespan("5x").is_err());
    assert!(CorrelationEngine::parse_timespan("abc").is_err());
    assert!(CorrelationEngine::parse_timespan("5").is_err());
}

#[test]
fn test_correlation_condition_comprehensive() {
    // Test gte condition
    let condition = CorrelationCondition {
        gte: Some(10),
        ..Default::default()
    };
    assert!(condition.matches(10));
    assert!(condition.matches(15));
    assert!(!condition.matches(5));

    // Test lte condition
    let condition = CorrelationCondition {
        lte: Some(20),
        ..Default::default()
    };
    assert!(condition.matches(20));
    assert!(condition.matches(15));
    assert!(!condition.matches(25));

    // Test eq condition
    let condition = CorrelationCondition {
        eq: Some(10),
        ..Default::default()
    };
    assert!(condition.matches(10));
    assert!(!condition.matches(15));
    assert!(!condition.matches(5));

    // Test gt condition
    let condition = CorrelationCondition {
        gt: Some(5),
        ..Default::default()
    };
    assert!(condition.matches(10));
    assert!(!condition.matches(5));
    assert!(!condition.matches(3));

    // Test lt condition
    let condition = CorrelationCondition {
        lt: Some(10),
        ..Default::default()
    };
    assert!(condition.matches(5));
    assert!(!condition.matches(10));
    assert!(!condition.matches(15));

    // Test combined conditions
    let condition = CorrelationCondition {
        gte: Some(5),
        lte: Some(20),
        ..Default::default()
    };
    assert!(condition.matches(10));
    assert!(condition.matches(5));
    assert!(condition.matches(20));
    assert!(!condition.matches(3));
    assert!(!condition.matches(25));
}

/// The Sigma correlation spec spells the grouping key `group-by`, with a hyphen. Without
/// `#[serde(rename = "group-by")]` serde looked for `group_by`, found nothing and left the field
/// `None` — and because serde ignores unknown keys by default, the rule still parsed and the
/// caller had no way to notice. Every correlation rule in the wild (SigmaHQ's and Suzaku's alike)
/// writes the hyphenated form, so grouping was dropped and thresholds were evaluated across the
/// whole corpus instead of per user, per source IP or per event id.
#[test]
fn test_group_by_accepts_the_hyphenated_spec_key() {
    let hyphenated = r#"
title: Grouped
correlation:
  type: event_count
  rules:
    - base
  group-by:
    - user
    - src_ip
  timespan: 5m
  condition:
    gte: 3
"#;
    let rule = parse_correlation_rule_from_yaml(hyphenated).unwrap();
    assert!(
        rule.correlation.group_by.is_some(),
        "the spec key `group-by` must deserialize into `group_by`"
    );
    assert_eq!(
        rule.correlation.group_by.unwrap(),
        vec!["user".to_string(), "src_ip".to_string()]
    );

    // The snake_case spelling stays accepted via the alias, so nothing that parsed before breaks.
    let underscored = hyphenated.replace("group-by:", "group_by:");
    let rule = parse_correlation_rule_from_yaml(&underscored).unwrap();
    assert_eq!(
        rule.correlation.group_by.unwrap(),
        vec!["user".to_string(), "src_ip".to_string()]
    );

    // A rule that declares no grouping still yields `None` rather than an empty list.
    let ungrouped = r#"
title: Ungrouped
correlation:
  type: event_count
  rules:
    - base
  timespan: 5m
  condition:
    gte: 3
"#;
    let rule = parse_correlation_rule_from_yaml(ungrouped).unwrap();
    assert!(rule.correlation.group_by.is_none());
}

/// The Sigma correlation spec defines `aliases` as a two-level map — alias name, then
/// referenced-rule name, then the field carrying that alias in that rule's log source. The
/// `FieldAliases` wrapper was not `#[serde(transparent)]`, so serde demanded a redundant nested
/// `aliases:` key underneath `correlation.aliases`. Unlike the `group-by` bug this was a hard
/// parse failure: any spec-conformant rule using aliases was rejected outright.
#[test]
fn test_aliases_parse_in_the_spec_two_level_form() {
    let yaml = r#"
title: Aliased
correlation:
  type: event_count
  rules:
    - rule_a
    - rule_b
  group-by:
    - user
  timespan: 5m
  condition:
    gte: 2
  aliases:
    user:
      rule_a: TargetUserName
      rule_b: SubjectUserName
"#;
    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    let aliases = rule.correlation.aliases.as_ref().expect("aliases parsed");
    let user = aliases.aliases.get("user").expect("`user` alias present");
    assert_eq!(user.get("rule_a"), Some(&"TargetUserName".to_string()));
    assert_eq!(user.get("rule_b"), Some(&"SubjectUserName".to_string()));
}

/// Aliases are only useful if the engine actually resolves them, so drive the parsed rule
/// through `process_events`: two base rules name the same user in differently-spelled fields,
/// and the alias has to collapse them into one group for the `gte: 2` threshold to trip.
#[test]
fn test_aliases_resolve_fields_per_referenced_rule() {
    let yaml = r#"
title: Aliased
correlation:
  type: event_count
  rules:
    - rule_a
    - rule_b
  group-by:
    - user
  timespan: 5m
  condition:
    gte: 2
  aliases:
    user:
      rule_a: TargetUserName
      rule_b: SubjectUserName
"#;
    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();

    let rule_a = create_test_rule("rule_a");
    let rule_b = create_test_rule("rule_b");

    let mut engine = CorrelationEngine::new();
    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2024-01-01T10:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    let events = vec![
        // alice, seen once under each rule's own spelling of the field
        TimestampedEvent {
            event: event_from_json(r#"{"TargetUserName": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"SubjectUserName": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule_b,
        },
        // bob only shows up once, so he must not reach the threshold
        TimestampedEvent {
            event: event_from_json(r#"{"TargetUserName": "bob"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
    ];

    let results = engine.process_events(&events).unwrap();
    let matched: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(
        matched.len(),
        1,
        "only alice's two differently-named fields should collapse into one group"
    );
    assert_eq!(matched[0].count, 2);
    assert_eq!(matched[0].aggregation_key.group_values, vec!["alice"]);
}

/// The spec allows a bare scalar wherever a list of rule names is expected.
#[test]
fn test_rules_accepts_a_scalar() {
    let yaml = r#"
title: Single rule
correlation:
  type: event_count
  rules: single_rule
  group-by:
    - user
  timespan: 5m
  condition:
    gte: 3
"#;
    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    assert_eq!(rule.correlation.rules, vec!["single_rule".to_string()]);

    // The sequence form keeps working.
    let as_seq = yaml.replace("rules: single_rule", "rules:\n    - single_rule");
    let rule = parse_correlation_rule_from_yaml(&as_seq).unwrap();
    assert_eq!(rule.correlation.rules, vec!["single_rule".to_string()]);
}

/// Likewise for `group-by`, whose most common real-world form is a single field name.
#[test]
fn test_group_by_accepts_a_scalar() {
    let yaml = r#"
title: Single group key
correlation:
  type: event_count
  rules:
    - base
  group-by: user
  timespan: 5m
  condition:
    gte: 3
"#;
    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    assert_eq!(
        rule.correlation.group_by,
        Some(vec!["user".to_string()]),
        "a scalar `group-by` must become a one-element list"
    );

    // The snake_case alias takes a scalar too.
    let underscored = yaml.replace("group-by: user", "group_by: user");
    let rule = parse_correlation_rule_from_yaml(&underscored).unwrap();
    assert_eq!(rule.correlation.group_by, Some(vec!["user".to_string()]));
}

/// The `group-by` rename changed the *write* path as well as the read path: serializing a
/// correlation rule now emits the hyphenated spec key, where it used to emit `group_by`.
/// Aliases likewise serialize in the flat spec form, with no redundant nested `aliases:` key.
#[test]
fn test_serialization_round_trip_emits_the_spec_keys() {
    let yaml = r#"
title: Round trip
correlation:
  type: event_count
  rules:
    - rule_a
  group-by:
    - user
    - src_ip
  timespan: 5m
  condition:
    gte: 3
  aliases:
    user:
      rule_a: TargetUserName
"#;
    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    let serialized = yaml_serde::to_string(&rule).unwrap();

    assert!(
        serialized.contains("group-by:"),
        "serialization must emit the spec key `group-by`, got:\n{serialized}"
    );
    assert!(
        !serialized.contains("group_by:"),
        "the old `group_by` spelling must no longer be written, got:\n{serialized}"
    );
    assert_eq!(
        serialized.matches("aliases:").count(),
        1,
        "aliases must serialize flat, without a redundant nested key, got:\n{serialized}"
    );

    let reparsed = parse_correlation_rule_from_yaml(&serialized).unwrap();
    assert_eq!(reparsed.correlation.group_by, rule.correlation.group_by);
    assert_eq!(reparsed.correlation.rules, rule.correlation.rules);
    assert_eq!(
        reparsed
            .correlation
            .aliases
            .as_ref()
            .unwrap()
            .aliases
            .get("user")
            .and_then(|m| m.get("rule_a")),
        Some(&"TargetUserName".to_string())
    );
}

#[test]
fn test_parse_correlation_rule() {
    let yaml = r#"
title: Multiple failed logons for a single user
status: test
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
    - TargetDomainName
  timespan: 5m
  condition:
    gte: 10
tags:
  - brute_force
  - attack.t1110
"#;

    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    assert_eq!(rule.title, "Multiple failed logons for a single user");
    assert_eq!(
        rule.correlation.correlation_type,
        CorrelationType::EventCount
    );
    assert_eq!(rule.correlation.rules, vec!["failed_logon"]);
    assert_eq!(
        rule.correlation.group_by,
        Some(vec![
            "TargetUserName".to_string(),
            "TargetDomainName".to_string()
        ])
    );
    assert_eq!(rule.correlation.timespan, "5m");
    assert_eq!(rule.correlation.condition.unwrap().gte, Some(10));
}

#[test]
fn test_parse_value_count_correlation_rule() {
    let yaml = r#"
title: Enumeration of multiple high-privilege groups
status: stable
correlation:
  type: value_count
  rules:
    - privileged_group_enumeration
  group-by:
    - SubjectUserName
  timespan: 15m
  condition:
    gte: 4
    field: TargetUserName
level: high
"#;

    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    assert_eq!(
        rule.correlation.correlation_type,
        CorrelationType::ValueCount
    );
    assert_eq!(
        rule.correlation.group_by,
        Some(vec!["SubjectUserName".to_string()])
    );
    assert_eq!(
        rule.correlation.condition.clone().unwrap().field,
        Some("TargetUserName".to_string())
    );
    assert_eq!(rule.correlation.condition.unwrap().gte, Some(4));
}

#[test]
fn test_parse_temporal_correlation_rule() {
    let yaml = r#"
title: CVE-2023-22518 Exploit Chain
description: Access to endpoint vulnerable to CVE-2023-22518 with suspicious process creation
status: experimental
correlation:
  type: temporal
  rules:
    - a902d249-9b9c-4dc4-8fd0-fbe528ef965c
    - 1ddaa9a4-eb0b-4398-a9fe-7b018f9e23db
  timespan: 10s
  condition:
    gte: 2
level: high
"#;

    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    assert_eq!(rule.correlation.correlation_type, CorrelationType::Temporal);
    assert_eq!(rule.correlation.rules.len(), 2);
    assert_eq!(rule.correlation.timespan, "10s");
}

#[test]
fn parse_correlation_and_base_rules() {
    let yaml = r#"
title: Correlation Rule
correlation:
  type: temporal
  rules:
    - rule1
    - rule2
  timespan: 15m
  condition:
    eq: 2
---
name: rule1
title: Base Rule 1
logsource:
    category: test
    product: windows
detection:
  selection:
    field1: value1
  condition: selection
---
name: rule2
title: Base Rule 2
logsource:
    category: test
    product: windows
detection:
  selection:
    field2: value2
  condition: selection
"#;

    let (correlation_rules, base_rules) = parse_rules_from_yaml(yaml).unwrap();

    assert_eq!(correlation_rules.len(), 1);
    assert_eq!(base_rules.len(), 2);

    assert_eq!(correlation_rules[0].title, "Correlation Rule");

    assert_eq!(base_rules[0].0, "rule1");
    assert_eq!(base_rules[1].0, "rule2");
}

#[test]
fn test_event_count_correlation() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Test Rule".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::EventCount,
            rules: vec!["test_rule".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "5m".to_string(),
            condition: Some(CorrelationCondition {
                gte: Some(3),
                ..Default::default()
            }),
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let rule: Rule = create_test_rule("test_rule");
    let events = vec![
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(60),
            rule: &rule,
        },
    ];

    let results = engine.process_events(&events).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].matched);
    assert_eq!(results[0].count, 3);
}

#[test]
fn test_event_count_correlation_multiple_groups() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Test Rule".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::EventCount,
            rules: vec!["test_rule".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "5m".to_string(),
            condition: Some(CorrelationCondition {
                gte: Some(2),
                ..Default::default()
            }),
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let rule: Rule = create_test_rule("test_rule");
    let events = vec![
        // Alice events (should match)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule,
        },
        // Bob events (should match)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(60),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(90),
            rule: &rule,
        },
        // Charlie events (should not match - only 1 event)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "charlie"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(120),
            rule: &rule,
        },
    ];

    let results = engine.process_events(&events).unwrap();
    assert_eq!(results.len(), 3); // One result per group

    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 2); // Alice and Bob should match

    for result in matched_results {
        assert_eq!(result.count, 2);
    }
}

#[test]
fn test_event_count_time_window() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Test Rule".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::EventCount,
            rules: vec!["test_rule".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "5m".to_string(),
            condition: Some(CorrelationCondition {
                gte: Some(3),
                lte: None,
                eq: None,
                gt: None,
                lt: None,
                field: None,
            }),
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);
    let rule: Rule = create_test_rule("test_rule");
    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let events = vec![
        // Events within 5 minutes - should be grouped together
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(2),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(4),
            rule: &rule,
        },
        // Event outside 5-minutes window - should be in different bucket
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(10),
            rule: &rule,
        },
    ];

    let results = engine.process_events(&events).unwrap();
    assert_eq!(results.len(), 2); // Two time buckets

    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 1); // Only the first bucket should match (3 events)
    assert_eq!(matched_results[0].count, 3);
}

#[test]
fn test_value_count_correlation() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Test Value Count Rule".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::ValueCount,
            rules: vec!["test_rule".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "15m".to_string(),
            condition: Some(CorrelationCondition {
                gte: Some(3),
                lte: None,
                eq: None,
                gt: None,
                lt: None,
                field: Some("target".to_string()),
            }),
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let rule: Rule = create_test_rule("test_rule");
    let events = vec![
        // Alice targeting different systems
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice", "target": "system1"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice", "target": "system2"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(5),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice", "target": "system3"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(10),
            rule: &rule,
        },
        // Bob targeting only two systems
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob", "target": "system1"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob", "target": "system2"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(5),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob", "target": "system2"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(10),
            rule: &rule,
        },
    ];

    let results = engine.process_events(&events).unwrap();
    assert_eq!(results.len(), 2); // One result per user

    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 1); // Only Alice should match (3 distinct targets)

    for result in &matched_results {
        if result
            .aggregation_key
            .group_values
            .contains(&"alice".to_string())
        {
            assert_eq!(result.count, 3);
        }
    }

    let unmatched_results: Vec<_> = results.iter().filter(|r| !r.matched).collect();
    for result in &unmatched_results {
        if result
            .aggregation_key
            .group_values
            .contains(&"bob".to_string())
        {
            assert_eq!(result.count, 2); // Bob only has 2 distinct targets
        }
    }
}

#[test]
fn test_temporal_correlation() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Temporal Sequence Test".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::Temporal,
            rules: vec!["rule_a".to_string(), "rule_b".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "1m".to_string(),
            condition: Some(CorrelationCondition {
                gte: Some(2),
                ..Default::default()
            }),
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let rule_a: Rule = create_test_rule("rule_a");
    let rule_b: Rule = create_test_rule("rule_b");
    let events = vec![
        // Alice's valid sequence (within timespan)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule_b,
        },
        // Bob's valid sequence (within timespan)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(5),
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(45),
            rule: &rule_b,
        },
        // Charlie's incomplete sequence (only rule_a)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "charlie"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        // Dave's sequence outside of timespan
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(2),
            rule: &rule_b,
        },
    ];

    let results = engine.process_events(&events).unwrap();

    // Processed events from 5 users
    assert_eq!(results.len(), 5);

    // Only two groups should match (alice, bob)
    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 2);

    // Verify results for alice and bob
    for result in &matched_results {
        // Each match should contain exactly 2 rules
        assert_eq!(result.count, 2);

        // Confirm that the group value is either alice or bob
        let group_value = &result.aggregation_key.group_values[0];
        assert!(group_value == "alice" || group_value == "bob");
    }
}

#[test]
fn test_ordered_temporal_correlation() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Ordered Temporal Sequence Test".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::TemporalOrdered,
            rules: vec![
                "rule_a".to_string(),
                "rule_b".to_string(),
                "rule_c".to_string(),
            ],
            group_by: Some(vec!["user".to_string()]),
            timespan: "1m".to_string(),
            condition: Some(CorrelationCondition {
                gte: Some(3),
                ..Default::default()
            }),
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    let rule_a: Rule = create_test_rule("rule_a");
    let rule_b: Rule = create_test_rule("rule_b");
    let rule_c: Rule = create_test_rule("rule_c");

    let events = vec![
        // Alice's valid sequence (correct order within timespan)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(15),
            rule: &rule_b,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule_c,
        },
        // Bob's invalid sequence (incorrect order - b comes before a)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_b,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(20),
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(40),
            rule: &rule_c,
        },
        // Charlie's incomplete sequence (missing rule_b)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "charlie"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "charlie"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule_c,
        },
        // Dave's valid sequence but outside of timespan
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule_b,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(2),
            rule: &rule_c,
        },
    ];

    let results = engine.process_events(&events).unwrap();

    // Processed events from 5 users
    assert_eq!(results.len(), 5);

    // Only one group should match (alice)
    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 1);

    // Verify results for alice
    for result in &matched_results {
        // Each match should contain exactly 3 rules
        assert_eq!(result.count, 3);

        // Confirm that the group value is alice
        let group_value = &result.aggregation_key.group_values[0];
        assert_eq!(group_value, "alice");
    }
}
