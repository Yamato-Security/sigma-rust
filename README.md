# sigma-rust

![Build](https://github.com/Yamato-Security/sigma-rust/actions/workflows/ci.yml/badge.svg)

A Rust library for parsing and evaluating Sigma rules to create custom detection pipelines.

> [!NOTE]
> **This is a maintained and actively updated fork** of the original
> [`jopohl/sigma-rust`](https://github.com/jopohl/sigma-rust), kept by
> [Yamato Security](https://github.com/Yamato-Security). On top of the upstream
> features it:
>
> - adds **Sigma correlation rule** support (`event_count`, `value_count`, `temporal`, `temporal_ordered`),
> - tracks the latest Rust edition and dependency versions, and
> - uses [`yaml_serde`](https://github.com/yaml/yaml-serde) (the actively maintained
>   `serde_yaml` fork from the official YAML organization) as its YAML backend,
>   which — unlike some other successors — parses large `u64` values correctly.
>
> Releases are published as [GitHub releases](https://github.com/Yamato-Security/sigma-rust/releases)
> and consumed as a git dependency (this fork is not published to crates.io):
>
> ```toml
> sigma-rust = { git = "https://github.com/Yamato-Security/sigma-rust", tag = "v0.7.1" }
> ```

## Features

- Supports the [Sigma condition](https://sigmahq.io/docs/basics/conditions.html) syntax using Pratt parsing
- Supports all [Sigma field modifiers](https://sigmahq.io/docs/basics/modifiers.html) except `expand`
- Support
  for [String wildcards](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#string-wildcard)
- Supports [Sigma correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
  (`event_count`, `value_count`, `temporal`, and `temporal_ordered`) over a stream of timestamped events
- Written in 100% safe Rust
- Daily automated security audit of dependencies
- Extensive test suite (validated against the full SigmaHQ rule set)

## Example

```rust
use sigma_rust::{rule_from_yaml, event_from_json};

fn main() {
    let rule_yaml = r#"
    title: A test rule
    logsource:
        category: test
    detection:
        selection_1:
            Event.ID: 42
            TargetFilename|contains: ':\temp\'
            TargetFilename|endswith:
                - '.au3'
                - '\autoit3.exe'
        selection_2:
            Image|contains: ':\temp\'
            Image|endswith:
                - '.au3'
                - '\autoit3.exe'
        condition: 1 of selection_*
    "#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    let event = event_from_json(
        r#"{"TargetFilename": "C:\\temp\\file.au3", "Image": "C:\\temp\\autoit4.exe", "Event": {"ID": 42}}"#,
    )
        .unwrap();

    assert!(rule.is_match(&event));
}
```

## Matching nested fields

You can access nested fields by using a dot `.` as a separator. For example, if you have an event like

```json
{
  "Event": {
    "ID": 42
  }
}
```

you can access the `ID` field by using `Event.ID` in the Sigma rule. Note, that fields containing a dot take
precedence over nested fields. For example, if you have an event like

```json
{
  "Event.ID": 42,
  "Event": {
    "ID": 43
  }
}
```

the engine will evaluate `Event.ID` to 42.

## Strong type checking

This library performs strong type checking. That is, if you have a rule like

```yaml
selection:
  - myname: 42
```

it would __not__ match the event `{"myname": "42"}`, however, it would match `{"myname": 42}` (note the difference
between string and integer).
If you need to match against several types you can define a rule such as the following.

```yaml
selection_1:
  field: 42
selection_2:
  field: "42"
condition: 1 of them
```

## Sigma correlation rules

Beyond single rules, this fork evaluates
[Sigma correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
over a stream of timestamped events. Parse a document of base rules and
correlation rules with `parse_rules_from_yaml`, feed `TimestampedEvent`s to a
`CorrelationEngine`, and it emits a result whenever a correlation
(`event_count`, `value_count`, `temporal`, or `temporal_ordered`) fires. See
[`examples/detect_correlation.rs`](examples/detect_correlation.rs) for a
complete, runnable example.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Contributions are welcome! Please open an issue or create a pull request.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
