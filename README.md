# sigma-rust

![Build](https://github.com/Yamato-Security/sigma-rust/actions/workflows/ci.yml/badge.svg)

A Rust library for parsing and evaluating Sigma rules to create custom detection pipelines.

> [!NOTE]
> **This is an actively maintained fork** of the original
> [`jopohl/sigma-rust`](https://github.com/jopohl/sigma-rust) crate, maintained by
> [Yamato Security](https://github.com/Yamato-Security). The upstream crate's latest
> release is [`v0.7.0` (November 2025)](https://crates.io/crates/sigma-rust) and it has
> had no commits since; this fork continues its development and — most notably — adds
> **Sigma correlation-rule** support. See
> [Differences from the upstream crate](#differences-from-the-upstream-crate) for the full list.
>
> This fork is **not published to crates.io** — consume it as a git dependency pinned to a
> [release tag](https://github.com/Yamato-Security/sigma-rust/releases):
>
> ```toml
> sigma-rust = { git = "https://github.com/Yamato-Security/sigma-rust", tag = "v0.7.2" }
> ```

## Features

- Supports the [Sigma condition](https://sigmahq.io/docs/basics/conditions.html) syntax using Pratt parsing
- Supports the [Sigma field modifiers](https://sigmahq.io/docs/basics/modifiers.html), including the
  `neq` negation modifier added in Sigma specification v2.1.0 (not yet supported: `expand`, the `re`
  sub-modifiers `i`/`m`/`s`, and the v2.1.0 time modifiers `minute`/`hour`/`day`/`week`/`month`/`year`)
- Support
  for [String wildcards](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#string-wildcard)
- Supports [Sigma correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
  (`event_count`, `value_count`, `temporal`, and `temporal_ordered`) over a stream of timestamped events
- Written in 100% safe Rust
- Daily automated security audit of dependencies
- Extensive test suite (validated against the full SigmaHQ rule set)

## Differences from the upstream crate

This fork builds on [`jopohl/sigma-rust`](https://github.com/jopohl/sigma-rust) `v0.7.0`
(Rust edition 2021, the `serde_norway` YAML backend, and **no correlation support**). The
notable differences are:

| Area | Upstream `jopohl/sigma-rust` `v0.7.0` | This fork (`v0.7.1`) |
|---|---|---|
| **Sigma correlation rules** | not supported | **supported** — `event_count`, `value_count`, `temporal`, and `temporal_ordered` correlations over a stream of timestamped events, via a new `correlation` module (`CorrelationEngine`, `SigmaCorrelationRule`, `TimestampedEvent`, `parse_rules_from_yaml`, `correlation_rule_from_yaml`) |
| **Rust edition / MSRV** | edition 2021, MSRV 1.81 | **edition 2024, MSRV 1.86** |
| **YAML backend** | `serde_norway` | **`yaml_serde`** — the [YAML organization's](https://github.com/yaml/yaml-serde) actively-maintained `serde_yaml` successor, with correct `u64` handling (all 3,040 SigmaHQ rules parse) |
| **New dependencies** | — | `chrono` (event timestamps), `rayon` (parallel evaluation), `anyhow` (correlation error handling) |
| **Error handling** | `thiserror` 1 | `thiserror` 2 |
| **Other dependencies** | older pins | refreshed — e.g. `strum` 0.26 → 0.28, `criterion` 0.5 → 0.8, plus `cidr`, `regex`, `serde`, `serde_json` |
| **Benchmarks** | matching only | matching **and** correlation benchmarks |
| **Distribution** | published on [crates.io](https://crates.io/crates/sigma-rust) | GitHub releases only — consumed as a pinned git dependency (not on crates.io) |
| **Maintenance** | last release `v0.7.0` (Nov 2025), no commits since | actively maintained |

Because of the YAML-backend change, the public API differs: `Rule.custom_fields` is a
`HashMap<String, yaml_serde::Value>` and `rule_from_yaml` returns
`Result<Rule, yaml_serde::Error>` (the upstream types are the `serde_norway` equivalents).

See the [CHANGELOG](CHANGELOG.md) for the full release history.

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
