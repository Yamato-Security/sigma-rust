# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(as a `0.x` crate, breaking changes bump the minor version).

## [0.7.1] - 2026-07-18

### Added

- **Sigma correlation rules.** New public API for evaluating Sigma correlation
  rules over a stream of timestamped events: `CorrelationEngine`,
  `SigmaCorrelationRule`, `TimestampedEvent`, `parse_rules_from_yaml`, and
  `correlation_rule_from_yaml`. Supports `event_count`, `value_count`,
  `temporal`, and `temporal_ordered` correlation types.

### Changed

- Reconciled the correlation feature onto the `yaml_serde` backend (see 0.7.0):
  the correlation work had been developed against `serde_yml` 0.0.13, whose
  `noyalib` backend has no `u64` representation (corrupting large unsigned values
  into lossy floats) and a YAML 1.2 core-schema that broke a Sigma rule. On
  `yaml_serde` (YAML 1.1, correct `u64`) all 3,040 SigmaHQ rules parse.

## [0.7.0] - 2026-07-18

Maintenance release: toolchain and dependency upgrades and a YAML-backend
replacement. Contains breaking changes.

### Changed — breaking

- **Migrated to Rust edition 2024** (MSRV raised from 1.81 to 1.86).
- **Replaced the deprecated `serde_yml` with `yaml_serde`** — the actively
  maintained fork of `serde_yaml`, published by the official
  [YAML organization](https://github.com/yaml/yaml-serde), a drop-in with correct
  `u64` handling. The public YAML type changes accordingly: `Rule.custom_fields`
  is now `HashMap<String, yaml_serde::Value>` and `rule_from_yaml` returns
  `Result<Rule, yaml_serde::Error>`.
- Bumped `thiserror` from 1 to 2.

### Changed

- Bumped the remaining dependencies to their latest versions (`strum` 0.26 →
  0.28, `criterion` 0.5 → 0.8, and refreshed `base64`, `cidr`, `regex`, `serde`,
  `serde_json`, `walkdir`).
- CI: the Codecov upload is now best-effort so a missing token no longer fails
  the build.

## Earlier releases

Releases before `0.7.0` predate this changelog. See the
[GitHub releases](https://github.com/Yamato-Security/sigma-rust/releases) and
[commit history](https://github.com/Yamato-Security/sigma-rust/commits/main).

- `0.6.0` — 2025-05-08 · `0.5.1` / `0.5.0` — 2025-01-26 · `0.4.1` — 2025-01-17 ·
  `0.4.0` — 2025-01-16 · `0.3.0` — 2024-11-28 · `0.2.1` — 2024-11-01 ·
  `0.2.0` — 2024-10-31

[0.7.1]: https://github.com/Yamato-Security/sigma-rust/releases/tag/v0.7.1
[0.7.0]: https://github.com/Yamato-Security/sigma-rust/releases/tag/v0.7.0
