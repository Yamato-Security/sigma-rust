# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(as a `0.x` crate, breaking changes bump the minor version).

## [Unreleased]

### Added

- **The `neq` field modifier** from the
  [Sigma specification v2.1.0](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md).
  `neq` negates the whole comparison of a field, so it composes with any other
  modifier — `Channel|neq`, `CommandLine|contains|neq`, `Image|endswith|neq`,
  `IpAddress|cidr|neq`, `EventID|gt|neq`, `Image|fieldref|neq`, ... — and lets a
  rule express an exclusion inside a selection instead of a separate
  `not filter` selection. With a list of values the field must differ from
  **all** of them (the negation of the OR), with `|all` it must fail at least one
  of them (the negation of the AND), and a missing field (or a missing
  `fieldref` target) counts as different, so it matches — the same semantics as
  pySigma's `SigmaNegateModifier` and Hayabusa. Repeating `neq` is idempotent,
  and `exists` stays standalone (`exists|neq` is rejected; negate it by flipping
  the boolean instead). Rules using `neq` were previously rejected with
  `Unknown field modifier 'neq'`.

## [0.7.2] - 2026-09-18

### Changed

- Bumped dependencies to their latest releases: `base64` 0.22.1 → 0.23.1,
  `serde` 1.0.228 → 1.0.229, `serde_json` 1.0.150 → 1.0.151,
  `yaml_serde` 0.10.4 → 0.10.7, `thiserror` 2.0.18 → 2.0.20,
  `anyhow` 1.0.103 → 1.0.104.

### Fixed

- **Correlation `group-by` was silently ignored.** The Sigma correlation spec
  spells the grouping key `group-by`, but `CorrelationSection::group_by` carried
  no `#[serde(rename)]`, so serde looked for `group_by`, found nothing and — since
  unknown keys are ignored by default — left the field `None` without an error.
  Every correlation rule written to spec lost its grouping: thresholds were
  evaluated across the whole event corpus instead of per user, per source IP or
  per event id, which both suppressed real matches and produced false ones. The
  hyphenated key now deserializes correctly and `group_by` is kept as an alias so
  rules written against the old behaviour still parse. Note this also changes the
  *write* path: serializing a `CorrelationSection` now emits `group-by` rather
  than `group_by`.
- **Correlation `aliases` failed to parse in its spec form.** `FieldAliases`
  required a redundant nested `aliases:` key underneath `correlation.aliases`,
  so the spec's two-level `aliases: {<alias>: {<rule>: <field>}}` mapping was
  rejected outright — a hard parse failure, not a silent drop. `FieldAliases` now
  serializes as `#[serde(transparent)]` and deserializes from either the spec
  mapping or the legacy nested form that earlier releases emitted;
  `resolve_field_alias` behaviour is unchanged.
- **Scalars are now accepted where the spec allows them.** `rules: single_rule`
  and `group-by: user` deserialize into one-element vectors, matching the spec's
  allowance of a bare scalar in place of a single-item list. Sequence forms are
  unaffected.

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

[Unreleased]: https://github.com/Yamato-Security/sigma-rust/compare/v0.7.2...HEAD
[0.7.2]: https://github.com/Yamato-Security/sigma-rust/releases/tag/v0.7.2
[0.7.1]: https://github.com/Yamato-Security/sigma-rust/releases/tag/v0.7.1
[0.7.0]: https://github.com/Yamato-Security/sigma-rust/releases/tag/v0.7.0
