# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(as a `0.x` crate, breaking changes bump the minor version).

## [0.7.0] - 2026-07-18

This is a maintenance release that upgrades the toolchain and dependencies and
replaces the unmaintained YAML backend. It contains breaking changes.

### Changed — breaking

- **Migrated to Rust edition 2024** (MSRV raised from 1.81 to 1.86). ([#5])
- **Replaced the deprecated `serde_yml` with `yaml_serde`.** `serde_yml` is
  unmaintained — its only newer release is a shim that forwards to `noyalib`,
  which parses values in `(i64::MAX, u64::MAX]` as lossy `f64` and corrupts them.
  `yaml_serde` is the actively maintained fork of `serde_yaml`, published by the
  official [YAML organization](https://github.com/yaml/yaml-serde), and is a
  drop-in with correct `u64` handling. The public API's YAML type changes
  accordingly: `Rule.custom_fields` is now `HashMap<String, yaml_serde::Value>`
  and `rule_from_yaml` returns `Result<Rule, yaml_serde::Error>`. ([#7])
- Bumped `thiserror` from 1 to 2. ([#5])

### Changed

- Bumped the remaining dependencies to their latest versions: `strum` 0.26 → 0.28,
  `criterion` 0.5 → 0.8, and refreshed `base64`, `cidr`, `regex`, `serde`,
  `serde_json`, and `walkdir`. ([#5])
- CI: the Codecov upload is now best-effort (`fail_ci_if_error: false`) so a
  missing token no longer fails the build; build, test, clippy, and fmt remain
  the gate.

## Earlier releases

Releases before `0.7.0` predate this changelog. See the
[GitHub releases](https://github.com/Yamato-Security/sigma-rust/releases) and
[commit history](https://github.com/Yamato-Security/sigma-rust/commits/master)
for details.

- `0.6.0` — 2025-05-08
- `0.5.1` — 2025-01-26
- `0.5.0` — 2025-01-26
- `0.4.1` — 2025-01-17
- `0.4.0` — 2025-01-16
- `0.3.0` — 2024-11-28
- `0.2.1` — 2024-11-01
- `0.2.0` — 2024-10-31

[0.7.0]: https://github.com/Yamato-Security/sigma-rust/releases/tag/v0.7.0
[#5]: https://github.com/Yamato-Security/sigma-rust/pull/5
[#7]: https://github.com/Yamato-Security/sigma-rust/pull/7
