# Yeager Project Guidelines & Release Policy

## Release Pre-Flight Protocol
Before creating or pushing any git release tag (`v*`):
1. **Changelog Gate:** Always update `CHANGELOG.md` and `CHANGELOG.vi.md` with the new version section. Ensure both English and Vietnamese sections detail all changes under `### Added`, `### Changed`, or `### Fixed`.
2. **Version Alignment:** Verify `version` in workspace `Cargo.toml`, `Cargo.lock`, and `installer/setup.iss` match the target release.
3. **Verification:** Run `cargo test --workspace` and `cargo clippy --workspace --all-targets` with 0 errors.
4. **Authenticode Signing:** Ensure pinned thumbprint `0E9C6BBE35AC13E58F951C446F2B524FA7297DCA` and DigiCert RFC 3161 timestamps are enforced.
5. **VirusTotal Decoupled Sidecar:** Verify `virustotal.yml` runs post-release via `workflow_run` and publishes `virustotal-<tag>.json`.
