# Changelog

All notable changes to atarus-webscan. v0.1.0 is tagged in git but was never published as a GitHub release.

## Unreleased (refresh-2026-10)

### Fixed
- HTML and PDF reports failed on every scan ("Could not find templates/report.html") because the template was never committed: the `.gitignore` rule `*.html` was only re-included for a root `templates/` directory. Added `src/atarus_webscan/templates/report.html` and fixed `.gitignore`.
- WeasyPrint is imported only for PDF export, so the CLI starts on hosts without the Pango system libraries.
- The nuclei timeout message said 240 seconds; the timeout is 90 seconds.
- `dangerous_files` sent its reachability probe twice.

### Added
- MIT LICENSE file (README and pyproject.toml already declared MIT).
- Offline unit tests (`tests/`), GitHub Actions workflow, `constraints.txt`, SECURITY.md and this changelog.
- `install-deps.sh` installs Pango for PDF export.

### Docs
- README: framework count (17), what the 404 baseline recalibration actually does, port handling, `--rate-limit` not yet applied, Pango requirement, suite description corrected.

## 0.1.0 (2026-04-29)
- Initial release: discover, headers, methods, dangerous_files, technology (nuclei) and risk modules; smart 404 baseline; HTML, PDF and JSON output.
