# Updates

## v0.3.0 (2026-04-16) - hardening release

### Why this update exists

Adversarial testing found practical bypasses that could evade detection
in default settings:

- split-line prompt injections
- Windows/PowerShell payload variants
- extensionless high-risk files (for example `README`)
- zero-width-only obfuscation markers
- weak CI coverage for these classes

This release closes those gaps while keeping the scanner deterministic
and dependency-free.

### What changed

1. Added split-line detection windows (up to 3 lines) in `scan_file()`.
2. Added Windows/PowerShell dangerous-command patterns:
   - `powershell_pipe_iex` (`iwr|irm|Invoke-WebRequest ... | iex`)
   - `powershell_remove_item` (`Remove-Item -Recurse -Force`)
   - `cmd_rmdir_tree` (`rd/rmdir /s /q`)
3. Added Windows sensitive-path patterns:
   - `windows_ssh_private_key`
   - `windows_aws_credentials`
4. Fixed zero-width marker detection by scanning raw text for
   `zero_width_char` before normalization strips those characters.
5. Expanded default coverage to include:
   - PowerShell and Windows shell extensions (`.ps1`, `.psm1`, `.cmd`,
     `.bat`)
   - Common config formats (`.ini`, `.cfg`, `.conf`)
   - Extensionless high-risk files (`README`, `SKILL.md`, `CLAUDE.md`,
     `Dockerfile`, `Makefile`)
   - `.env*` dotfiles by filename
6. Removed `env` from skipped directory names to avoid blind spots.
7. Added a file size guard (`2 MB`) to reduce accidental DoS via very
   large text-like files.
8. Added CI regression tests that explicitly verify these bypass classes
   are detected.

### Security impact

- Improves cross-platform detection (Linux/macOS + Windows).
- Reduces false negatives for realistic attacker payload structure.
- Makes future regressions less likely by pinning bypass checks in CI.

### Limitations (still true)

- Regex-based detection is still signature-based, not semantic.
- Attackers can invent new paraphrases that require new patterns.
- This scanner should still be paired with a runtime defensive prompt.
