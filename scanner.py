#!/usr/bin/env python3
"""
prompt-injection-scanner

Scans files for prompt injection patterns targeting AI coding assistants
(Claude Code, Cursor, GitHub Copilot, Aider, Continue, ...).

These assistants read README files, SKILL files, and source code as part
of their context window. Attackers can hide instructions inside those
files that the AI will execute as if the user typed them.

Usage:
    python scanner.py path/to/file.md
    python scanner.py path/to/repo/
    python scanner.py . --min-severity HIGH
    python scanner.py . --json > report.json

Exit codes:
    0 — no findings
    1 — findings present
    2 — bad arguments
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------

RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GREEN = "\033[92m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": BLUE,
}

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Pattern:
    """A single detection rule."""

    name: str
    regex: re.Pattern[str]
    severity: str
    description: str
    category: str


@dataclass(frozen=True)
class Finding:
    """One match of a pattern inside a file."""

    file: Path
    line: int
    column: int
    pattern: Pattern
    snippet: str


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------
#
# Each pattern is a regex + severity + category. Categories group related
# attacks so the report is easier to read. Severity drives the exit code
# filter (--min-severity) and the color in the terminal output.

PATTERNS: list[Pattern] = [
    # --- Direct instruction override ---------------------------------------
    Pattern(
        name="ignore_previous",
        regex=re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+"
            r"(instructions?|rules?|messages?|context|prompts?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Classic 'ignore previous instructions' override",
        category="override",
    ),
    Pattern(
        name="forget_guidelines",
        regex=re.compile(
            r"forget\s+(your|all|everything|previous)\s+"
            r"(guidelines?|rules?|instructions?|training|safety)",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction to forget safety guidelines",
        category="override",
    ),
    Pattern(
        name="disregard",
        regex=re.compile(
            r"disregard\s+(all\s+)?(safety|security|previous|the|your)\s+"
            r"(checks?|rules?|instructions?|guidelines?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction to disregard rules",
        category="override",
    ),
    Pattern(
        name="override_safety",
        regex=re.compile(
            r"(override|bypass|skip|disable)\s+(safety|security|all|the|any)\s+"
            r"(checks?|rules?|protocols?|filters?|guardrails?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Attempt to override safety checks",
        category="override",
    ),
    # --- Role / mode switching ---------------------------------------------
    Pattern(
        name="privileged_mode",
        regex=re.compile(
            r"(enable|activate|enter|switch\s+to|you\s+are\s+(now\s+)?in)\s+"
            r"(admin|developer|debug|god|root|system|dan|jailbreak|unrestricted)\s+mode",
            re.I,
        ),
        severity="HIGH",
        description="Attempt to activate a privileged mode",
        category="role_switch",
    ),
    Pattern(
        name="you_are_now",
        regex=re.compile(
            r"you\s+are\s+now\s+(a|an|the)\s+"
            r"(different|new|helpful|uncensored|unrestricted|malicious)",
            re.I,
        ),
        severity="MEDIUM",
        description="Role / persona change",
        category="role_switch",
    ),
    Pattern(
        name="from_now_on",
        regex=re.compile(
            r"from\s+now\s+on,?\s+you\s+(are|will|must|should|have\s+to)",
            re.I,
        ),
        severity="HIGH",
        description="Persistent behavior change instruction",
        category="role_switch",
    ),
    # --- Authority impersonation -------------------------------------------
    Pattern(
        name="fake_vendor_note",
        regex=re.compile(
            r"(note|message|instruction|notice)s?\s+from\s+"
            r"(anthropic|openai|google|meta|the\s+system|your\s+creators?|the\s+developers?)",
            re.I,
        ),
        severity="HIGH",
        description="Fake vendor / authority message",
        category="authority",
    ),
    Pattern(
        name="fake_verification",
        regex=re.compile(
            r"(verified|approved|audited|certified|trusted|safe)\s+by\s+"
            r"(anthropic|openai|google|the\s+system|security|the\s+team)",
            re.I,
        ),
        severity="HIGH",
        description="Fake verification claim",
        category="authority",
    ),
    Pattern(
        name="system_prefix",
        regex=re.compile(
            r"\bSYSTEM\s*[:\-]\s*(override|message|instruction|command|prompt|alert|update)",
            re.I,
        ),
        severity="CRITICAL",
        description="Fake system message",
        category="authority",
    ),
    # --- Hidden instruction markers ----------------------------------------
    Pattern(
        name="html_comment_inst",
        regex=re.compile(
            r"<!--\s*(SYSTEM|AI|ADMIN|INSTRUCTION|PROMPT|HIDDEN|CLAUDE|GPT|LLM|ASSISTANT)[\s:\-]",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction hidden inside an HTML comment",
        category="hidden",
    ),
    Pattern(
        name="bracket_marker",
        regex=re.compile(
            r"\[(HIDDEN|SYSTEM|AI|INSTRUCTION|PROMPT|INTERNAL|SECRET|ADMIN)[\s:\-]",
            re.I,
        ),
        severity="HIGH",
        description="Instruction tagged with a bracket marker",
        category="hidden",
    ),
    Pattern(
        name="code_comment_inst",
        regex=re.compile(
            r"(^|\s)(#|//|/\*|\*)\s*(SYSTEM|AI|ADMIN|CLAUDE|GPT|LLM)\s*[:\-]\s*\S",
            re.I,
        ),
        severity="HIGH",
        description="AI instruction hidden in a code comment",
        category="hidden",
    ),
    # --- Suppression / silencing -------------------------------------------
    Pattern(
        name="tell_user_ok",
        regex=re.compile(
            r"(tell|say\s+to|reassure)\s+(the\s+)?user\s+"
            r"(that\s+)?(everything|all|it)\s+(is|looks|seems)\s+"
            r"(ok|okay|fine|safe|good|working|secure)",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to suppress warnings from user",
        category="suppression",
    ),
    Pattern(
        name="do_not_mention",
        regex=re.compile(
            r"(do\s+not|don't|never)\s+(mention|tell|show|warn|notify|inform|reveal)\s+"
            r"(the\s+)?user",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to hide information from the user",
        category="suppression",
    ),
    Pattern(
        name="without_asking",
        regex=re.compile(
            r"without\s+(asking|confirming|permission|the\s+user('s)?\s+consent)",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to bypass user confirmation",
        category="suppression",
    ),
    Pattern(
        name="silently_execute",
        regex=re.compile(
            r"(silently|quietly|secretly)\s+(execute|run|perform|read|send|upload)",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction to perform an action silently",
        category="suppression",
    ),
    # --- Multi-stage / indirect instruction loading ------------------------
    Pattern(
        name="follow_instructions_in_file",
        regex=re.compile(
            r"follow\s+(every|all|the|each)\s+instructions?\s+(in|from|inside|within)",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to execute commands from another file",
        category="multi_stage",
    ),
    Pattern(
        name="read_and_execute",
        regex=re.compile(
            r"(read|load|open)\s+(the\s+)?(file|contents?)\s+[^\s.]+\s+and\s+"
            r"(follow|execute|run|apply|perform)",
            re.I,
        ),
        severity="HIGH",
        description="Read-and-execute chain across files",
        category="multi_stage",
    ),
    Pattern(
        name="treat_as_instructions",
        regex=re.compile(
            r"treat\s+(it|this|the\s+\w+|\w+)\s+as\s+(your\s+)?(instructions?|commands?|system\s+prompt)",
            re.I,
        ),
        severity="CRITICAL",
        description="Explicit instruction to treat data as commands",
        category="multi_stage",
    ),
    # --- Dangerous commands ------------------------------------------------
    Pattern(
        name="rm_rf",
        regex=re.compile(r"rm\s+-rf?\s+[/~]"),
        severity="CRITICAL",
        description="Destructive recursive deletion",
        category="dangerous_cmd",
    ),
    Pattern(
        name="curl_pipe_shell",
        regex=re.compile(
            r"(curl|wget|fetch)\s+[^\s|]+\s*\|\s*(sh|bash|zsh|fish|python|node|ruby|perl)",
            re.I,
        ),
        severity="CRITICAL",
        description="Remote code execution via curl | sh",
        category="dangerous_cmd",
    ),
    Pattern(
        name="chmod_777",
        regex=re.compile(r"chmod\s+(-R\s+)?777"),
        severity="HIGH",
        description="Overly permissive file mode",
        category="dangerous_cmd",
    ),
    # --- Sensitive paths ---------------------------------------------------
    Pattern(
        name="ssh_private_key",
        regex=re.compile(
            r"~?/?\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)"
        ),
        severity="CRITICAL",
        description="Reference to SSH private key",
        category="sensitive_path",
    ),
    Pattern(
        name="aws_credentials",
        regex=re.compile(r"~?/?\.aws/(credentials|config)"),
        severity="CRITICAL",
        description="Reference to AWS credentials",
        category="sensitive_path",
    ),
    Pattern(
        name="env_file",
        regex=re.compile(r"(^|\s|[\"'`/])\.env(\.local|\.prod|\.production)?\b"),
        severity="HIGH",
        description="Reference to .env file",
        category="sensitive_path",
    ),
    Pattern(
        name="token_credentials_file",
        regex=re.compile(
            r"\b(token|credentials?|secrets?|api[_-]?key|password)s?"
            r"\.(json|ya?ml|txt|env|toml)\b",
            re.I,
        ),
        severity="HIGH",
        description="Reference to credentials file",
        category="sensitive_path",
    ),
    # --- Obfuscation -------------------------------------------------------
    Pattern(
        name="zero_width_char",
        regex=re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]"),
        severity="HIGH",
        description="Zero-width character (hidden text)",
        category="obfuscation",
    ),
    Pattern(
        name="long_base64_block",
        regex=re.compile(
            r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])"
        ),
        severity="LOW",
        description="Long base64 block (possible encoded payload)",
        category="obfuscation",
    ),
]


# ---------------------------------------------------------------------------
# Scanning logic
# ---------------------------------------------------------------------------


DEFAULT_EXTENSIONS = {
    ".md",
    ".markdown",
    ".txt",
    ".rst",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".html",
    ".xml",
    ".sh",
    ".bash",
}

SKIP_DIR_NAMES = {
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".venv",
    "venv",
    "env",
    ".git",
    ".idea",
    ".vscode",
}


def iter_files(root: Path, extensions: set[str]) -> Iterator[Path]:
    """Yield every file under ``root`` whose suffix is in ``extensions``."""

    if root.is_file():
        yield root
        return

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() in extensions:
            yield path


def scan_file(path: Path) -> Iterator[Finding]:
    """Scan a single file and yield every matching pattern."""

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(line):
                yield Finding(
                    file=path,
                    line=line_num,
                    column=match.start() + 1,
                    pattern=pattern,
                    snippet=line.strip()[:140],
                )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_finding(finding: Finding, *, color: bool) -> str:
    """Render one finding as a multi-line string for terminal output."""

    sev_color = SEVERITY_COLOR.get(finding.pattern.severity, "") if color else ""
    bold = BOLD if color else ""
    dim = DIM if color else ""
    reset = RESET if color else ""

    return (
        f"{sev_color}{bold}[{finding.pattern.severity}]{reset} "
        f"{bold}{finding.file}{reset}:{finding.line}:{finding.column}\n"
        f"  {sev_color}{finding.pattern.name}{reset} "
        f"{dim}({finding.pattern.category}){reset} - {finding.pattern.description}\n"
        f"  {dim}>{reset} {finding.snippet}"
    )


def build_summary(findings: list[Finding], files_scanned: int) -> str:
    """Build a one-line summary string."""

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.pattern.severity] = counts.get(finding.pattern.severity, 0) + 1

    if not findings:
        return f"Scanned {files_scanned} file(s). No issues found."

    parts = [
        f"{sev}: {counts[sev]}"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if sev in counts
    ]
    return (
        f"Scanned {files_scanned} file(s), found {len(findings)} issue(s). "
        + ", ".join(parts)
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the CLI."""

    parser = argparse.ArgumentParser(
        prog="prompt-injection-scanner",
        description=(
            "Scan files for prompt injection patterns targeting AI coding assistants."
        ),
    )
    parser.add_argument("path", type=Path, help="File or directory to scan")
    parser.add_argument(
        "--ext",
        default=",".join(sorted(DEFAULT_EXTENSIONS)),
        help="File extensions to scan (comma-separated, default: common text/code)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Only report findings at or above this severity (default: LOW)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON instead of human-readable text",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in text output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""

    # Windows consoles sometimes default to a non-UTF-8 code page which
    # chokes on snippets containing non-ASCII characters. Force UTF-8 so
    # the scanner can print anything it finds without crashing. The
    # getattr dance keeps the call out of the static type checker's
    # hair — reconfigure exists on TextIOWrapper at runtime but not on
    # the generic IO[str] stub.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.path.exists():
        print(f"error: path does not exist: {args.path}", file=sys.stderr)
        return 2

    extensions = {
        e.strip() if e.strip().startswith(".") else f".{e.strip()}"
        for e in args.ext.split(",")
        if e.strip()
    }
    min_rank = SEVERITY_RANK[args.min_severity]

    findings: list[Finding] = []
    files_scanned = 0

    for file_path in iter_files(args.path, extensions):
        files_scanned += 1
        for finding in scan_file(file_path):
            if SEVERITY_RANK[finding.pattern.severity] >= min_rank:
                findings.append(finding)

    if args.json:
        payload = [
            {
                "file": str(f.file),
                "line": f.line,
                "column": f.column,
                "severity": f.pattern.severity,
                "category": f.pattern.category,
                "pattern": f.pattern.name,
                "description": f.pattern.description,
                "snippet": f.snippet,
            }
            for f in findings
        ]
        print(json.dumps(payload, indent=2))
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        for finding in findings:
            print(format_finding(finding, color=use_color))
            print()
        print(build_summary(findings, files_scanned))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
