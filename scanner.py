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
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

__version__ = "0.2.0"


# ---------------------------------------------------------------------------
# Pre-match normalization
# ---------------------------------------------------------------------------
#
# Before running regex patterns against a line we normalize it. Attackers
# hide prompt injections inside visually-identical or invisible Unicode
# characters so they pass a naive regex and render "correctly" on GitHub.
# The three tricks we neutralize here:
#
# 1. NFKC — collapses compatibility forms (ﬁ → fi, ⅈ → i, fullwidth → ASCII)
# 2. Invisible / BiDi controls — stripped entirely (ZWSP inside "ig[zwsp]nore",
#    RLO flips, LRE embeddings)
# 3. Cyrillic / Greek homoglyph fold — "ignоre" with a Cyrillic 'о' (U+043E)
#    becomes "ignore" so the override pattern matches. Only folds a small
#    hand-picked set of confusables; does not touch real non-Latin text.


# Invisible and bidirectional control characters — stripped outright.
_STRIP_CHARS = (
    "\u200b"  # ZWSP
    "\u200c"  # ZWNJ
    "\u200d"  # ZWJ
    "\u2060"  # WJ
    "\ufeff"  # BOM / ZWNBSP
    "\u202a"  # LRE
    "\u202b"  # RLE
    "\u202c"  # PDF
    "\u202d"  # LRO
    "\u202e"  # RLO
    "\u2066"  # LRI
    "\u2067"  # RLI
    "\u2068"  # FSI
    "\u2069"  # PDI
)
_STRIP_TABLE = {ord(c): None for c in _STRIP_CHARS}

# Cyrillic / Greek → Latin homoglyph fold. Deliberately narrow: only letters
# that routinely show up in English injection payloads disguised with a
# lookalike. A full Unicode confusable table would trip over legitimate
# non-Latin prose.
_HOMOGLYPH_TABLE = str.maketrans(
    {
        # Lowercase Cyrillic
        "\u0430": "a",  # а
        "\u0435": "e",  # е
        "\u043e": "o",  # о
        "\u0440": "p",  # р
        "\u0441": "c",  # с
        "\u0443": "y",  # у
        "\u0445": "x",  # х
        "\u0456": "i",  # і
        "\u0455": "s",  # ѕ
        "\u0501": "d",  # ԁ
        # Uppercase Cyrillic
        "\u0410": "A",
        "\u0412": "B",
        "\u0415": "E",
        "\u041a": "K",
        "\u041c": "M",
        "\u041d": "H",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0422": "T",
        "\u0425": "X",
        # Uppercase Greek
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0396": "Z",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a3": "S",  # Σ
        "\u03a4": "T",
        "\u03a5": "Y",
        "\u03a7": "X",
    }
)


def normalize_for_match(line: str) -> str:
    """Return *line* folded into a form safe for regex matching.

    Applies NFKC, strips invisible / BiDi control characters, then folds a
    small set of Cyrillic and Greek homoglyphs back to ASCII. The original
    line is still used for the user-facing snippet so the report shows the
    attack as written.
    """
    normalized = unicodedata.normalize("NFKC", line)
    normalized = normalized.translate(_STRIP_TABLE)
    return normalized.translate(_HOMOGLYPH_TABLE)


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
            r"ignore\s+"
            r"(all\s+|the\s+|any\s+|my\s+|your\s+|these\s+|those\s+|earlier\s+)*"
            r"(previous|prior|above|earlier|preceding|former|system|safety|user)?"
            r"\s*(instructions?|rules?|messages?|context|prompts?|guidelines?|directives?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Classic 'ignore previous instructions' override",
        category="override",
    ),
    Pattern(
        name="overlook_instructions",
        regex=re.compile(
            r"(overlook|discard|disregard|brush\s+aside|push\s+aside|set\s+aside|"
            r"throw\s+out|drop|skip)\s+"
            r"(all\s+|the\s+|any\s+|my\s+|your\s+|these\s+|those\s+|previous\s+|"
            r"prior\s+|safety\s+|system\s+)*"
            r"(instructions?|rules?|guidelines?|directives?|prompts?|commands?)",
            re.I,
        ),
        severity="HIGH",
        description="Synonym form of 'ignore instructions' (overlook/discard/drop)",
        category="override",
    ),
    Pattern(
        name="forget_guidelines",
        regex=re.compile(
            r"forget\s+(about\s+)?"
            r"(your|all|everything|previous|the|any|these|those|my)\s+"
            r"(guidelines?|rules?|instructions?|training|safety|prompts?|context)",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction to forget safety guidelines",
        category="override",
    ),
    Pattern(
        name="disregard",
        regex=re.compile(
            r"disregard\s+(all\s+|any\s+|every\s+)?"
            r"(safety|security|previous|prior|the|your|my|these|those)\s+"
            r"(checks?|rules?|instructions?|guidelines?|prompts?|directives?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction to disregard rules",
        category="override",
    ),
    Pattern(
        name="override_safety",
        regex=re.compile(
            r"(override|bypass|skip|disable|circumvent|evade)\s+"
            r"(safety|security|all|the|any|every|your|my)\s+"
            r"(checks?|rules?|protocols?|filters?|guardrails?|restrictions?)",
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
            r"(admin|developer|debug|god|root|dan|jailbreak|jailbroken|"
            r"unrestricted|uncensored|unfiltered|sudo)[\s\-]*mode",
            re.I,
        ),
        severity="HIGH",
        description="Attempt to activate a privileged mode",
        category="role_switch",
    ),
    Pattern(
        name="you_are_now",
        regex=re.compile(
            r"you\s+are\s+(now\s+|no\s+longer\s+)?(a|an|the)?\s*"
            r"(different|new|helpful|uncensored|unrestricted|malicious|"
            r"dan|jailbroken|evil|free|rogue|unfiltered)",
            re.I,
        ),
        severity="MEDIUM",
        description="Role / persona change",
        category="role_switch",
    ),
    Pattern(
        name="from_now_on",
        regex=re.compile(
            r"(from\s+now\s+on|starting\s+now|from\s+this\s+(point|moment))"
            r",?\s+you\s+(are|will|must|should|have\s+to|need\s+to|can|may)",
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
            r"(note|message|instruction|notice|memo|alert)s?\s+"
            r"(from|by|sent\s+by)\s+"
            r"(anthropic|openai|google|meta|microsoft|mistral|"
            r"the\s+system|your\s+creators?|the\s+developers?|the\s+vendor)",
            re.I,
        ),
        severity="HIGH",
        description="Fake vendor / authority message",
        category="authority",
    ),
    Pattern(
        name="fake_verification",
        regex=re.compile(
            r"(verified|approved|audited|certified|trusted|safe|reviewed|endorsed)"
            r"\s+by\s+(the\s+)?"
            r"(anthropic|openai|google|meta|microsoft|"
            r"the\s+system|security(\s+team)?|the\s+team|our\s+team)",
            re.I,
        ),
        severity="HIGH",
        description="Fake verification claim",
        category="authority",
    ),
    Pattern(
        name="system_prefix",
        regex=re.compile(
            r"\bSYSTEM\s*[:\-\>_]+\s*"
            r"(override|message|instruction|command|prompt|alert|update|directive)",
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
            r"<!--\s*"
            r"(SYSTEM|AI|ADMIN|INSTRUCTION|PROMPT|HIDDEN|CLAUDE|GPT|LLM|"
            r"ASSISTANT|COPILOT|AGENT|BOT)"
            r"\s*[:\-\>\s]",
            re.I,
        ),
        severity="CRITICAL",
        description="Instruction hidden inside an HTML comment",
        category="hidden",
    ),
    Pattern(
        name="bracket_marker",
        regex=re.compile(
            r"[\[\{\(]\s*"
            r"(HIDDEN|SYSTEM|AI|INSTRUCTION|PROMPT|INTERNAL|SECRET|ADMIN|"
            r"OVERRIDE|BYPASS|EXECUTE|DIRECTIVE)"
            r"\s*[:\-\]\}\)]",
            re.I,
        ),
        severity="HIGH",
        description="Instruction tagged with a bracket / brace marker",
        category="hidden",
    ),
    Pattern(
        name="code_comment_inst",
        regex=re.compile(
            r"(^|\s)(#|//|/\*|\*|--|;)\s*"
            r"(SYSTEM|AI|ADMIN|CLAUDE|GPT|LLM|COPILOT|ASSISTANT|AGENT)"
            r"\s*[:\-]",
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
            r"(tell|say\s+to|reassure|inform|convince)\s+(the\s+)?users?\s+"
            r"(that\s+)?(everything|all|it|things?)"
            r"(\s+is|'s|\s+are|\s+looks?|\s+seems?|\s+appears?)\s+"
            r"(ok|okay|fine|safe|good|working|secure|alright|normal)",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to suppress warnings from user",
        category="suppression",
    ),
    Pattern(
        name="do_not_mention",
        regex=re.compile(
            r"(do\s+not|don't|never|don\u2019t)\s+"
            r"(mention|tell|show|warn|notify|inform|reveal|disclose|"
            r"acknowledge|say\s+(anything\s+)?to)\s+"
            r"(this\s+to\s+|it\s+to\s+|anything\s+to\s+|to\s+)?"
            r"(the\s+|any\s+)?users?",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to hide information from the user",
        category="suppression",
    ),
    Pattern(
        name="without_asking",
        regex=re.compile(
            r"without\s+"
            r"(asking|confirming|notifying|warning|alerting|prompting|"
            r"(the\s+|any\s+)?(user|users)"
            r"('s)?\s*(consent|confirmation|permission|approval|knowledge)?|"
            r"(prior\s+|explicit\s+|any\s+)?(consent|permission|approval))",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to bypass user confirmation",
        category="suppression",
    ),
    Pattern(
        name="silently_execute",
        regex=re.compile(
            r"(silently|quietly|secretly|discreetly|stealthily|invisibly|"
            r"without\s+(a\s+)?(trace|notice)|in\s+the\s+background)\s+"
            r"(execute|run|perform|read|send|upload|transmit|exfiltrate|"
            r"delete|remove|modify|write|overwrite|install|deploy|"
            r"copy|download|fetch|post|submit|leak|dump|capture|"
            r"append|patch|replace)",
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
            r"(follow|apply|execute|implement|obey|adhere\s+to|carry\s+out)\s+"
            r"(every|all|the|each|any)\s+instructions?\s+"
            r"(in|from|inside|within|contained\s+in|listed\s+in)",
            re.I,
        ),
        severity="HIGH",
        description="Instruction to execute commands from another file",
        category="multi_stage",
    ),
    Pattern(
        name="read_and_execute",
        regex=re.compile(
            r"(read|load|open|fetch|download)\s+"
            r"(the\s+|my\s+|your\s+|this\s+)?(file|contents?|script|document)\s*"
            r"(?:[^\n]{0,80}?)\band\s+"
            r"(follow|execute|run|apply|perform|obey)",
            re.I,
        ),
        severity="HIGH",
        description="Read-and-execute chain across files",
        category="multi_stage",
    ),
    Pattern(
        name="treat_as_instructions",
        regex=re.compile(
            r"treat\s+(it|this|that|the\s+[\w\s]+?|\w+)\s+as\s+"
            r"(your|my|the|a|an)?\s*"
            r"(instructions?|commands?|system\s+prompt|directives?|rules?|orders?)",
            re.I,
        ),
        severity="CRITICAL",
        description="Explicit instruction to treat data as commands",
        category="multi_stage",
    ),
    # --- Dangerous commands ------------------------------------------------
    Pattern(
        name="rm_rf",
        regex=re.compile(
            r"\brm\s+-[rRf]{1,2}\s+"
            r"(/|~|\./|\$[A-Z_][A-Z0-9_]*|\*|[\w.][\w./-]*\*?)"
        ),
        severity="CRITICAL",
        description="Destructive recursive deletion",
        category="dangerous_cmd",
    ),
    Pattern(
        name="curl_pipe_shell",
        regex=re.compile(
            r"(curl|wget|fetch)\s+"
            r"(-[a-zA-Z]+\s+)*"
            r"(\"[^\"]+\"|'[^']+'|\S+)"
            r"\s*\|\s*"
            r"(sh|bash|zsh|fish|ksh|dash|python|python3|node|ruby|perl|php|lua)\b",
            re.I,
        ),
        severity="CRITICAL",
        description="Remote code execution via curl | sh",
        category="dangerous_cmd",
    ),
    Pattern(
        name="chmod_777",
        regex=re.compile(
            r"chmod\s+(-R\s+)?"
            r"(0?777|a\+rwx|ugo\+rwx|u\+rwx,g\+rwx,o\+rwx)"
        ),
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
    """Scan a single file and yield every matching pattern.

    Each line is passed through :func:`normalize_for_match` before the
    patterns run, which folds Unicode homoglyphs, strips zero-width / BiDi
    control characters, and applies NFKC. The original line is still used
    for the user-facing snippet so the report shows the attack as written.
    """

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    for line_num, line in enumerate(content.splitlines(), start=1):
        normalized = normalize_for_match(line)
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(normalized):
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
    parser.add_argument(
        "path",
        type=Path,
        nargs="+",
        help="File(s) or directory(ies) to scan",
    )
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

    for path in args.path:
        if not path.exists():
            print(f"error: path does not exist: {path}", file=sys.stderr)
            return 2

    extensions = {
        e.strip() if e.strip().startswith(".") else f".{e.strip()}"
        for e in args.ext.split(",")
        if e.strip()
    }
    min_rank = SEVERITY_RANK[args.min_severity]

    findings: list[Finding] = []
    files_scanned = 0

    for root in args.path:
        for file_path in iter_files(root, extensions):
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
