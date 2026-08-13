import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SecretFinding:
    secret_type: str
    line: int
    snippet: str
    severity: str
    column: int = 0


_PATTERNS: list[tuple[re.Pattern, str, str]] = []


def _compile(patterns: list[tuple[str, str, str]]) -> None:
    for regex_str, type_name, severity in patterns:
        try:
            _PATTERNS.append((re.compile(regex_str), type_name, severity))
        except re.error:
            pass


_SECRET_PATTERNS = [
    (r'(?i)gh[psuor]_[A-Za-z0-9_]{25,}', 'GitHub Token', 'high'),
    (r'(?i)glpat-[A-Za-z0-9\-_]{20,}', 'GitLab Token', 'high'),
    (r'(?i)AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'high'),
    (r'(?i)(?<![A-Za-z0-9])(?:aws|amazon)?[_-]?secret(?:access)?[_-]?key[_-]?[\'"]?\s*[:=]\s*[\'"]?[A-Za-z0-9\/+=]{40}', 'AWS Secret Key', 'high'),
    (r'-----BEGIN\s?(?:RSA|DSA|EC|PGP|OPENSSH)\s?PRIVATE KEY-----', 'Private Key', 'high'),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'JWT Token', 'high'),
    (r'(xox[baprs]-[A-Za-z0-9]{10,})', 'Slack Token', 'high'),
    (r'https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}', 'Slack Webhook', 'high'),
    (r'(?i)npm_[A-Za-z0-9]{36}', 'npm Token', 'high'),
    (r'(?i)pypi[A-Za-z0-9\-_]{20,}', 'PyPI Token', 'high'),
    (r'(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*[\'"][^\'"]{6,}[\'"]', 'Potential Password', 'medium'),
    (r'(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\\+srv)?|redis|sqlite)://[^\s:@]+:[^\s:@]+@', 'DB Connection String', 'high'),
]

_compile(_SECRET_PATTERNS)


def scan_text(content: str, filepath: str | None = None) -> list[SecretFinding]:
    if not content:
        return []
    findings = []
    seen = set()
    for i, line in enumerate(content.splitlines(), 1):
        line_stripped = line.strip()
        for pattern, type_name, severity in _PATTERNS:
            for match in pattern.finditer(line_stripped):
                key = (i, type_name, match.group()[:60])
                if key not in seen:
                    seen.add(key)
                    findings.append(SecretFinding(
                        secret_type=type_name,
                        line=i,
                        snippet=line_stripped[:80],
                        severity=severity,
                        column=match.start(),
                    ))
    return findings


def scan_file(path: Path) -> list[SecretFinding]:
    try:
        content = path.read_text("utf-8", errors="replace")
        return scan_text(content, str(path))
    except Exception:
        return []


def format_findings(findings: list[SecretFinding]) -> str:
    """Format findings into the standard warning block appended to tool output.
    Shared by fs_read (file content) and sh_exec/sh_script (command output) so the
    format stays consistent and isn't duplicated across call sites.
    """
    if not findings:
        return ""
    warn_lines = ["\n\n--- Security Scan ---"]
    warn_lines.append(f"Found {len(findings)} potential secret(s):")
    sev_order = {"high": 0, "medium": 1}
    sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f.severity, 99), f.line))
    for f in sorted_findings:
        warn_lines.append(f"  [{f.severity.upper()}] Line {f.line}: {f.secret_type}")
        warn_lines.append(f"          {f.snippet}")
    return "\n".join(warn_lines)


def scan_and_warn(content: str, enabled: bool = True) -> str:
    """Scan content for secrets if enabled and append standard warning block if findings exist."""
    if not enabled or not content or not content.strip():
        return ""
    findings = scan_text(content)
    return format_findings(findings) if findings else ""

