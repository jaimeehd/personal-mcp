import ast
from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass
class RiskFinding:
    category: str  # "NETWORK", "DESTRUCTIVE_IO", "SUBPROCESS", "SYNTAX"
    description: str
    line: int


class ScriptAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.findings: List[RiskFinding] = []
        self._network_modules: Set[str] = {
            "requests", "urllib", "http", "httpx", "socket", "aiohttp", "ftplib", "smtplib"
        }
        self._destructive_funcs: Set[str] = {
            "remove", "unlink", "rmdir", "rmtree"
        }
        self._subprocess_funcs: Set[str] = {
            "system", "popen", "spawn", "exec", "eval"
        }

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod_root = alias.name.split(".")[0].lower()
            if mod_root in self._network_modules:
                self.findings.append(RiskFinding(
                    category="NETWORK",
                    description=f"Script imports network module '{alias.name}'",
                    line=node.lineno
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            mod_root = node.module.split(".")[0].lower()
            if mod_root in self._network_modules:
                self.findings.append(RiskFinding(
                    category="NETWORK",
                    description=f"Script imports from network module '{node.module}'",
                    line=node.lineno
                ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr.lower()
            if func_name in self._destructive_funcs:
                self.findings.append(RiskFinding(
                    category="DESTRUCTIVE_IO",
                    description=f"Script calls potentially destructive function '{func_name}'",
                    line=node.lineno
                ))
            elif func_name in self._subprocess_funcs:
                self.findings.append(RiskFinding(
                    category="SUBPROCESS",
                    description=f"Script invokes subshell/execution function '{func_name}'",
                    line=node.lineno
                ))
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id.lower()
            if func_name in ("eval", "exec"):
                self.findings.append(RiskFinding(
                    category="SUBPROCESS",
                    description=f"Script invokes dynamic execution '{func_name}'",
                    line=node.lineno
                ))
        self.generic_visit(node)


def analyze_python_script(code: str) -> List[RiskFinding]:
    """Parse Python code using AST and return risk findings (network, destructive IO, subprocess)."""
    if not code or not code.strip():
        return []
    try:
        tree = ast.parse(code)
        analyzer = ScriptAnalyzer()
        analyzer.visit(tree)
        return analyzer.findings
    except Exception:
        return [RiskFinding(
            category="SYNTAX",
            description="Script contains invalid Python syntax and cannot be statically analyzed",
            line=1
        )]


def analyze_javascript_script(code: str) -> List[RiskFinding]:
    """Scan JavaScript/Node.js code for network, subprocess, and destructive file operations."""
    if not code or not code.strip():
        return []
    findings: List[RiskFinding] = []
    lines = code.splitlines()

    import re
    net_pattern = re.compile(r'(?i)(require\s*\(\s*[\'"](?:http|https|net|axios|node-fetch|express|socket\.io)[\'"]\s*\)|import\s+.*from\s+[\'"](?:http|https|net|axios|node-fetch|express|socket\.io)[\'"]|fetch\s*\()')
    subproc_pattern = re.compile(r'(?i)(require\s*\(\s*[\'"]child_process[\'"]\s*\)|exec\s*\(|spawn\s*\(|execSync\s*\()')
    io_pattern = re.compile(r'(?i)(fs\.unlink|fs\.rmdir|fs\.rm|fs\.promises\.unlink|fs\.promises\.rm)')

    for i, line in enumerate(lines, 1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//"):
            continue
        if net_pattern.search(line_clean):
            findings.append(RiskFinding(category="NETWORK", description=f"JS/TS script includes network operation/import", line=i))
        if subproc_pattern.search(line_clean):
            findings.append(RiskFinding(category="SUBPROCESS", description=f"JS/TS script invokes child process/shell", line=i))
        if io_pattern.search(line_clean):
            findings.append(RiskFinding(category="DESTRUCTIVE_IO", description=f"JS/TS script includes destructive file system operation", line=i))

    return findings

