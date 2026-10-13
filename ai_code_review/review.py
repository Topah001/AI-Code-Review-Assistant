"""Deterministic, non-executing Python source checks."""

from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True, order=True)
class Finding:
    line: int
    rule: str
    severity: str
    message: str


_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*"""
    r"""(?P<quote>['"])(?P<value>[^'"]{8,})(?P=quote)"""
)
_PLACEHOLDER = re.compile(r"(?i)^(?:change.?me|example|placeholder|your[_-].*|xxx+|test)$")


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(self, node: ast.AST, rule: str, severity: str, message: str) -> None:
        self.findings.append(Finding(getattr(node, "lineno", 1), rule, severity, message))

    def visit_Call(self, node: ast.Call) -> None:
        name = node.func.id if isinstance(node.func, ast.Name) else ""
        attribute = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name in {"eval", "exec"}:
            self.add(node, "PY001", "high", f"Use of {name} executes dynamically constructed code.")
        if name in {"compile", "__import__"}:
            self.add(node, "PY002", "medium", f"Dynamic {name} can make static behavior harder to inspect.")
        if attribute in {"eval", "exec"}:
            self.add(node, "PY001", "high", f"Use of {attribute} executes dynamically constructed code.")
        if attribute in {"compile", "__import__"}:
            self.add(node, "PY002", "medium", f"Dynamic {attribute} can make static behavior harder to inspect.")
        if name in {"Popen", "run", "call", "check_call", "check_output"} \
                or (isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and attribute in {"Popen", "run", "call", "check_call", "check_output"}):
            if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                   and keyword.value.value is True for keyword in node.keywords):
                self.add(node, "PY003", "high", "subprocess with shell=True can interpret untrusted input.")
        if attribute == "load" and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
            self.add(node, "PY004", "medium", "yaml.load may construct unsafe objects; prefer safe_load for untrusted data.")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.add(node, "PY005", "medium", "Bare except catches nearly every exception and can hide failures.")
        elif isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}:
            self.add(node, "PY006", "low", "Broad exception handling may conceal unrelated errors.")
        self.generic_visit(node)

    def _visit_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = node.args.defaults + [d for d in node.args.kw_defaults if d is not None]
        for default in defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.add(default, "PY007", "medium", "Mutable default value is shared between function calls.")
        self.generic_visit(node)

    visit_FunctionDef = _visit_defaults
    visit_AsyncFunctionDef = _visit_defaults


def review_source(source: str, filename: str = "<source>") -> list[Finding]:
    """Inspect Python source text without importing or executing it."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as error:
        return [Finding(error.lineno or 1, "PY000", "error",
                        f"Python syntax error: {error.msg}")]

    visitor = _Visitor()
    visitor.visit(tree)

    for line_number, line in enumerate(source.splitlines(), 1):
        for match in _SECRET_ASSIGNMENT.finditer(line):
            value = match.group("value")
            if not _PLACEHOLDER.fullmatch(value):
                visitor.findings.append(Finding(
                    line_number, "TXT001", "medium",
                    "Assignment resembles an embedded credential; verify it is not a real secret.",
                ))
        if "TODO" in line or "FIXME" in line:
            visitor.findings.append(Finding(
                line_number, "TXT002", "info", "TODO/FIXME marker may indicate unfinished work."
            ))
    return sorted(set(visitor.findings))


def findings_as_dicts(findings: list[Finding]) -> list[dict[str, object]]:
    return [asdict(finding) for finding in findings]
