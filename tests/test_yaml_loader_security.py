from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOTS = (ROOT / "cml", ROOT / "cli", ROOT / "api")


def _base_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return None


def _safe_loader_classes(tree: ast.AST) -> set[str]:
    safe = {"SafeLoader", "yaml.SafeLoader"}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {_base_name(base) for base in node.bases}
            if bases & safe and node.name not in safe:
                safe.add(node.name)
                changed = True
    return safe


def _yaml_load_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id == "yaml"
            and function.attr == "load"
        ):
            yield node


def test_every_yaml_load_uses_a_safe_loader_subclass():
    violations: list[str] = []
    for production_root in PRODUCTION_ROOTS:
        for path in sorted(production_root.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            safe_loaders = _safe_loader_classes(tree)
            for call in _yaml_load_calls(tree):
                loader_keywords = [
                    keyword.value
                    for keyword in call.keywords
                    if keyword.arg == "Loader"
                ]
                if len(loader_keywords) != 1:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{call.lineno}: "
                        "yaml.load must specify exactly one Loader"
                    )
                    continue
                loader_name = _base_name(loader_keywords[0])
                if loader_name not in safe_loaders:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{call.lineno}: "
                        f"unsafe YAML loader {loader_name!r}"
                    )
    assert not violations, "\n".join(violations)


def test_bandit_b506_exception_is_bound_to_semantic_regression():
    config = (ROOT / ".bandit").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
    assert "skips = B506" in config
    assert "test_yaml_loader_security.py" in config
    assert "python -m bandit \\\n            --ini .bandit \\" in workflow
