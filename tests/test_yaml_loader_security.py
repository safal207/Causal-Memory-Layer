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


def _yaml_import_bindings(tree: ast.AST) -> tuple[set[str], set[str], set[str]]:
    module_aliases = {"yaml"}
    load_aliases: set[str] = set()
    safe_loader_refs = {"SafeLoader", "yaml.SafeLoader"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "yaml":
                    module_aliases.add(alias.asname or "yaml")
        elif isinstance(node, ast.ImportFrom) and node.module == "yaml":
            for alias in node.names:
                bound_name = alias.asname or alias.name
                if alias.name == "load":
                    load_aliases.add(bound_name)
                elif alias.name == "SafeLoader":
                    safe_loader_refs.add(bound_name)
    safe_loader_refs.update(
        f"{module_alias}.SafeLoader" for module_alias in module_aliases
    )
    return module_aliases, load_aliases, safe_loader_refs


def _safe_loader_classes(tree: ast.AST, safe_loader_refs: set[str]) -> set[str]:
    safe = set(safe_loader_refs)
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


def _yaml_load_calls(
    tree: ast.AST, module_aliases: set[str], load_aliases: set[str]
):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        is_module_call = (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id in module_aliases
            and function.attr == "load"
        )
        is_imported_call = isinstance(function, ast.Name) and function.id in load_aliases
        if is_module_call or is_imported_call:
            yield node


def _yaml_policy_violations(source: str, *, filename: str) -> list[str]:
    tree = ast.parse(source, filename=filename)
    module_aliases, load_aliases, safe_loader_refs = _yaml_import_bindings(tree)
    safe_loaders = _safe_loader_classes(tree, safe_loader_refs)
    violations: list[str] = []
    for call in _yaml_load_calls(tree, module_aliases, load_aliases):
        loader_keywords = [
            keyword.value for keyword in call.keywords if keyword.arg == "Loader"
        ]
        if len(loader_keywords) != 1:
            violations.append(
                f"{filename}:{call.lineno}: yaml.load must specify exactly one Loader"
            )
            continue
        loader_name = _base_name(loader_keywords[0])
        if loader_name not in safe_loaders:
            violations.append(
                f"{filename}:{call.lineno}: unsafe YAML loader {loader_name!r}"
            )
    return violations


def test_every_yaml_load_uses_a_safe_loader_subclass():
    violations: list[str] = []
    for production_root in PRODUCTION_ROOTS:
        for path in sorted(production_root.rglob("*.py")):
            violations.extend(
                _yaml_policy_violations(
                    path.read_text(encoding="utf-8"),
                    filename=path.relative_to(ROOT).as_posix(),
                )
            )
    assert not violations, "\n".join(violations)


def test_yaml_policy_resolves_module_aliases_and_imported_load_functions():
    unsafe_alias = "import yaml as y\ny.load('x', Loader=y.Loader)\n"
    unsafe_import = "from yaml import load as yload, Loader\nyload('x', Loader=Loader)\n"
    assert _yaml_policy_violations(unsafe_alias, filename="unsafe_alias.py")
    assert _yaml_policy_violations(unsafe_import, filename="unsafe_import.py")


def test_yaml_policy_accepts_safe_loader_aliases_and_subclasses():
    safe_alias = """
import yaml as y
class UniqueLoader(y.SafeLoader):
    pass
y.load('x', Loader=UniqueLoader)
"""
    safe_import = """
from yaml import load as yload, SafeLoader as SL
class UniqueLoader(SL):
    pass
yload('x', Loader=UniqueLoader)
"""
    assert not _yaml_policy_violations(safe_alias, filename="safe_alias.py")
    assert not _yaml_policy_violations(safe_import, filename="safe_import.py")


def test_bandit_b506_exception_is_bound_to_semantic_regression():
    config = (ROOT / ".bandit").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
    assert "skips = B506" in config
    assert "test_yaml_loader_security.py" in config
    assert "python -m bandit \\\n            --ini .bandit \\" in workflow
