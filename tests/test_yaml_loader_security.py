from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOTS = (ROOT / "cml", ROOT / "cli", ROOT / "api")
LOADER_REQUIRED_METHODS = frozenset({"load", "load_all"})
FORBIDDEN_METHODS = frozenset(
    {"unsafe_load", "unsafe_load_all", "full_load", "full_load_all"}
)
TRACKED_METHODS = LOADER_REQUIRED_METHODS | FORBIDDEN_METHODS


def _base_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return None


def _yaml_import_bindings(
    tree: ast.AST,
) -> tuple[set[str], dict[str, str], set[str]]:
    module_aliases = {"yaml"}
    method_aliases: dict[str, str] = {}
    safe_loader_refs = {"SafeLoader", "yaml.SafeLoader"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "yaml":
                    module_aliases.add(alias.asname or "yaml")
        elif isinstance(node, ast.ImportFrom) and node.module == "yaml":
            for alias in node.names:
                bound_name = alias.asname or alias.name
                if alias.name in TRACKED_METHODS:
                    method_aliases[bound_name] = alias.name
                elif alias.name == "SafeLoader":
                    safe_loader_refs.add(bound_name)
    safe_loader_refs.update(
        f"{module_alias}.SafeLoader" for module_alias in module_aliases
    )
    return module_aliases, method_aliases, safe_loader_refs


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
    tree: ast.AST,
    module_aliases: set[str],
    method_aliases: dict[str, str],
):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id in module_aliases
            and function.attr in TRACKED_METHODS
        ):
            yield node, function.attr
        elif isinstance(function, ast.Name) and function.id in method_aliases:
            yield node, method_aliases[function.id]


def _yaml_policy_violations(source: str, *, filename: str) -> list[str]:
    tree = ast.parse(source, filename=filename)
    module_aliases, method_aliases, safe_loader_refs = _yaml_import_bindings(tree)
    safe_loaders = _safe_loader_classes(tree, safe_loader_refs)
    violations: list[str] = []
    for call, method_name in _yaml_load_calls(tree, module_aliases, method_aliases):
        if method_name in FORBIDDEN_METHODS:
            violations.append(
                f"{filename}:{call.lineno}: yaml.{method_name} is strictly forbidden"
            )
            continue

        loader_keywords = [
            keyword.value for keyword in call.keywords if keyword.arg == "Loader"
        ]
        if len(loader_keywords) != 1:
            violations.append(
                f"{filename}:{call.lineno}: yaml.{method_name} must specify "
                "exactly one Loader"
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
    unsafe_load_all = "import yaml as y\ny.load_all('x', Loader=y.Loader)\n"
    imported_load_all = (
        "from yaml import load_all as yload_all, Loader\n"
        "yload_all('x', Loader=Loader)\n"
    )
    assert _yaml_policy_violations(unsafe_alias, filename="unsafe_alias.py")
    assert _yaml_policy_violations(unsafe_import, filename="unsafe_import.py")
    assert _yaml_policy_violations(unsafe_load_all, filename="unsafe_load_all.py")
    assert _yaml_policy_violations(imported_load_all, filename="imported_load_all.py")


def test_yaml_policy_strictly_forbids_unsafe_and_full_load_methods():
    module_calls = """
import yaml as y
y.unsafe_load('x')
y.unsafe_load_all('x')
y.full_load('x')
y.full_load_all('x')
"""
    imported_calls = """
from yaml import unsafe_load as ul, unsafe_load_all as ula
from yaml import full_load as fl, full_load_all as fla
ul('x')
ula('x')
fl('x')
fla('x')
"""
    module_violations = _yaml_policy_violations(
        module_calls, filename="module_forbidden.py"
    )
    imported_violations = _yaml_policy_violations(
        imported_calls, filename="imported_forbidden.py"
    )
    assert len(module_violations) == 4
    assert len(imported_violations) == 4
    assert all("strictly forbidden" in item for item in module_violations)
    assert all("strictly forbidden" in item for item in imported_violations)


def test_yaml_policy_accepts_safe_loader_aliases_and_subclasses():
    safe_alias = """
import yaml as y
class UniqueLoader(y.SafeLoader):
    pass
y.load('x', Loader=UniqueLoader)
y.load_all('x', Loader=UniqueLoader)
y.safe_load('x')
y.safe_load_all('x')
"""
    safe_import = """
from yaml import load as yload, load_all as yload_all, SafeLoader as SL
class UniqueLoader(SL):
    pass
yload('x', Loader=UniqueLoader)
yload_all('x', Loader=UniqueLoader)
"""
    assert not _yaml_policy_violations(safe_alias, filename="safe_alias.py")
    assert not _yaml_policy_violations(safe_import, filename="safe_import.py")


def test_bandit_b506_exception_is_bound_to_semantic_regression():
    config = (ROOT / ".bandit").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
    assert "skips = B506" in config
    assert "test_yaml_loader_security.py" in config
    assert "python -m bandit \\\n            --ini .bandit \\" in workflow
