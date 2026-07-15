"""AST helpers for no-op, fake-agent, copycat, and structural policy checks."""

from __future__ import annotations

import ast
import difflib


def agent_main_returns_direct_empty_report(agent_main: ast.FunctionDef) -> bool:
    """Catch direct scaffold/no-op reports without rejecting real analysis code."""
    for return_node in iter_direct_function_returns(agent_main):
        value = return_node.value
        if not isinstance(value, ast.Dict):
            continue
        for key, item in zip(value.keys, value.values, strict=False):
            if not (isinstance(key, ast.Constant) and key.value == "vulnerabilities"):
                continue
            if isinstance(item, ast.List) and not item.elts:
                return True
    return False


def agent_main_returns_direct_constant_report(agent_main: ast.FunctionDef) -> bool:
    """Reject literal canned reports while allowing findings built from analysis."""
    for return_node in iter_direct_function_returns(agent_main):
        value = return_node.value
        if not isinstance(value, ast.Dict):
            continue
        for key, item in zip(value.keys, value.values, strict=False):
            if not (isinstance(key, ast.Constant) and key.value == "vulnerabilities"):
                continue
            if (
                isinstance(item, ast.List)
                and item.elts
                and all(isinstance(element, ast.Dict) for element in item.elts)
            ):
                return True
    return False


def iter_direct_function_returns(function_node: ast.FunctionDef):
    stack: list[ast.AST] = list(reversed(function_node.body))
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Return):
            yield node
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def dict_contains_string_key(node: ast.Dict, key_name: str) -> bool:
    for key in node.keys:
        if isinstance(key, ast.Constant) and key.value == key_name:
            return True
    return False


def python_sources_equivalent(left: str, right: str) -> bool:
    try:
        left_tree = ast.parse(left)
        right_tree = ast.parse(right)
    except SyntaxError:
        return left == right
    return ast.dump(left_tree, include_attributes=False) == ast.dump(
        right_tree,
        include_attributes=False,
    )


def python_source_similarity(left: str, right: str) -> float:
    return difflib.SequenceMatcher(
        None,
        normalize_python_source_for_similarity(left),
        normalize_python_source_for_similarity(right),
    ).ratio()


def normalize_python_source_for_similarity(source: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return "\n".join(line.strip() for line in source.splitlines() if line.strip())
    # ``ast.dump`` is not a stable similarity representation across supported
    # Python versions: added AST fields change its length and can move an
    # otherwise identical near-copy across the screening threshold.  ``unparse``
    # gives the same canonical source for equivalent syntax while ignoring
    # comments and irrelevant formatting.
    return ast.unparse(tree)
