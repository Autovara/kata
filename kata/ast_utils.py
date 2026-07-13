from __future__ import annotations

import ast


def find_module_function_def(
    module_tree: ast.AST,
    function_name: str,
) -> ast.FunctionDef | None:
    if not isinstance(module_tree, ast.Module):
        return None
    for node in module_tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return node
    return None


def find_module_async_function_def(
    module_tree: ast.AST,
    function_name: str,
) -> ast.AsyncFunctionDef | None:
    if not isinstance(module_tree, ast.Module):
        return None
    for node in module_tree.body:
        if isinstance(node, ast.AsyncFunctionDef) and node.name == function_name:
            return node
    return None


def count_module_function_defs(module_tree: ast.AST, function_name: str) -> int:
    """Count top-level ``def``/``async def`` bindings of ``function_name``.

    Python keeps only the *last* such binding in the module namespace, so more
    than one definition means the function the runtime executes is not the one
    ``find_module_function_def`` (which returns the first) hands to the static
    checks. Callers use this to reject that ambiguity instead of validating a
    definition the sandbox never runs.
    """
    if not isinstance(module_tree, ast.Module):
        return 0
    return sum(
        1
        for node in module_tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name == function_name
    )


def function_supports_no_arg_invocation(function_node: ast.FunctionDef) -> bool:
    positional_args = [*function_node.args.posonlyargs, *function_node.args.args]
    required_positional_args = len(positional_args) - len(function_node.args.defaults)
    if required_positional_args > 0:
        return False
    required_keyword_only_args = [
        arg
        for arg, default in zip(function_node.args.kwonlyargs, function_node.args.kw_defaults)
        if default is None
    ]
    return not required_keyword_only_args
