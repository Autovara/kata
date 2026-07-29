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


def count_module_function_defs(
    module_tree: ast.AST,
    function_name: str,
) -> int:
    """Count top-level ``def``/``async def`` bindings of ``function_name``.

    Screening looks up the *first* definition, but Python keeps the *last*
    binding at import time, so a duplicate entrypoint lets a decoy pass checks
    the runner never executes. Callers reject a count greater than one.
    """
    if not isinstance(module_tree, ast.Module):
        return 0
    return sum(
        1
        for node in module_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    )


#: Nodes that open a NEW scope. Their bodies bind names locally, so a ``def`` nested
#: inside one of them never replaces a module global.
_NEW_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def iter_module_scope_nodes(module_tree: ast.AST):
    """Yield the nodes Python executes in MODULE scope, control flow included.

    Descends into ``if`` / ``try`` / ``for`` / ``while`` / ``with`` bodies, because
    those run at import time and bind module globals, and stops at every nested
    function or class, whose body binds names in its own scope instead.
    """
    if not isinstance(module_tree, ast.Module):
        return
    stack: list[ast.AST] = list(reversed(module_tree.body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, _NEW_SCOPE_NODES):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def count_module_scope_name_bindings(module_tree: ast.AST, name: str) -> int:
    """Count every module-scope statement that BINDS ``name`` at import time.

    ``count_module_function_defs`` only sees ``def``s in the module body, but a
    module global is equally rebound by an assignment, an ``import ... as``, a loop
    or ``with`` target, or a ``def`` nested in module-level control flow. Screening
    inspects the definition it can find, so any *second* binding means the callable
    the runner ends up executing was never the one that was checked.
    """
    count = 0
    for node in iter_module_scope_nodes(module_tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            count += int(node.name == name)
        elif isinstance(node, ast.Assign):
            count += sum(_count_target_bindings(target, name) for target in node.targets)
        elif isinstance(node, ast.AnnAssign):
            # A bare annotation (``agent_main: Callable``) declares without binding.
            if node.value is not None:
                count += _count_target_bindings(node.target, name)
        elif isinstance(node, (ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor)):
            count += _count_target_bindings(node.target, name)
        elif isinstance(node, ast.withitem):
            if node.optional_vars is not None:
                count += _count_target_bindings(node.optional_vars, name)
        elif isinstance(node, ast.ExceptHandler):
            count += int(node.name == name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            count += sum(int(_imported_binding(alias) == name) for alias in node.names)
    return count


def has_module_scope_star_import(module_tree: ast.AST) -> bool:
    """Whether the module runs a ``from x import *`` in module scope.

    A star import binds whatever the imported module exports, so it can silently
    replace an entrypoint that screening already inspected.
    """
    return any(
        isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names)
        for node in iter_module_scope_nodes(module_tree)
    )


def declares_global_name(module_tree: ast.AST, name: str) -> bool:
    """Whether any nested scope declares ``global name``, letting it rebind the global."""
    return any(
        isinstance(node, ast.Global) and name in node.names for node in ast.walk(module_tree)
    )


def _count_target_bindings(target: ast.AST, name: str) -> int:
    if isinstance(target, ast.Name):
        return int(target.id == name)
    if isinstance(target, ast.Starred):
        return _count_target_bindings(target.value, name)
    if isinstance(target, (ast.Tuple, ast.List)):
        return sum(_count_target_bindings(element, name) for element in target.elts)
    return 0


def _imported_binding(alias: ast.alias) -> str:
    """The name an ``import`` alias actually binds (``import a.b`` binds ``a``)."""
    return alias.asname or alias.name.split(".")[0]


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
