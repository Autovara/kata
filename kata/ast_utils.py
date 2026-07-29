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


# ---- module-scope binding analysis -----
#
# WHAT THIS DOES AND DOES NOT GUARANTEE.
#
# It closes direct syntax and short alias routes a reviewer could reasonably overlook. It does not,
# and cannot, prove that the inspected function is the one the runner invokes: Python's namespace is
# writable at run time, and static analysis of an arbitrary program cannot bound reflection. A
# determined submission can still reach the module global through machinery this file does not
# model.
#
# What changes is the cost. Replacing the entrypoint now requires code that no reviewer would
# mistake for indirection, which is a different problem from one that hides behind a one-line
# assignment.
#
# The complete fix pairs this with a check at INVOCATION time: the trusted runner confirms the
# object it is about to call is a plain synchronous function defined in agent.py, at the screened
# source location, with the approved signature. That half is not implemented here because SN60's
# agent is invoked inside the upstream Bitsec sandbox container, which this project vendors and
# does not modify. The full rationale is the comment block below.
#--------------------------------------------------------
#
# `count_module_function_defs` above answers "how many top-level `def`s bind this name?". That is
# not the question screening needs. Screening validates one AST node; the runner calls whatever the
# module global holds AFTER import. Those agree only if the inspected `def` is the ONLY thing that
# ever binds the name in module scope.
#
# A module global is equally bound by an assignment, an `import ... as`, a loop/`with`/`except`
# target, a `def` or `class` nested in module-level control flow, a walrus, a `global` declaration
# in a helper that runs at import, a star import, or namespace mutation. None of those are
# `FunctionDef` nodes in `module_tree.body`, so a decoy-plus-rebind submission passed every check
# tied to the inspected function -- including SN60's canned-report detection, which is exactly the
# check that would have caught the incident this exists to prevent.

#: Statement types that RUN in module scope and can therefore bind a module global from inside them.
#: A `def`/`class` body does not: it creates a new scope, so an `agent_main` method or
#: inner function is legal and must not be counted.
_MODULE_SCOPE_BLOCKS = (
    ast.If, ast.Try, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Match,
)
if hasattr(ast, "TryStar"):          # Python 3.11+: `except*` is a distinct node
    _MODULE_SCOPE_BLOCKS = (*_MODULE_SCOPE_BLOCKS, ast.TryStar)

_NEW_SCOPE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def iter_module_scope_statements(module_tree: ast.AST):
    """Every statement that executes in module scope, control flow included.

    Descends into ``if``/``try``/``for``/``while``/``with``/``match`` bodies, which run at import.
    Stops at function and class bodies, which bind in their own scope.
    """
    if not isinstance(module_tree, ast.Module):
        return

    def walk(body):
        for node in body:
            yield node
            if isinstance(node, _NEW_SCOPE):
                continue
            if isinstance(node, _MODULE_SCOPE_BLOCKS):
                for field in ("body", "orelse", "finalbody"):
                    yield from walk(getattr(node, field, []) or [])
                for handler in getattr(node, "handlers", []) or []:
                    yield handler
                    yield from walk(handler.body)
                for case in getattr(node, "cases", []) or []:
                    yield case
                    yield from walk(case.body)

    yield from walk(module_tree.body)


def _target_names(target: ast.AST):
    """Names bound by an assignment target, including tuple, list and starred unpacking."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _target_names(element)
    elif isinstance(target, ast.Starred):
        yield from _target_names(target.value)


def _walk_same_scope(node: ast.AST):
    """Every sub-node of ``node`` that shares its scope.

    Definition-time expressions need special handling. Defaults, decorators, annotations, class
    bases and keywords execute in the scope CONTAINING the definition; function/lambda bodies and
    class bodies do not. Treating every child of a definition as nested misses real module writes,
    while walking every child rejects local assignments in an honest helper.
    """
    yield node
    if isinstance(node, _NEW_SCOPE):
        children = _definition_outer_nodes(node)
    else:
        children = ast.iter_child_nodes(node)
    for child in children:
        yield from _walk_same_scope(child)


def _definition_outer_nodes(node: ast.AST, *, annotations_eager: bool = True):
    """Children of a definition that execute in its enclosing scope.

    AST nodes group a function's defaults/decorators/annotations and body under the same parent even
    though Python evaluates them in different scopes. Keeping this distinction in one helper avoids
    duplicating an easy-to-get-wrong list across the binding and namespace analyses.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        yield from node.decorator_list
        yield from node.args.defaults
        yield from (default for default in node.args.kw_defaults if default is not None)
        if annotations_eager:
            arguments = (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
            if node.args.vararg is not None:
                arguments = (*arguments, node.args.vararg)
            if node.args.kwarg is not None:
                arguments = (*arguments, node.args.kwarg)
            yield from (argument.annotation for argument in arguments if argument.annotation)
            if node.returns is not None:
                yield node.returns
        return
    if isinstance(node, ast.Lambda):
        yield from node.args.defaults
        yield from (default for default in node.args.kw_defaults if default is not None)
        return
    if isinstance(node, ast.ClassDef):
        yield from node.decorator_list
        yield from node.bases
        yield from node.keywords


def _postpones_annotations(module_tree: ast.Module) -> bool:
    return any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "__future__"
        and any(alias.name == "annotations" for alias in statement.names)
        for statement in module_tree.body
    )


def _definition_lazy_annotation_nodes(node: ast.AST):
    """PEP 695 expressions evaluated later in an annotation scope."""
    yield from getattr(node, "type_params", ())


def _binds_via_walrus(node: ast.AST, name: str) -> bool:
    """``(agent_main := ...)`` anywhere in this statement, at any nesting inside the same scope.

    Checked for EVERY statement rather than as a fallthrough. The first version of this only
    reached the walrus when no other branch matched, so ``_ = (agent_main := _canned)`` -- an
    ``Assign`` whose target is ``_`` -- returned False from the assignment branch and never got
    here.
    """
    return any(
        isinstance(sub, ast.NamedExpr)
        and isinstance(sub.target, ast.Name)
        and sub.target.id == name
        for sub in _walk_same_scope(node)
    )


def _statement_unbinds(node: ast.AST, name: str) -> bool:
    """``del agent_main`` in module scope.

    Deleting the entrypoint is not a binding, but it has the same consequence: whatever answers for
    the name afterwards is not the definition screening read. It is also the necessary ingredient
    for the PEP 562 route -- a module ``__getattr__`` only fires for names the module does NOT have,
    so the attack needs the ``del``. One visible statement, so it is worth catching rather than
    documenting as out of reach.
    """
    return isinstance(node, ast.Delete) and any(
        isinstance(t, ast.Name) and t.id == name for t in node.targets
    )


def _statement_binds(node: ast.AST, name: str) -> bool:
    """Whether one module-scope statement binds ``name``."""
    if _binds_via_walrus(node, name):
        return True
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name == name
    if isinstance(node, ast.Lambda):
        return False
    if hasattr(ast, "TypeAlias") and isinstance(node, ast.TypeAlias):
        return isinstance(node.name, ast.Name) and node.name.id == name
    if isinstance(node, ast.Assign):
        return any(name == bound for target in node.targets for bound in _target_names(target))
    if isinstance(node, ast.AnnAssign):
        # A bare annotation (`agent_main: Callable`) binds nothing.
        return node.value is not None and any(name == b for b in _target_names(node.target))
    if isinstance(node, ast.AugAssign):
        return any(name == b for b in _target_names(node.target))
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return any(name == b for b in _target_names(node.target))
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return any(
            item.optional_vars is not None
            and any(name == b for b in _target_names(item.optional_vars))
            for item in node.items
        )
    if isinstance(node, ast.ExceptHandler):
        return node.name == name
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return any((alias.asname or alias.name.split(".")[0]) == name for alias in node.names)
    if isinstance(node, ast.match_case):
        return any(
            isinstance(sub, (ast.MatchAs, ast.MatchStar)) and sub.name == name
            for sub in ast.walk(node.pattern)
        )
    return False


def count_module_scope_name_bindings(module_tree: ast.AST, name: str) -> int:
    """How many times module scope binds ``name``, by any construct."""
    return sum(
        1 for node in iter_module_scope_statements(module_tree) if _statement_binds(node, name)
    )


def unbinds_module_scope_name(module_tree: ast.AST, name: str) -> bool:
    """Whether module scope deletes ``name`` after defining it."""
    return any(
        _statement_unbinds(node, name) for node in iter_module_scope_statements(module_tree)
    )


def has_module_scope_star_import(module_tree: ast.AST) -> bool:
    """``from x import *`` in module scope -- it can bind any name, including the entrypoint."""
    return any(
        isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names)
        for node in iter_module_scope_statements(module_tree)
    )


def _same_scope_statements(scope: ast.AST):
    """Statements executed by ``scope`` itself, not by anything nested inside it."""
    if isinstance(scope, ast.Lambda):
        yield from _walk_same_scope(scope.body)
        return
    for statement in getattr(scope, "body", ()):
        yield from _walk_same_scope(statement)


def declares_global_binding(module_tree: ast.AST, name: str) -> bool:
    """A scope that declares ``global name`` AND assigns it **in that same scope**.

    Scope-aware on purpose. An earlier version walked the whole subtree of any scope containing a
    ``global`` declaration, so an outer function that merely DECLARED the name combined with an
    inner function that assigned a purely LOCAL variable of that name was reported as a rebinding.
    That rejects ordinary code: the inner assignment binds in the inner scope and never reaches the
    module.
    """
    if not isinstance(module_tree, ast.Module):
        return False
    for scope in ast.walk(module_tree):
        if not isinstance(scope, _NEW_SCOPE):
            continue
        own = list(_same_scope_statements(scope))
        declares = any(isinstance(n, ast.Global) and name in n.names for n in own)
        if not declares:
            continue
        if any(_statement_binds(n, name) for n in own):
            return True
    return False


#: Reflection that can write THIS module's namespace. The distinction that matters is not "is this
#: a namespace call?" but "does it reach the module global the runner reads?".
#:
#: ``eval`` is deliberately absent because it evaluates an expression and cannot bind a name.
#: ``__import__`` is accepted for ordinary imports, but importing ``__name__`` is recognised as a
#: route to this module object.
_MODULE_NAMESPACE_CALLS = ("globals", "locals", "vars")

#: Methods that write or delete entries in a mapping in place.
_MAPPING_WRITERS = ("update", "setdefault", "__setitem__", "__ior__")
_MAPPING_DELETERS = ("clear", "pop", "popitem", "__delitem__")

_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_MAX_ALIAS_PASSES = 64


def _walk_scoped(
    node: ast.AST,
    at_module_scope: bool = True,
    *,
    annotations_eager: bool | None = None,
):
    """Yield ``(node, at_module_scope)`` for the whole tree.

    Needed because two of these calls mean different things depending on where they appear:
    ``globals()`` is always this module, but ``locals()`` and no-argument ``vars()`` are the
    *enclosing* namespace -- inside a function they are that function's locals, and writing to them
    cannot replace the module entrypoint.
    """
    if annotations_eager is None:
        annotations_eager = not (
            isinstance(node, ast.Module) and _postpones_annotations(node)
        )

    yield node, at_module_scope

    if isinstance(node, _NEW_SCOPE):
        for child in _definition_outer_nodes(node, annotations_eager=annotations_eager):
            yield from _walk_scoped(
                child,
                at_module_scope,
                annotations_eager=annotations_eager,
            )
        for child in _definition_lazy_annotation_nodes(node):
            yield from _walk_scoped(child, False, annotations_eager=annotations_eager)
        body = node.body
        body_nodes = (body,) if isinstance(body, ast.AST) else body
        for child in body_nodes:
            yield from _walk_scoped(child, False, annotations_eager=annotations_eager)
        return

    if hasattr(ast, "TypeAlias") and isinstance(node, ast.TypeAlias):
        for child in (*node.type_params, node.value):
            yield from _walk_scoped(child, False, annotations_eager=annotations_eager)
        return

    if isinstance(node, _COMPREHENSIONS):
        # The outermost iterable is evaluated by the containing scope. The comprehension's targets,
        # filters, remaining iterables and result expression execute in its implicit local scope.
        first_generator, *remaining_generators = node.generators
        yield first_generator, False
        yield from _walk_scoped(
            first_generator.iter,
            at_module_scope,
            annotations_eager=annotations_eager,
        )
        for child in (first_generator.target, *first_generator.ifs):
            yield from _walk_scoped(child, False, annotations_eager=annotations_eager)
        for generator in remaining_generators:
            yield from _walk_scoped(generator, False, annotations_eager=annotations_eager)
        if isinstance(node, ast.DictComp):
            yield from _walk_scoped(node.key, False, annotations_eager=annotations_eager)
            yield from _walk_scoped(node.value, False, annotations_eager=annotations_eager)
        else:
            yield from _walk_scoped(node.elt, False, annotations_eager=annotations_eager)
        return

    for child in ast.iter_child_nodes(node):
        yield from _walk_scoped(
            child,
            at_module_scope,
            annotations_eager=annotations_eager,
        )


def _is_own_module(
    node: ast.AST,
    module_aliases: set[str] | frozenset[str] = frozenset(),
    registry_aliases: set[str] | frozenset[str] = frozenset(),
) -> bool:
    """Whether ``node`` is this module object, directly or through a known alias."""
    if isinstance(node, ast.Name) and node.id in module_aliases:
        return True

    if isinstance(node, ast.Subscript):
        return _is_module_registry(
            node.value,
            registry_aliases,
        ) and _is_current_module_key(node.slice)

    if not isinstance(node, ast.Call) or not node.args:
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id == "__import__":
        return _is_current_module_key(node.args[0])
    if isinstance(func, ast.Attribute) and func.attr == "import_module":
        return _is_current_module_key(node.args[0])
    if (
        isinstance(func, ast.Attribute)
        and func.attr in {"get", "__getitem__"}
        and _is_module_registry(func.value, registry_aliases)
    ):
        return _is_current_module_key(node.args[0])
    return False


def _is_module_registry(
    node: ast.AST,
    registry_aliases: set[str] | frozenset[str] = frozenset(),
) -> bool:
    return (
        isinstance(node, ast.Attribute) and node.attr == "modules"
    ) or (
        isinstance(node, ast.Name)
        and (node.id == "modules" or node.id in registry_aliases)
    )


def _is_current_module_key(node: ast.AST) -> bool:
    """A standard expression that names the currently importing module."""
    if isinstance(node, ast.Name):
        return node.id == "__name__"
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "name"
        and isinstance(node.value, ast.Name)
        and node.value.id == "__spec__"
    )


def _is_own_namespace(
    node: ast.AST,
    at_module_scope: bool = True,
    *,
    module_aliases: set[str] | frozenset[str] = frozenset(),
    mapping_aliases: set[str] | frozenset[str] = frozenset(),
    registry_aliases: set[str] | frozenset[str] = frozenset(),
) -> bool:
    """Whether ``node`` evaluates to THIS module or its namespace.

    ``globals()`` always is. ``locals()`` and no-argument ``vars()`` are only at module scope; in a
    function they are that function's locals, and a write there is invisible to the module. Treating
    them as the module namespace everywhere rejected ordinary code that provably cannot reach the
    entrypoint -- verified: those writes leave ``agent_main`` unchanged at run time.

    ``sys.modules[__name__]`` is the module object. ``vars(obj)`` and ``setattr(obj, ...)`` for any
    other object change that object, not the entrypoint, and are allowed.
    """
    if isinstance(node, ast.Name):
        return node.id in module_aliases or node.id in mapping_aliases
    # Keep this before the generic Call branch. sys.modules.get(__name__) and
    # importlib.import_module(__name__) are calls that return this module object.
    if _is_own_module(node, module_aliases, registry_aliases):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if not isinstance(func, ast.Name) or func.id not in _MODULE_NAMESPACE_CALLS:
            return False
        if node.args:
            return (
                func.id == "vars"
                and len(node.args) == 1
                and _is_own_module(node.args[0], module_aliases, registry_aliases)
            )
        return func.id == "globals" or at_module_scope
    # sys.modules[__name__].__dict__
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return _is_own_module(node.value, module_aliases, registry_aliases)
    return False


def _assignment_pairs(node: ast.AST):
    """``(target, value)`` pairs that can establish an alias.

    Destructuring is deliberately excluded: following a value through arbitrary unpacking is not
    reliable without full data-flow analysis. Direct and chained aliases cover the ordinary,
    reviewer-invisible route this check is intended to close.
    """
    if isinstance(node, ast.Assign):
        yield from ((target, node.value) for target in node.targets)
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        yield node.target, node.value
    elif isinstance(node, ast.NamedExpr):
        yield node.target, node.value


def _collect_namespace_aliases(module_tree: ast.Module) -> tuple[set[str], set[str], set[str]]:
    """Conservatively find names that may refer to this module or its globals mapping."""
    module_aliases: set[str] = set()
    mapping_aliases: set[str] = set()
    registry_aliases: set[str] = set()

    assignments: list[tuple[set[str], ast.AST, bool]] = []
    for node, at_module in _walk_scoped(module_tree):
        if isinstance(node, ast.ImportFrom) and node.module == "sys":
            registry_aliases.update(
                alias.asname or alias.name for alias in node.names if alias.name == "modules"
            )
        for target, value in _assignment_pairs(node):
            names = set(_target_names(target))
            if names:
                assignments.append((names, value, at_module))

    for _ in range(_MAX_ALIAS_PASSES):
        changed = False
        for names, value, at_module in assignments:
            if _is_module_registry(value, registry_aliases):
                before = len(registry_aliases)
                registry_aliases.update(names)
                changed = changed or len(registry_aliases) != before
                continue
            if _is_own_module(value, module_aliases, registry_aliases):
                before = len(module_aliases)
                module_aliases.update(names)
                changed = changed or len(module_aliases) != before
                continue
            if _is_own_namespace(
                value,
                at_module,
                module_aliases=module_aliases,
                mapping_aliases=mapping_aliases,
                registry_aliases=registry_aliases,
            ):
                before = len(mapping_aliases)
                mapping_aliases.update(names)
                changed = changed or len(mapping_aliases) != before
        if not changed:
            break
    else:
        # A deliberately long reverse alias chain must not make static screening quadratic. At
        # the fixed-point budget, fail closed by treating every direct alias target as relevant.
        all_alias_targets = set().union(*(names for names, _value, _scope in assignments))
        module_aliases.update(all_alias_targets)
        mapping_aliases.update(all_alias_targets)

    return module_aliases, mapping_aliases, registry_aliases


def _store_targets(node: ast.AST):
    """Every target written by an assignment-like construct."""
    targets: tuple[ast.AST, ...] = ()
    if isinstance(node, ast.Assign):
        targets = tuple(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor, ast.comprehension)):
        if not isinstance(node, ast.AnnAssign) or node.value is not None:
            targets = (node.target,)
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        targets = tuple(
            item.optional_vars for item in node.items if item.optional_vars is not None
        )

    for target in targets:
        yield from _store_target_leaves(target)


def _store_target_leaves(target: ast.AST):
    if isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _store_target_leaves(element)
    elif isinstance(target, ast.Starred):
        yield from _store_target_leaves(target.value)
    else:
        yield target


def _writes_this_name(key: ast.AST | None, name: str) -> bool:
    """Whether a write keyed by ``key`` could land on ``name``.

    A constant key that is provably some other name cannot; anything computed is unknowable and
    fails closed.
    """
    if key is None:
        return True
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value == name
    return True


def rebinds_name_dynamically(module_tree: ast.AST, name: str) -> bool:
    """Reflection that could replace ``name`` in this module's namespace.

    Spans the WHOLE tree, not module scope only: a helper called at import writes the module global
    just as effectively.

    Fails closed on anything unknowable -- a computed key, an opaque ``update(...)``, any ``exec``.
    Stays quiet on writes that provably cannot reach the entrypoint, because rejecting those would
    punish ordinary code for the shape of an attack it cannot perform.
    """
    if not isinstance(module_tree, ast.Module):
        return False

    module_aliases, mapping_aliases, registry_aliases = _collect_namespace_aliases(module_tree)

    for node, at_module in _walk_scoped(module_tree):
        # ``namespace |= {...}`` is AugAssign, not a call to ``namespace.__ior__`` in the AST.
        # A Name target therefore bypasses the mapping-writer call table unless handled directly.
        if (
            isinstance(node, ast.AugAssign)
            and isinstance(node.op, ast.BitOr)
            and _is_own_namespace(
                node.target,
                at_module,
                module_aliases=module_aliases,
                mapping_aliases=mapping_aliases,
                registry_aliases=registry_aliases,
            )
        ):
            return True

        # An assignment to a namespace target, annotated or not:
        #   globals()["agent_main"] = ...            globals()["agent_main"]: object = ...
        #   sys.modules[__name__].agent_main = ...   ...__dict__["agent_main"]: object = ...
        #
        # AnnAssign was missed by the first version, which matched ast.Assign only. An annotation
        # changes nothing about what the statement does -- all three annotated forms rebind the
        # entrypoint at run time, verified against a real module object.
        for target in _store_targets(node):
            if isinstance(target, ast.Subscript) and _is_own_namespace(
                target.value,
                at_module,
                module_aliases=module_aliases,
                mapping_aliases=mapping_aliases,
                registry_aliases=registry_aliases,
            ):
                if _writes_this_name(target.slice, name):
                    return True
            if isinstance(target, ast.Attribute) and _is_own_namespace(
                target.value,
                at_module,
                module_aliases=module_aliases,
                mapping_aliases=mapping_aliases,
                registry_aliases=registry_aliases,
            ):
                if target.attr == name:
                    return True

        if isinstance(node, ast.Delete):
            for target in node.targets:
                for leaf in _store_target_leaves(target):
                    if isinstance(leaf, ast.Subscript) and _is_own_namespace(
                        leaf.value,
                        at_module,
                        module_aliases=module_aliases,
                        mapping_aliases=mapping_aliases,
                        registry_aliases=registry_aliases,
                    ):
                        if _writes_this_name(leaf.slice, name):
                            return True
                    if isinstance(leaf, ast.Attribute) and _is_own_namespace(
                        leaf.value,
                        at_module,
                        module_aliases=module_aliases,
                        mapping_aliases=mapping_aliases,
                        registry_aliases=registry_aliases,
                    ):
                        if leaf.attr == name:
                            return True

        if not isinstance(node, ast.Call):
            continue
        func = node.func

        # exec() can bind; eval() cannot.
        if isinstance(func, ast.Name) and func.id == "exec":
            return True

        # setattr(<this module>, "agent_main", ...)
        if isinstance(func, ast.Name) and func.id in {"setattr", "delattr"} and node.args:
            if _is_own_module(node.args[0], module_aliases, registry_aliases):
                if len(node.args) < 2 or _writes_this_name(node.args[1], name):
                    return True
            continue

        # module.__setattr__("agent_main", ...) / module.__delattr__("agent_main")
        if isinstance(func, ast.Attribute) and func.attr in {"__setattr__", "__delattr__"}:
            if _is_own_module(func.value, module_aliases, registry_aliases):
                if not node.args or _writes_this_name(node.args[0], name):
                    return True

        # Unbound descriptors bypass the module's bound method:
        #   object.__setattr__(module, ...)
        #   type(sys).__setattr__(module, ...)
        #   types.ModuleType.__setattr__(module, ...)
        if (
            isinstance(func, ast.Attribute)
            and func.attr in {"__setattr__", "__delattr__"}
            and node.args
            and _is_own_module(node.args[0], module_aliases, registry_aliases)
            and _is_module_attribute_descriptor(func.value)
        ):
            if len(node.args) < 2 or _writes_this_name(node.args[1], name):
                return True

        # globals().update(...) / globals().__setitem__("agent_main", ...) / vars().setdefault(...)
        if isinstance(func, ast.Attribute) and func.attr in {
            *_MAPPING_WRITERS,
            *_MAPPING_DELETERS,
        }:
            writes_own_namespace = _is_own_namespace(
                func.value,
                at_module,
                module_aliases=module_aliases,
                mapping_aliases=mapping_aliases,
                registry_aliases=registry_aliases,
            )
            if writes_own_namespace:
                if func.attr in {"__setitem__", "__delitem__", "pop"}:
                    if not node.args or _writes_this_name(node.args[0], name):
                        return True
                else:
                    return True  # update/setdefault/clear/popitem: opaque argument, fail closed

        # Unbound standard-library mutation helpers are the same operations with the mapping passed
        # explicitly: dict.__setitem__(globals(), ...) / operator.setitem(globals(), ...).
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in {"dict", "operator"}
            and func.attr
            in {
                "update",
                "setdefault",
                "__setitem__",
                "__ior__",
                "clear",
                "pop",
                "popitem",
                "__delitem__",
                "setitem",
                "delitem",
            }
            and node.args
            and _is_own_namespace(
                node.args[0],
                at_module,
                module_aliases=module_aliases,
                mapping_aliases=mapping_aliases,
                registry_aliases=registry_aliases,
            )
        ):
            keyed_methods = {"__setitem__", "__delitem__", "pop", "setitem", "delitem"}
            if func.attr not in keyed_methods:
                return True
            if len(node.args) < 2 or _writes_this_name(node.args[1], name):
                return True
    return False


def _is_module_attribute_descriptor(node: ast.AST) -> bool:
    """Known unbound descriptors capable of mutating a module object."""
    if isinstance(node, ast.Name):
        return node.id == "object"
    if isinstance(node, ast.Call):
        return isinstance(node.func, ast.Name) and node.func.id == "type"
    return isinstance(node, ast.Attribute) and node.attr == "ModuleType"
