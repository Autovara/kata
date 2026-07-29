# Entrypoint binding: what screening guarantees

`screen_bundle_miner_contract` validates one AST node. The runner does:

```python
spec.loader.exec_module(agent)   # every rebinding in the module happens here
result = agent.agent_main()      # calls the module global AFTER import
```

Those are the same function only if the inspected `def` is the **only** thing that ever binds the
name. Until #206 the check counted top-level `def`s alone, so a submission could present real
analysis code to screening and execute a canned report — bypassing, among others, SN60's
`direct_constant_report` rule, which is the check aimed squarely at that incident class.

## What is closed now

`kata/ast_utils.py` counts bindings scope-aware: it descends into `if`/`try`/`for`/`while`/`with`/
`match` bodies, which run at import, and stops at function and class bodies, which bind locally.
On top of that it detects star imports, `global` rebinding from a helper, and namespace mutation.

Rejected: assignment, tuple/starred unpacking, annotated assignment with a value, walrus, `def` or
`class` or `type` alias nested in module-level control flow (including `except*`), `import ... as`,
loop/`with`/`except` targets, `global` declaration plus assignment **in the same scope**,
`from x import *`,
writes to this module's namespace via `globals()`/`locals()`/`vars()` (subscript, `update`,
`setdefault`, `__setitem__`), attribute and `__dict__` writes on `sys.modules[__name__]`, `setattr`
and unbound module-type `__setattr__` descriptors on this module, namespace deletions, direct aliases
of the module or its globals mapping, in-place mapping union, assignment-like namespace targets
(including `for` targets), `sys.modules.get(__name__)`, `sys.modules[__spec__.name]`, `exec`, and
a decorated entrypoint.

Annotated forms count. `globals()["agent_main"]: object = _canned` does exactly what the unannotated
version does; an earlier version matched `ast.Assign` only and let all three annotated namespace
writes through.

`locals()` and no-argument `vars()` are scope-aware. At module scope they are the module namespace
and a write there really does rebind. Inside a function they are that function's locals, the write
is invisible to the module, and rejecting it would fail an honest submission for something it cannot
do.

The scope analysis follows Python's *execution* scopes rather than the AST's structural nesting.
Defaults, decorators and eager annotations on a function, plus lambda defaults, execute in the
scope containing the definition and can therefore replace the module entrypoint during import.
Function/lambda bodies and class bodies bind locally and do not count. This distinction prevents
both a working definition-time bypass and the inverse false positive on a walrus inside an honest
helper body.

PEP 695 type-parameter bounds and type-alias values are lazy annotation scopes. They are inspected
as such because an agent can force them before invocation: a `globals()` mutation is rejected, while
a `locals()` write remains local to the annotation scope.

Still accepted: methods, inner `def`s and lambdas of the same name, bare annotations,
`try/except ImportError` fallbacks for other names, decorated *helpers*, `__all__`, `__main__`
guards, namespace writes with a constant key that is provably some other name, `vars(obj)` and
`setattr(obj, ...)` on any object that is not this module, `eval` (it evaluates an expression and
cannot bind a name) and `__import__` (it returns a module).

### `if TYPE_CHECKING:` has no exemption

An earlier version skipped those blocks on the assumption they never execute. Two things were wrong
with that: `TYPE_CHECKING` is an ordinary name a submission can bind to `True`, and skipping the
statement also skipped its `else:` branch — which runs precisely when the guard is false. Both were
working bypasses. Binding analysis now inspects every branch regardless of presumed reachability;
the legitimate case (`if TYPE_CHECKING: from helpers import Report`) still passes because it does
not bind the entrypoint.

Both `kata/screening/rules.py` and `kata-sn60`'s `static_screening.py` call the same analysis, so
the two layers cannot drift into different ideas of what the entrypoint is.

## What is NOT closed, stated plainly

**This does not prove the inspected function is the one the runner calls.** Python's namespace is
writable at run time and static analysis cannot bound reflection in an arbitrary program. Anything
reached through machinery these rules do not model — an import hook, a C extension, a metaclass, a
`__getattr__` on the module — remains outside their reach.

What changes is the cost of doing it. Replacing the entrypoint now requires code no reviewer would
read as ordinary indirection.

That claim is deliberately narrower than "every route is closed". The first version of this rule
rejected every example in issue #206 and still left nine working bypasses, several of them one-line
namespace writes. The rules are as complete as review and testing have made them, not as complete
as the language allows.

Any claim that the static rules make the runtime function "provable" is stronger than static Python
analysis supports, and should not be made.

### Known routes that remain open

Named rather than implied, because a limitation nobody wrote down is one the next reader assumes was
handled:

```python
module = some_opaque_function(sys.modules[__name__])
module.agent_main = _canned
```

Direct and chained aliases (`module = sys.modules[__name__]`, `namespace = globals()`) are tracked.
An alias hidden behind an arbitrary function, container or dynamically imported callable is general
Python data flow, which this syntax-directed analysis cannot prove. This is what the invocation-time
check below exists to catch.

Three shorter routes are also open, and are worth naming because they are one line each rather than
general data flow — they reach the same two objects through one more indirection than the matchers
recognise:

```python
sys.modules.setdefault(__name__, None).agent_main = _canned   # setdefault returns the module
sys.modules[globals()["__name__"]].agent_main = _canned       # __name__ read indirectly
getattr(sys, "modules")[__name__].agent_main = _canned        # registry reached via getattr
```

Closing these by adding `setdefault` and `getattr` to the matchers would work, and would very likely
be followed by a fifth family: the reachable set does not converge by enumeration, because there is
always one more level of indirection to `sys.modules` and `__name__`. The generalisation that would
actually close it is to treat an *unresolvable* expression in either position as fail-closed. That
is a deliberate future tightening, not an oversight — it trades some exotic-but-honest code for a
bound, and `agent.py` is a single-purpose file where that trade is cheap.

The PEP 562 route — `del agent_main` followed by a module-level `__getattr__` that returns a
different function — **is** closed, by `bundle.agent_main_deleted`. A module `__getattr__` only
fires for names the module does not have, so the attack needs the `del`, and that is one visible
statement.

## The other half

The complete fix adds a check at **invocation** time. Before calling, the trusted runner confirms
the resolved object is:

- a plain function (not a builtin, partial, callable object or coroutine function);
- defined in `agent.py`;
- at the source location screening inspected — `__code__.co_filename` and `co_firstlineno`;
- with the approved signature.

Two honest caveats about that check:

1. **It is also forgeable.** `code.replace(co_filename=..., co_firstlineno=...)` exists, so a
   determined submission can point forged bytecode at the screened line. It raises the cost again
   rather than settling the question.
2. **It is not implemented here.** SN60's agent runs inside the upstream `Bitsec-AI/sandbox`
   container, which this project vendors at a pinned commit and does not modify — changing the
   subnet's own validation is out of scope by policy. Wiring it in requires either an upstream
   change or moving invocation into a runner we own.

SN22 is unaffected: its `static_screen` performs entry-point, symlink, size, sealed-credential and
egress checks, and never inspects an `agent_main` body. Its submissions use the `Agent` SDK class,
not a module-level entrypoint.

## Severity

High, competition-integrity, release-blocking. Not a TEE escape, not credential exposure, and not
benchmark disclosure: a submission still has to produce a winning score. The bug makes that path
available to anyone who already has usable canned answers.
