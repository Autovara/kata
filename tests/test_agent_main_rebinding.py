"""Static screening must validate the function the runner actually calls.

`screen_bundle_miner_contract` inspects one AST node; `run_sandbox.py` does
``spec.loader.exec_module(agent)`` and then ``agent.agent_main()`` -- the module global AFTER
import. Those agree only if the inspected ``def`` is the sole thing that ever binds the name.

Counting only top-level ``def``s (issue #151) closed one route. Every other binding form stayed
open, and a submission could show real analysis to screening while executing a canned report --
the shape of the incidents in #86 and #122. Concretely, it bypassed SN60's
``direct_constant_report`` rule, which is the check that detects a hardcoded answer bank.

Both directions are tested. False positives matter as much as bypasses here: a rule that rejected
ordinary code would push honest miners into rewriting working agents.
"""

from __future__ import annotations

import ast

import pytest

from kata.screening.rules import screen_bundle_miner_contract

#: A plausible entrypoint plus a canned alternative, so each attack below only has to add the
#: rebinding line. Without this decoy the attacks are rejected for a DIFFERENT reason -- see the
#: standalone tests at the bottom.
DECOY = '''
def agent_main(project_dir=None, inference_api=None):
    return {"vulnerabilities": _real(project_dir)}

def _real(directory):
    return []

def _canned(project_dir=None, inference_api=None):
    return {"vulnerabilities": [{"file": "Vault.sol", "severity": "critical", "description": "x"}]}
'''


def _screen(source: str) -> list[str]:
    return [f.rule_id for f in screen_bundle_miner_contract({"agent.py": ast.parse(source)})]


# ---- every route that silently replaced the entrypoint ---

REBINDING_ROUTES = {
    "assignment": "agent_main = _canned",
    "tuple unpacking": "agent_main, _other = _canned, 1",
    "starred unpacking": "*_rest, agent_main = [1, _canned]",
    "annotated assignment": "agent_main: object = _canned",
    "walrus in an assignment": "_ = (agent_main := _canned)",
    "walrus in a call": "print(agent_main := _canned)",
    "def nested in if": "if True:\n    def agent_main(p=None, i=None):\n        return {}",
    "def nested in try": (
        "try:\n    def agent_main(p=None, i=None):\n        return {}\n"
        "except Exception:\n    pass"
    ),
    "def nested in while": (
        "while False:\n    def agent_main(p=None, i=None):\n        return {}"
    ),
    "def nested in with": (
        "import contextlib\nwith contextlib.nullcontext():\n"
        "    def agent_main(p=None, i=None):\n        return {}"
    ),
    "class shadowing": "class agent_main:\n    pass",
    "type alias shadowing": "type agent_main = object",
    "import alias": "from helpers.canned import report as agent_main",
    "plain import alias": "import helpers.canned as agent_main",
    "for-loop target": "for agent_main in (_canned,):\n    pass",
    "with-as target": (
        "import contextlib\n"
        "with contextlib.nullcontext(_canned) as agent_main:\n    pass"
    ),
    "except-as target": "try:\n    pass\nexcept Exception as agent_main:\n    pass",
    "global rebind from a helper": (
        "def _install():\n    global agent_main\n    agent_main = _canned\n_install()"
    ),
}


@pytest.mark.parametrize("route", sorted(REBINDING_ROUTES))
def test_a_rebound_entrypoint_is_rejected(route):
    findings = _screen(DECOY + "\n" + REBINDING_ROUTES[route] + "\n")
    assert findings, f"{route} still passes screening"
    assert findings[0] in {"bundle.agent_main_rebound", "bundle.agent_main_star_import"}, findings


NAMESPACE_ROUTES = {
    "globals subscript": "globals()['agent_main'] = _canned",
    "globals update": "globals().update({'agent_main': _canned})",
    "vars subscript": "vars()['agent_main'] = _canned",
    "setattr on this module": (
        "import sys\nsetattr(sys.modules[__name__], 'agent_main', _canned)"
    ),
    "exec": "exec('agent_main = _canned')",
    "computed globals key": "_k = 'agent' + '_main'\nglobals()[_k] = _canned",
}


@pytest.mark.parametrize("route", sorted(NAMESPACE_ROUTES))
def test_namespace_mutation_that_could_reach_the_entrypoint_is_rejected(route):
    """A computed key is unknowable statically, so it fails closed."""
    findings = _screen(DECOY + "\n" + NAMESPACE_ROUTES[route] + "\n")
    assert findings == ["bundle.agent_main_namespace_mutation"], f"{route}: {findings}"


def test_a_star_import_is_rejected():
    """It can bind any name, including the entrypoint, and nothing in this file reveals which."""
    assert _screen(DECOY + "\nfrom helpers.canned import *\n") == ["bundle.agent_main_star_import"]


def test_a_decorated_entrypoint_is_rejected():
    """A decorator's return value is by definition not the body screening read. Static analysis
    cannot distinguish an identity-preserving wrapper from a replacement, so this fails closed."""
    source = '''
def _swap(fn):
    return lambda *a, **k: {"vulnerabilities": [{"file": "X.sol"}]}

@_swap
def agent_main(project_dir=None, inference_api=None):
    return {"vulnerabilities": []}
'''
    assert _screen(source) == ["bundle.agent_main_decorated"]


# ---- the routes that were ALREADY rejected, and must stay that way ---
#
# Standalone -- with no decoy -- these are caught by the entrypoint fallthrough rather than by the
# rebinding rule: with no top-level `def`, `find_module_function_def` returns None. They fail
# CLOSED BY ACCIDENT of the design. Pinned because a later change that made the lookup more
# permissive would silently reopen them, and every test above includes a decoy so none would notice.

@pytest.mark.parametrize("source,expected", [
    ("if True:\n    def agent_main(p=None, i=None):\n        return {}\n", "bundle.entrypoint"),
    ("from helpers.canned import report as agent_main\n", "bundle.entrypoint"),
    ("agent_main = lambda: {}\n", "bundle.entrypoint"),
])
def test_a_module_with_no_top_level_def_is_still_rejected(source, expected):
    assert _screen(source) == [expected]


def test_the_plain_duplicate_def_rule_is_unchanged():
    """#151's rule id and message are load-bearing for the bot's handling; the new rules sit
    alongside it rather than replacing it."""
    source = DECOY + "\ndef agent_main(p=None, i=None):\n    return {'vulnerabilities': []}\n"
    assert _screen(source) == ["bundle.agent_main_duplicate"]


# ---- what must keep working ---

LEGITIMATE = {
    "plain entrypoint": "",
    "method of the same name": (
        "class Analyzer:\n    def agent_main(self):\n        return None"
    ),
    "inner def of the same name": (
        "def _outer():\n    def agent_main():\n        return 1\n    return agent_main"
    ),
    "bare annotation without a value": "from typing import Callable\nagent_main: Callable",
    "TYPE_CHECKING block": (
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from helpers import Report"
    ),
    "try/except import of another name": (
        "try:\n    import fast as _p\nexcept ImportError:\n    _p = None"
    ),
    "decorated helper": (
        "import functools\n@functools.lru_cache\ndef _score(x):\n    return x"
    ),
    "globals write to an unrelated constant key": "globals()['_CACHE'] = {}",
    "setattr on an unrelated name": (
        "import sys\nsetattr(sys.modules[__name__], '_CACHE', {})"
    ),
    "loop binding another name": "for _name in ('a', 'b'):\n    pass",
    "__all__ export": "__all__ = ['agent_main']",
    "__main__ guard": "if __name__ == '__main__':\n    print(agent_main())",
}


@pytest.mark.parametrize("case", sorted(LEGITIMATE))
def test_ordinary_code_is_not_rejected(case):
    """False positives are the real cost of this rule: each one is an honest miner told to rewrite
    a working agent."""
    source = '''
def agent_main(project_dir=None, inference_api=None):
    return {"vulnerabilities": _real(project_dir)}

def _real(directory):
    return []
''' + "\n" + LEGITIMATE[case] + "\n"
    assert _screen(source) == [], f"{case} was rejected"


# ---- routes found in review of the FIRST version of this rule ---
#
# The first version rejected every example in issue #206 and still left the vulnerability class
# open. Each case below passed it. They are grouped separately from the tests above so the reason
# they exist is not lost: closing the reported syntax is not the same as closing the class.

REVIEW_ROUTES = {
    # `if TYPE_CHECKING:` was skipped entirely, on the assumption its body never runs. The name is
    # just a name -- a submission can bind it True -- and skipping the statement also skipped the
    # `else:` branch, which runs precisely when TYPE_CHECKING is false.
    "TYPE_CHECKING rebound to True": (
        "TYPE_CHECKING = True\nif TYPE_CHECKING:\n    agent_main = _canned"
    ),
    "TYPE_CHECKING else branch": (
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n    pass\nelse:\n    agent_main = _canned"
    ),
    # `except*` is ast.TryStar, a different node from ast.Try.
    "assignment inside except*": (
        "try:\n    pass\nexcept* Exception:\n    agent_main = _canned"
    ),
}


@pytest.mark.parametrize("route", sorted(REVIEW_ROUTES))
def test_a_control_flow_route_found_in_review_is_rejected(route):
    findings = _screen(DECOY + "\n" + REVIEW_ROUTES[route] + "\n")
    assert findings == ["bundle.agent_main_rebound"], f"{route}: {findings}"


REVIEW_NAMESPACE_ROUTES = {
    "locals() write": "locals()['agent_main'] = _canned",
    "vars() no-arg write": "vars()['agent_main'] = _canned",
    "globals().__setitem__": "globals().__setitem__('agent_main', _canned)",
    "module attribute write": (
        "import sys\nsys.modules[__name__].agent_main = _canned"
    ),
    "module __dict__ write": (
        "import sys\nsys.modules[__name__].__dict__['agent_main'] = _canned"
    ),
    "setattr on this module": (
        "import sys\nsetattr(sys.modules[__name__], 'agent_main', _canned)"
    ),
}


@pytest.mark.parametrize("route", sorted(REVIEW_NAMESPACE_ROUTES))
def test_a_namespace_route_found_in_review_is_rejected(route):
    """Every one of these is a one-line namespace write, not exotic metaprogramming."""
    findings = _screen(DECOY + "\n" + REVIEW_NAMESPACE_ROUTES[route] + "\n")
    assert findings == ["bundle.agent_main_namespace_mutation"], f"{route}: {findings}"


# ---- false positives found in the same review ---
#
# Failing closed is reasonable; failing closed on code that provably cannot reach the entrypoint is
# not. Each of these was rejected by the first version.

REVIEW_LEGITIMATE = {
    # eval evaluates an EXPRESSION and cannot bind a name; __import__ returns a module object.
    "eval of an expression": "_v = eval('1 + 1')",
    "__import__": "_m = __import__('math')",
    # These change the OBJECT, not this module's namespace.
    "vars(obj) write": "class _C:\n    pass\n_c = _C()\nvars(_c)['agent_main'] = 1",
    "setattr on another object": "class _C:\n    pass\n_c = _C()\nsetattr(_c, 'agent_main', 1)",
    "type setattr on another object": (
        "class _C:\n"
        "    pass\n"
        "_c = _C()\n"
        "type(_c).__setattr__(_c, 'agent_main', 1)"
    ),
    "in-place merge on an ordinary dict": (
        "_g = {}\n_g |= {'agent_main': _canned}"
    ),
    "get an unrelated module": (
        "import sys\nsys.modules.get('sys')._KATA_TEST_VALUE = 1"
    ),
    # A lambda body is its own scope, so the walrus binds there.
    "walrus inside a lambda": "_f = lambda x: (agent_main := x)",
    # The outer scope DECLARES global but never assigns; the inner assignment is local to the inner
    # scope and never reaches the module.
    "global declared outside, assigned locally inside": (
        "def _outer():\n"
        "    global agent_main\n"
        "    def _inner():\n"
        "        agent_main = 1\n"
        "        return agent_main\n"
        "    return _inner"
    ),
}


@pytest.mark.parametrize("case", sorted(REVIEW_LEGITIMATE))
def test_a_false_positive_found_in_review_is_accepted(case):
    source = DECOY + "\n" + REVIEW_LEGITIMATE[case] + "\n"
    assert _screen(source) == [], f"{case} was rejected"


# ---- routes found in the SECOND review round ---
#
# The rule matched ``ast.Assign`` only, so the same namespace write with an annotation on it walked
# straight through. An annotation changes nothing about what the statement does: all three forms
# below were verified to rebind the entrypoint against a real module object.

ANNOTATED_NAMESPACE_ROUTES = {
    "annotated globals subscript": 'globals()["agent_main"]: object = _canned',
    "annotated module attribute": (
        "import sys\nsys.modules[__name__].agent_main: object = _canned"
    ),
    "annotated module __dict__": (
        'import sys\nsys.modules[__name__].__dict__["agent_main"]: object = _canned'
    ),
}


@pytest.mark.parametrize("route", sorted(ANNOTATED_NAMESPACE_ROUTES))
def test_an_annotated_namespace_write_is_rejected(route):
    findings = _screen(DECOY + "\n" + ANNOTATED_NAMESPACE_ROUTES[route] + "\n")
    assert findings == ["bundle.agent_main_namespace_mutation"], f"{route}: {findings}"


@pytest.mark.parametrize("call", ["locals", "vars"])
def test_a_module_scope_namespace_write_is_rejected(call):
    """At module scope these ARE the module namespace, and the write really does rebind."""
    source = DECOY + f'\n{call}()["agent_main"] = _canned\n'
    assert _screen(source) == ["bundle.agent_main_namespace_mutation"]


@pytest.mark.parametrize("call", ["locals", "vars"])
def test_the_same_write_inside_a_function_is_accepted(call):
    """Inside a function they are that function's locals. The write is invisible to the module --
    confirmed at run time, where ``agent_main`` is left untouched -- so rejecting it would fail an
    honest submission for an attack it cannot perform."""
    source = DECOY + f'\ndef helper():\n    {call}()["agent_main"] = _canned\nhelper()\n'
    assert _screen(source) == [], f"{call}() inside a function was rejected"


def test_a_bare_annotation_on_a_namespace_target_is_accepted():
    """``x: object`` with no value binds nothing."""
    source = DECOY + "\nimport sys\nsys.modules[__name__].agent_main: object\n"
    assert _screen(source) == []


def test_an_annotated_write_to_an_unrelated_key_is_accepted():
    assert _screen(DECOY + '\nglobals()["_CACHE"]: object = {}\n') == []


def test_deleting_the_entrypoint_is_rejected():
    """``del agent_main`` is the necessary ingredient for the PEP 562 route: a module-level
    ``__getattr__`` only fires for names the module does NOT have. One visible statement, so it is
    caught rather than left to the runtime check."""
    source = DECOY + "\ndel agent_main\ndef __getattr__(name):\n    return _canned\n"
    assert _screen(source) == ["bundle.agent_main_deleted"]


def test_deleting_an_unrelated_name_is_accepted():
    assert _screen(DECOY + "\n_scratch = 1\ndel _scratch\n") == []


# ---- definition-time scopes and aliases found in the THIRD review round ---
#
# A definition's AST children do not all execute in the definition's body scope. Defaults,
# decorators and eager annotations run in the containing scope while the definition is created.
# Lambda defaults do too. A structural "stop at FunctionDef/Lambda" walk therefore misses writes
# that happen during module import.

DEFINITION_TIME_NAMESPACE_ROUTES = {
    "function default through locals": (
        "def helper(value=locals().__setitem__('agent_main', _canned)):\n    pass"
    ),
    "function default through vars": (
        "def helper(value=vars().__setitem__('agent_main', _canned)):\n    pass"
    ),
    "eager return annotation": (
        "def helper() -> locals().__setitem__('agent_main', _canned):\n    pass"
    ),
    "helper decorator expression": (
        "def identity(fn):\n"
        "    return fn\n"
        "@(locals().__setitem__('agent_main', _canned), identity)[1]\n"
        "def helper():\n"
        "    pass"
    ),
    "lambda default": (
        "helper = lambda value=locals().__setitem__('agent_main', _canned): value"
    ),
    "class base expression": (
        "class Helper((locals().__setitem__('agent_main', _canned), object)[1]):\n"
        "    pass"
    ),
}


@pytest.mark.parametrize("route", sorted(DEFINITION_TIME_NAMESPACE_ROUTES))
def test_a_definition_time_namespace_write_is_rejected(route):
    findings = _screen(DECOY + "\n" + DEFINITION_TIME_NAMESPACE_ROUTES[route] + "\n")
    assert findings == ["bundle.agent_main_namespace_mutation"], f"{route}: {findings}"


def test_a_postponed_annotation_does_not_execute_during_import():
    source = (
        "from __future__ import annotations\n"
        + DECOY
        + "\ndef helper() -> locals().__setitem__('agent_main', _canned):\n"
        "    pass\n"
    )
    assert _screen(source) == []


def test_a_forced_type_parameter_bound_cannot_mutate_globals():
    source = (
        DECOY
        + "\ndef helper[T: (globals().__setitem__('agent_main', _canned), object)[1]]():\n"
        "    pass\n"
        "_ = helper.__type_params__[0].__bound__\n"
    )
    assert _screen(source) == ["bundle.agent_main_namespace_mutation"]


def test_locals_in_a_lazy_annotation_scope_are_not_module_globals():
    source = (
        DECOY
        + "\ndef helper[T: (locals().__setitem__('agent_main', _canned), object)[1]]():\n"
        "    pass\n"
        "_ = helper.__type_params__[0].__bound__\n"
    )
    assert _screen(source) == []


def test_a_walrus_in_a_lambda_default_is_a_module_binding():
    source = DECOY + "\nhelper = lambda value=(agent_main := _canned): value\n"
    assert _screen(source) == ["bundle.agent_main_rebound"]


@pytest.mark.parametrize(
    "body",
    [
        "def helper():\n    value = (agent_main := _canned)\n    return value",
        "class Helper:\n    value = (agent_main := _canned)",
    ],
)
def test_a_walrus_confined_to_a_nested_scope_is_accepted(body):
    """Function and class bodies have their own bindings; neither changes the module global."""
    assert _screen(DECOY + "\n" + body + "\n") == []


MODULE_ALIAS_ROUTES = {
    "module object alias": (
        "import sys\nmodule = sys.modules[__name__]\nmodule.agent_main = _canned"
    ),
    "module mapping alias": "namespace = globals()\nnamespace['agent_main'] = _canned",
    "chained module alias": (
        "import sys\nmodule = sys.modules[__name__]\nalias = module\nalias.agent_main = _canned"
    ),
    "function-local module alias": (
        "def install():\n"
        "    import sys\n"
        "    module = sys.modules[__name__]\n"
        "    module.agent_main = _canned\n"
        "install()"
    ),
    "vars of module alias": (
        "import sys\n"
        "module = sys.modules[__name__]\n"
        "namespace = vars(module)\n"
        "namespace['agent_main'] = _canned"
    ),
    "module registry alias": (
        "import sys\n"
        "registry = sys.modules\n"
        "module = registry[__name__]\n"
        "module.agent_main = _canned"
    ),
    "imported module registry alias": (
        "from sys import modules as registry\n"
        "module = registry[__name__]\n"
        "module.agent_main = _canned"
    ),
    "import current module": (
        "module = __import__(__name__)\nmodule.agent_main = _canned"
    ),
}


@pytest.mark.parametrize("route", sorted(MODULE_ALIAS_ROUTES))
def test_a_write_through_a_module_alias_is_rejected(route):
    findings = _screen(DECOY + "\n" + MODULE_ALIAS_ROUTES[route] + "\n")
    assert findings == ["bundle.agent_main_namespace_mutation"], f"{route}: {findings}"


NAMESPACE_DELETE_AND_TARGET_ROUTES = {
    "delete through globals": (
        "del globals()['agent_main']\ndef __getattr__(name):\n    return _canned"
    ),
    "delete through module alias": (
        "import sys\n"
        "module = sys.modules[__name__]\n"
        "del module.agent_main\n"
        "def __getattr__(name):\n"
        "    return _canned"
    ),
    "object setattr": (
        "import sys\n"
        "object.__setattr__(sys.modules[__name__], 'agent_main', _canned)"
    ),
    "module type setattr": (
        "import sys\n"
        "type(sys).__setattr__(sys.modules[__name__], 'agent_main', _canned)"
    ),
    "ModuleType setattr": (
        "import sys\n"
        "import types\n"
        "types.ModuleType.__setattr__(sys.modules[__name__], 'agent_main', _canned)"
    ),
    "mapping alias augmented union": (
        "namespace = globals()\nnamespace |= {'agent_main': _canned}"
    ),
    "module registry get": (
        "import sys\nsys.modules.get(__name__).agent_main = _canned"
    ),
    "module spec name": (
        "import sys\nsys.modules[__spec__.name].agent_main = _canned"
    ),
    "loop namespace target": "for globals()['agent_main'] in (_canned,):\n    pass",
    "comprehension namespace target": (
        "_ = [None for globals()['agent_main'] in (_canned,)]"
    ),
    "unbound dict setitem": (
        "dict.__setitem__(globals(), 'agent_main', _canned)"
    ),
    "operator setitem": (
        "import operator\noperator.setitem(globals(), 'agent_main', _canned)"
    ),
    "in-place mapping union": "globals().__ior__({'agent_main': _canned})",
}


@pytest.mark.parametrize("route", sorted(NAMESPACE_DELETE_AND_TARGET_ROUTES))
def test_other_direct_namespace_mutations_are_rejected(route):
    findings = _screen(DECOY + "\n" + NAMESPACE_DELETE_AND_TARGET_ROUTES[route] + "\n")
    assert findings == ["bundle.agent_main_namespace_mutation"], f"{route}: {findings}"


@pytest.mark.parametrize(
    "body",
    [
        "class Helper:\n    locals()['agent_main'] = _canned",
        "_ = [locals().__setitem__('agent_main', _canned) for _index in range(1)]",
    ],
)
def test_a_nested_locals_mapping_cannot_rebind_the_module(body):
    """Class and comprehension locals are not the module namespace."""
    assert _screen(DECOY + "\n" + body + "\n") == []
