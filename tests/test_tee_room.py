"""Tests for the sealed-room (TEE) Kata-side logic in kata.validator_system.tee_room.

Uses fake launcher/verifier so the whole flow is testable without a real TEE.
"""
import hashlib

from kata.validator_system.tee_room import (
    RoomPolicy,
    RoomResult,
    VerifiedQuote,
    canonical,
    evaluate_candidate_in_room,
    verify_room_run,
)

APPROVED = "approved-runner-image"
POLICY = RoomPolicy(approved_measurements=frozenset({APPROVED}))
NONCE = bytes.fromhex("0123456789abcdef0123456789abcdef")
PROJECT = "demo-project"
REPORT = {"vulnerabilities": [{"id": "F1"}]}


def _commitment(report, nonce, project):
    ah = hashlib.sha256(canonical(report)).digest()
    return hashlib.sha256(nonce + project.encode() + ah).digest()


class _Verifier:
    def __init__(self, report=REPORT, measurement=APPROVED, ok=True):
        self._rd = _commitment(report, NONCE, PROJECT)
        self._m, self._ok = measurement, ok

    def verify(self, quote_hex):
        return VerifiedQuote(self._ok, self._rd, self._m, "")


class _Launcher:
    def __init__(self, report=REPORT, boom=False):
        self._report, self._boom = report, boom

    def launch_and_run(self, **kw):
        if self._boom:
            raise RuntimeError("CVM failed")
        return RoomResult(report=self._report, quote_hex="q")


def _eval(**over):
    kw = dict(
        candidate_id="pr-1", agent_ref="b", project_key=PROJECT, sealed_key_ref="blob",
        nonce=NONCE, policy=POLICY, launcher=_Launcher(), verifier=_Verifier(),
        seen_nonces=set(),
    )
    kw.update(over)
    return evaluate_candidate_in_room(**kw)


def test_valid_run_accepted():
    o = _eval()
    assert o.accepted and o.report == REPORT


def test_swapped_answer_rejected():
    # room returns a different answer than the proof commits to
    o = _eval(launcher=_Launcher(report={"vulnerabilities": [{"id": "SWAP"}]}))
    assert not o.accepted


def test_unapproved_image_rejected():
    o = _eval(verifier=_Verifier(measurement="rogue"))
    assert not o.accepted


def test_room_failure_handled():
    o = _eval(launcher=_Launcher(boom=True))
    assert not o.accepted and "failed" in o.reason


def test_replay_rejected():
    seen = set()
    assert _eval(seen_nonces=seen).accepted
    assert not _eval(seen_nonces=seen).accepted


def test_verify_binds_answer():
    good = VerifiedQuote(True, _commitment(REPORT, NONCE, PROJECT), APPROVED, "")

    class V:
        def verify(self, q):
            return good

    r = verify_room_run(quote_hex="q", report=REPORT, nonce=NONCE, project_key=PROJECT,
                        policy=POLICY, verifier=V())
    assert r.accepted


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)
    print("all tee_room tests passed")
