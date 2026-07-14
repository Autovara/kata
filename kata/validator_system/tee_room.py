"""Sealed-room (TEE) execution for SN60 -- the Kata side.

A candidate can be run inside a confidential VM (Phala/dstack) that the miner pays for and
whose key the owner never sees. This module holds the Kata-side pieces:

  * verify_room_run  -- check the room's attestation (genuine TEE, approved image, binds
                        this exact answer + round), before trusting the answer;
  * evaluate_candidate_in_room -- mint a nonce, run the candidate in the room, verify, and
                        return the verified answer (report) for the normal judge to score;
  * HttpRoomLauncher -- drive ONE running room over HTTP, per candidate (the miner's sealed
                        key travels per request; the room decrypts it inside).

Kata never sees the miner's key and never runs the raw inference itself. Decryption happens
inside the room, so this module needs no crypto -- only stdlib. The raw quote signature
check is delegated to a QuoteVerifier (default: the dcap-qvl CLI), so the logic is testable
with a fake verifier.

Ported from the tested spike (kata-sn60-runner/*). Gated behind KATA_SN60_USE_TEE_ROOM.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


def canonical(obj) -> bytes:
    """Stable byte form of the answer so its hash matches on both sides."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# -- attestation verification ------------------------------------------------


@dataclass(frozen=True)
class VerifiedQuote:
    ok: bool
    report_data: bytes
    measurement: str
    detail: str = ""


class QuoteVerifier(Protocol):
    def verify(self, quote_hex: str) -> VerifiedQuote: ...


@dataclass(frozen=True)
class RoomPolicy:
    approved_measurements: frozenset[str]


@dataclass(frozen=True)
class AttestationResult:
    accepted: bool
    reason: str


def verify_room_run(
    *,
    quote_hex: str,
    report: object,
    nonce: bytes,
    project_key: str,
    policy: RoomPolicy,
    verifier: QuoteVerifier,
    seen_nonces: set | None = None,
) -> AttestationResult:
    vq = verifier.verify(quote_hex)
    if not vq.ok:
        return AttestationResult(False, f"quote not verified: {vq.detail}")
    if vq.measurement not in policy.approved_measurements:
        return AttestationResult(False, f"runner image not approved: {vq.measurement}")
    answer_hash = hashlib.sha256(canonical(report)).digest()
    expected = hashlib.sha256(nonce + project_key.encode() + answer_hash).digest()
    if vq.report_data[:32] != expected:
        return AttestationResult(False, "quote does not cover this answer (swap or replay)")
    if seen_nonces is not None:
        if nonce in seen_nonces:
            return AttestationResult(False, "nonce already used (replay)")
        seen_nonces.add(nonce)
    return AttestationResult(True, "ok")


class DcapQvlVerifier:
    """Verify a TDX quote with the dcap-qvl Python package.

    `parse_quote()` gives report_data + the TD measurement registers; `verify()` checks the
    signature/TCB against Intel/Phala PCCS collateral. The runner image is identified by
    RTMR3 (the app/compose measurement; MRTD/RTMR0-2 are firmware/OS shared by all dstack
    apps), overridable via KATA_SN60_ROOM_MEASUREMENT_REGISTER.

    CONFIRM on real hardware (A6 step 0): the exact collateral-fetch call, the attribute
    names (`report_data`, `rt_mr3`), and which TCB statuses to accept. Those are the only
    unknowns; the surrounding logic is tested.
    """

    ACCEPT_STATUS = frozenset(
        {"UpToDate", "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded"}
    )

    def verify(self, quote_hex: str) -> VerifiedQuote:
        try:
            import time as _time

            import dcap_qvl
        except ImportError:
            return VerifiedQuote(False, b"", "", "dcap-qvl python package not installed")
        try:
            import os as _os

            raw = bytes.fromhex(quote_hex)
            parsed = dcap_qvl.parse_quote(raw)
            report = parsed.report
            report_data = report.report_data
            # Approved-image identity = the dstack COMPOSE-HASH (stable across redeploys),
            # encoded in mr_config_id (byte 0 = version tag, bytes 1..33 = compose-hash).
            # rt_mr3 is NOT usable: it folds in per-instance app-id/instance-id, so it
            # changes on every deployment. Override via KATA_SN60_ROOM_MEASUREMENT_REGISTER.
            register = _os.environ.get("KATA_SN60_ROOM_MEASUREMENT_REGISTER", "compose_hash")
            if register == "compose_hash":
                measurement = report.mr_config_id[1:33].hex()
            else:
                measurement = getattr(report, register).hex()
            import asyncio as _asyncio
            import inspect as _inspect

            pccs = _os.environ.get("KATA_SN60_PCCS_URL", dcap_qvl.PHALA_PCCS_URL)

            async def _collateral_and_verify():
                col = dcap_qvl.get_collateral(pccs, raw)
                if _inspect.isawaitable(col):
                    col = await col
                v = dcap_qvl.verify(raw, col, int(_time.time()))
                if _inspect.isawaitable(v):
                    v = await v
                return v

            verified = _asyncio.run(_collateral_and_verify())
            status = getattr(verified, "status", "")
            if status not in self.ACCEPT_STATUS:
                return VerifiedQuote(False, report_data, measurement, f"tcb status {status}")
            return VerifiedQuote(True, report_data, measurement, "ok")
        except Exception as exc:  # noqa: BLE001
            return VerifiedQuote(False, b"", "", f"dcap-qvl error: {exc}")


# -- run a candidate in a room -----------------------------------------------


@dataclass(frozen=True)
class RoomResult:
    report: object
    quote_hex: str


class RoomLauncher(Protocol):
    def launch_and_run(
        self, *, candidate_id: str, agent_ref: str, project_key: str,
        nonce: bytes, sealed_key_ref: str,
    ) -> RoomResult: ...


@dataclass(frozen=True)
class CandidateOutcome:
    accepted: bool
    report: object | None
    reason: str


def evaluate_candidate_in_room(
    *,
    candidate_id: str,
    agent_ref: str,
    project_key: str,
    sealed_key_ref: str,
    nonce: bytes,
    policy: RoomPolicy,
    launcher: RoomLauncher,
    verifier: QuoteVerifier,
    seen_nonces: set | None = None,
) -> CandidateOutcome:
    try:
        result = launcher.launch_and_run(
            candidate_id=candidate_id, agent_ref=agent_ref, project_key=project_key,
            nonce=nonce, sealed_key_ref=sealed_key_ref,
        )
    except Exception as exc:  # noqa: BLE001 - a room failure is a failed run, not a crash
        return CandidateOutcome(False, None, f"room run failed: {exc}")

    verdict = verify_room_run(
        quote_hex=result.quote_hex, report=result.report, nonce=nonce,
        project_key=project_key, policy=policy, verifier=verifier, seen_nonces=seen_nonces,
    )
    if not verdict.accepted:
        return CandidateOutcome(False, None, verdict.reason)
    return CandidateOutcome(True, result.report, "ok")


class HttpRoomLauncher:
    """Drive ONE running room over HTTP, per candidate (sealed key travels per request)."""

    def __init__(self, base_url: str, timeout: float = 900.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def launch_and_run(
        self, *, candidate_id: str, agent_ref: str, project_key: str,
        nonce: bytes, sealed_key_ref: str,
    ) -> RoomResult:
        payload = json.dumps({
            "nonce": nonce.hex(), "project_key": project_key, "sealed_key": sealed_key_ref,
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/run", data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"room HTTP {exc.code}: {exc.read().decode(errors='replace')[:400]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"could not reach room: {exc.reason}") from exc
        if "report" not in data or "quote" not in data:
            raise RuntimeError(f"room error: {data.get('error', data)}")
        return RoomResult(report=data["report"], quote_hex=data["quote"])
