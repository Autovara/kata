"""Resolving which execution backend a subnet runs its candidates on.

Subnet-neutral on purpose. SN22 and SN60 had byte-identical copies of this logic differing only in
an environment-variable name, which meant a fix to one -- for example tightening what counts as an
acceptable value -- silently did not apply to the other.

Nothing here knows what a backend *does*. It knows only how to read one from the environment and
when to refuse, because the refusal is the security-relevant part:

    a misspelled backend that fell back to "tee" would be harmless;
    one that fell back to "sandbox" would run an untrusted agent outside the attested room while
    the deployment believed otherwise.

So this **fails closed**. An unrecognised value is an error, never a default.

The caller supplies the variable name, the permitted values and the safe default, because those are
subnet decisions. This module supplies only the discipline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionBackendPolicy:
    """One subnet's backend selection rule.

    ``default`` must itself be permitted; a policy whose default is not in ``allowed`` would refuse
    every unconfigured deployment, which is a mistake worth catching when the policy is declared
    rather than on the first round that runs without the variable set.
    """

    env_var: str
    allowed: frozenset[str]
    default: str

    def __post_init__(self) -> None:
        if not self.allowed:
            raise ValueError(f"{self.env_var}: a policy must permit at least one backend")
        if self.default not in self.allowed:
            raise ValueError(
                f"{self.env_var}: default {self.default!r} is not one of "
                f"{', '.join(sorted(self.allowed))}"
            )

    def resolve(self, environ: dict[str, str] | None = None) -> str:
        """The configured backend, or the safe default. Raises on anything unrecognised.

        ``environ`` is injectable so a caller can resolve against a prepared mapping rather than
        the process environment; production passes nothing.
        """
        source = os.environ if environ is None else environ
        configured = (source.get(self.env_var) or "").strip().lower()
        if not configured:
            return self.default
        if configured not in self.allowed:
            raise ValueError(
                f"{self.env_var} must be one of: {', '.join(sorted(self.allowed))}."
            )
        return configured

    def is_selected(self, backend: str, environ: dict[str, str] | None = None) -> bool:
        return self.resolve(environ) == backend
