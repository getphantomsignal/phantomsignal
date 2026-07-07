"""
PhantomSignal signature engine — Nuclei-style YAML templates over the intel graph.

Two template modes:
  * ``match`` — evaluate matchers against aggregated result dicts and emit a
    finding when they fire (exposures, takeovers, exposed panels, ...).
  * ``dork``  — render GHDB-style search queries scoped to the target and emit
    them as ready-to-run findings (the first, highest-yield template pack).
"""
from phantomsignal.intel.signatures.engine import (
    SignatureEngine,
    Signature,
    load_templates,
)

__all__ = ["SignatureEngine", "Signature", "load_templates"]
