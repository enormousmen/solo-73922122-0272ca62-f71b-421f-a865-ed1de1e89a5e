"""Run the bundled scenarios through the planner without a server.

Usage (from the repository root)::

    python examples/demo.py

It prints a short, human-readable summary of each response.  ``0[1-4]*.json``
exercise ``POST /plan``; ``0[5-7]*.json`` exercise ``POST /query``.  Start the
service with ``docker compose up --build`` and use the JSON files with curl for
the HTTP examples in README.md.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.models import PlanRequest, QueryRequest
from app.query import build_query_response
from app.service import build_plan

HERE = pathlib.Path(__file__).resolve().parent


def summarise(name: str, out: dict) -> None:
    print(f"=== {name} -> {out['status']}")
    print(out["message"])
    if out["order"]:
        for step in out["steps"]:
            print(
                f"  {step['step']}. {step['zone']}: "
                f"{step['addresses_before']} -> {step['addresses_after']}"
            )
    if out["fault_chains"]:
        for chain in out["fault_chains"]:
            print(f"  故障[{chain['category_label']}] {chain['chain']}")
    if out["blocked_zones"]:
        print(f"  安全前缀: {out['safe_prefix'] or '（无）'}")
        for blocked in out["blocked_zones"]:
            labels = "/".join(c["label"] for c in blocked["categories"])
            print(f"  若无安全顺序时先发布 {blocked['zone']} -> {labels}")
            for failure in blocked["failures"]:
                print(f"      {failure['chain']}")
    print()


def summarise_query(name: str, out: dict) -> None:
    print(f"=== {name} -> {out['status']}")
    print(out["message"])
    print(
        f"  UDP 预算: min(link={out['udp_budget']['link_udp_size']}, "
        f"client={out['udp_budget']['client_udp_size']}) = "
        f"{out['udp_budget']['effective']} 字节"
    )
    if out["fault_chain"]:
        print(f"  故障[{out['fault_chain']['category']}] {out['fault_chain']['chain']}")
    for key, label in (("full_response", "完整应答"), ("udp_response", "UDP 应答")):
        message = out[key]
        if message is None:
            print(f"  {label}: （无）")
            continue
        extra = ""
        if key == "udp_response":
            extra = f" tc={message['tc']} 保留 {message['rrset_count']} 个 RRset"
        print(
            f"  {label}: {message['bytes']} 字节, "
            f"{message['rr_count']} 条记录, OPT={message['has_opt']}{extra}"
        )
    print()


def main() -> None:
    for path in sorted(HERE.glob("0*.json")):
        raw = json.loads(path.read_text())
        if "qname" in raw:
            summarise_query(path.name, build_query_response(QueryRequest.model_validate(raw)))
        else:
            summarise(path.name, build_plan(PlanRequest.model_validate(raw)))


if __name__ == "__main__":
    main()
