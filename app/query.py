"""Offline UDP-budget check: resolve one A/IN query and encode its response.

This answers the operator's question *before* lowering the intranet DNS UDP
limit: for the submitted authoritative snapshots, can the query still be
answered within the link's UDP budget, or will it be truncated (forcing the
client to retry over TCP)?

The resolution rules are deliberately identical to ``POST /plan``'s initial
state -- submitted zones are authoritative and non-nested, resolution is
cache-less, and a chain that leaves the submitted zones is a fault rather
than an assumed answer.  A query that cannot be resolved returns the same
structured fault chain the planner uses; no DNS response is synthesized for
it.

For a resolvable query we build two messages:

* the **full response** (what a TCP client, or a UDP client with a large
  enough budget, would receive), with name compression enabled;
* the **UDP response**, limited to ``min(link_udp_size, client limit)``.

If the full response does not fit, the UDP response carries the longest
prefix of whole RRsets, in resolution order, that fits, and has TC set.  If
even the header, question and required OPT do not fit, there is no UDP
response at all and the result reports an insufficient budget.
"""

from __future__ import annotations

import base64
from typing import Any

from .dns_wire import (
    DEFAULT_SERVER_PAYLOAD,
    TYPE_A,
    TYPE_CNAME,
    EncodingError,
    RRSet,
    build_response,
    fixed_overhead,
)
from .models import QueryRequest, Record, Zone
from .resolver import Resolution, Resolver

STATUS_MEANINGS = {
    "resolved": "查询可解析，已生成完整应答与 UDP 应答",
    "broken": "查询无法解析，返回故障链路（不生成 DNS 应答）",
}


def _rrsets(records: list[Record]) -> list[RRSet]:
    """Group resolved records into RRsets in resolution order.

    Every CNAME hop is its own RRset (one record per owner).  The trailing A
    records all belong to the final owner and form a single RRset, so they are
    kept or dropped together during truncation.  Records in an RRset must share
    a TTL; the lowest submitted TTL is used (the safe choice) if they differ.
    """
    out: list[RRSet] = []
    for rec in records:
        if rec.type == "CNAME":
            out.append(
                RRSet(name=rec.name, rtype=TYPE_CNAME, ttl=rec.ttl, values=[rec.value])
            )
            continue
        if out and out[-1].rtype == TYPE_A and out[-1].name == rec.name:
            out[-1].values.append(rec.value)
            out[-1].ttl = min(out[-1].ttl, rec.ttl)
        else:
            out.append(RRSet(name=rec.name, rtype=TYPE_A, ttl=rec.ttl, values=[rec.value]))
    return out


def _rrset_json(index: int, rrset: RRSet) -> dict[str, Any]:
    return {
        "index": index,
        "owner": rrset.name,
        "type": "A" if rrset.rtype == TYPE_A else "CNAME",
        "ttl": rrset.ttl,
        "values": rrset.values,
        "record_count": rrset.count,
    }


def _message_json(
    message: bytes,
    *,
    has_opt: bool,
    answer_sets: list[RRSet],
    kept_rrsets: int,
) -> dict[str, Any]:
    """Describe one encoded message, including its Base64 body."""
    kept = answer_sets[:kept_rrsets]
    return {
        "format": "dns_wire",
        "encoding": "base64",
        "name_compression": True,
        "has_opt": has_opt,
        "answer_rrsets": [_rrset_json(i, r) for i, r in enumerate(kept)],
        "rr_count": sum(r.count for r in kept),
        "rrset_count": kept_rrsets,
        "bytes": len(message),
        "base64": base64.b64encode(message).decode("ascii"),
    }


def build_query_response(request: QueryRequest) -> dict[str, Any]:
    # A snapshot zone is modelled as an unchanged plan zone (old == new), which
    # is exactly how POST /plan treats a zone submitted with identical states.
    resolver = Resolver(
        [
            Zone(name=z.name, records=z.records, new_records=z.records)
            for z in request.zones
        ]
    )
    resolution: Resolution = resolver.resolve(request.qname, frozenset())

    edns = request.has_edns
    client_limit = request.client_udp_size
    budget = request.udp_budget
    base: dict[str, Any] = {
        "mode": "authoritative_no_cache",
        "query": {
            "name": request.qname,
            "type": request.qtype,
            "class": request.qclass,
        },
        "edns": {
            "present": edns,
            "client_udp_size": client_limit,
            "client_limit_source": "edns_udp_size" if edns else "classic_512",
        },
        "udp_budget": {
            "link_udp_size": request.link_udp_size,
            "client_udp_size": client_limit,
            "effective": budget,
            "rule": "min(link_udp_size, client limit; 512 without EDNS)",
        },
        "assumptions": [
            "提交的区即为权威区现状，互不嵌套；一个名称只归属一个区。",
            "解析不经过缓存，只按提交的权威记录推演。",
            "CNAME 链离开已提交的区即视为无法确认，返回故障链而不是合成应答。",
            "完整应答启用 RFC 1035 名称压缩；UDP 应答按整个 RRset 截断。",
            "EDNS 存在时两种应答都带 OPT，并计入字节数。",
        ],
    }

    if not resolution.ok:
        return {
            **base,
            "status": "broken",
            "status_meaning": STATUS_MEANINGS["broken"],
            "message": resolution.message,
            "fault_chain": {
                "domain": resolution.domain,
                "category": resolution.category,
                "detail": resolution.detail,
                "chain": resolution.chain_text(),
                "trace": [
                    {
                        "name": t.name,
                        "zone": t.zone,
                        "outcome": t.outcome,
                        "target": t.target,
                        "addresses": t.addresses,
                    }
                    for t in resolution.trace
                ],
            },
            "answer_section": [],
            "full_response": None,
            "udp_response": None,
            "udp_budget_insufficient": False,
        }

    answer_sets = _rrsets(resolution.records)
    # EDNS responses advertise the server's own receive size, capped by the
    # client's advertised size.  Without EDNS no OPT is emitted at all.
    opt_payload = min(DEFAULT_SERVER_PAYLOAD, client_limit) if edns else None
    try:
        full = build_response(
            request.qname, TYPE_A, answer_sets, payload=opt_payload, compression=True
        )
        overhead = fixed_overhead(
            request.qname, TYPE_A, payload=opt_payload, compression=True
        )
    except EncodingError as exc:  # pragma: no cover - inputs are validated
        return {
            **base,
            "status": "broken",
            "status_meaning": STATUS_MEANINGS["broken"],
            "message": f"应答编码失败：{exc}",
            "fault_chain": None,
            "answer_section": [_rrset_json(i, r) for i, r in enumerate(answer_sets)],
            "full_response": None,
            "udp_response": None,
            "udp_budget_insufficient": False,
        }

    udp_insufficient = overhead > budget
    udp_response = None
    if not udp_insufficient:
        udp = build_response(
            request.qname,
            TYPE_A,
            answer_sets,
            payload=opt_payload,
            compression=True,
            limit=budget,
        )
        truncated = udp.dropped_rrsets > 0
        udp_response = {
            **_message_json(
                udp.wire,
                has_opt=edns,
                answer_sets=answer_sets,
                kept_rrsets=udp.kept_rrsets,
            ),
            "budget": budget,
            "fits_budget": len(udp.wire) <= budget,
            "truncated": truncated,
            "tc": truncated,
            "dropped_rrsets": udp.dropped_rrsets,
        }

    full_response = {
        **_message_json(
            full.wire,
            has_opt=edns,
            answer_sets=answer_sets,
            kept_rrsets=len(answer_sets),
        ),
        "fits_udp_budget": len(full.wire) <= budget,
    }
    if udp_insufficient:
        message = (
            f"UDP 预算 {budget} 字节连报头、问题段"
            f"{'和 OPT' if edns else ''}（共 {overhead} 字节）都放不下，"
            "不生成 UDP 应答；只返回完整应答，UDP 侧只能依赖客户端转 TCP。"
            "请提高链路 UDP 上限或增大客户端 EDNS 上限。"
        )
    elif udp_response is not None and udp_response["truncated"]:
        message = (
            f"完整应答 {len(full.wire)} 字节超出 UDP 预算 {budget} 字节，"
            f"UDP 应答置 TC 并保留前 {udp_response['rrset_count']} 个完整 RRset"
            f"（丢弃 {udp_response['dropped_rrsets']} 个），客户端需转 TCP。"
        )
    else:
        message = (
            f"完整应答 {len(full.wire)} 字节未超出 UDP 预算 {budget} 字节，"
            "UDP 应答无需截断。"
        )

    return {
        **base,
        "status": "resolved",
        "status_meaning": STATUS_MEANINGS["resolved"],
        "message": message,
        "fault_chain": None,
        "answer_section": [_rrset_json(i, r) for i, r in enumerate(answer_sets)],
        "answer_addresses": resolution.addresses,
        "udp_overhead": overhead,
        "udp_budget_insufficient": udp_insufficient,
        "full_response": full_response,
        "udp_response": udp_response,
    }
