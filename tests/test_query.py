"""Tests for the offline /query API and its DNS wire encoder.

The wire tests use a small independent parser (no DNS library) so they verify
the bytes themselves: name decompression, RR boundaries, the OPT record and
truncation at whole-RRset granularity.
"""

from __future__ import annotations

import base64
import struct

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.dns_wire import (
    TYPE_A,
    TYPE_CNAME,
    TYPE_OPT,
    RRSet,
    build_response,
    fixed_overhead,
)
from app.main import app
from app.models import QueryRequest
from app.query import build_query_response

client = TestClient(app)

TYPE_NAMES = {TYPE_A: "A", TYPE_CNAME: "CNAME", TYPE_OPT: "OPT"}


# --------------------------------------------------------------------------- #
# Independent wire parser
# --------------------------------------------------------------------------- #


class Parsed:
    def __init__(self, wire: bytes) -> None:
        self.wire = wire
        qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", wire[:12])
        self.id = qid
        self.flags = flags
        self.qd, self.an, self.ns, self.ar = qd, an, ns, ar
        self.tc = bool(flags & 0x0200)
        self.aa = bool(flags & 0x0400)
        self.qr = bool(flags & 0x8000)
        offset = 12
        self.question: list[tuple[str, int, int]] = []
        for _ in range(qd):
            name, offset = self._name(offset)
            qtype, qclass = struct.unpack("!HH", wire[offset:offset + 4])
            offset += 4
            self.question.append((name, qtype, qclass))
        self.answer: list[dict] = []
        for _ in range(an):
            rr, offset = self._rr(offset)
            self.answer.append(rr)
        self.authority: list[dict] = []
        for _ in range(ns):
            rr, offset = self._rr(offset)
            self.authority.append(rr)
        self.additional: list[dict] = []
        for _ in range(ar):
            rr, offset = self._rr(offset)
            self.additional.append(rr)
        assert offset == len(wire), (offset, len(wire))

    def _name(self, offset: int) -> tuple[str, int]:
        labels: list[str] = []
        jumped = False
        end = offset
        seen = 0
        while True:
            length = self.wire[offset]
            if length & 0xC0 == 0xC0:
                pointer = ((length & 0x3F) << 8) | self.wire[offset + 1]
                if not jumped:
                    end = offset + 2
                jumped = True
                offset = pointer
                seen += 1
                assert seen < 32, "compression pointer loop"
                continue
            if length == 0:
                if not jumped:
                    end = offset + 1
                break
            labels.append(self.wire[offset + 1:offset + 1 + length].decode("ascii"))
            offset += 1 + length
        return ".".join(labels).lower(), end

    def _rr(self, offset: int) -> tuple[dict, int]:
        name, offset = self._name(offset)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", self.wire[offset:offset + 10])
        offset += 10
        rdata_at = offset
        rdata_bytes = self.wire[offset:offset + rdlen]
        offset += rdlen
        if rtype == TYPE_OPT:
            value: object = None
        elif rtype == TYPE_A:
            value = ".".join(str(b) for b in rdata_bytes)
        elif rtype == TYPE_CNAME:
            value, _ = self._name(rdata_at)
        else:  # pragma: no cover
            value = rdata_bytes
        return {
            "name": name,
            "type": rtype,
            "type_name": TYPE_NAMES.get(rtype, str(rtype)),
            "class": rclass,
            "ttl": ttl,
            "rdlength": rdlen,
            "value": value,
        }, offset


def parse(message: dict) -> Parsed:
    return Parsed(base64.b64decode(message["base64"]))


def zones_cnames() -> list[dict]:
    return [
        {
            "name": "a.example.com",
            "records": [
                {"name": "www.a.example.com", "type": "CNAME",
                 "value": "svc.b.example.com"},
                {"name": "alias.a.example.com", "type": "CNAME",
                 "value": "www.a.example.com"},
            ],
        },
        {
            "name": "b.example.com",
            "records": [
                {"name": "svc.b.example.com", "type": "A", "value": "10.0.0.1"},
                {"name": "svc.b.example.com", "type": "A", "value": "10.0.0.2"},
                {"name": "svc.b.example.com", "type": "A", "value": "10.0.0.3"},
            ],
        },
    ]


def make_request(**overrides) -> QueryRequest:
    body = {
        "zones": zones_cnames(),
        "qname": "alias.a.example.com",
        "link_udp_size": 512,
    }
    body.update(overrides)
    return QueryRequest.model_validate(body)


def query(**overrides) -> dict:
    return build_query_response(make_request(**overrides))


# --------------------------------------------------------------------------- #
# Resolution: same authoritative/no-cache rules as /plan
# --------------------------------------------------------------------------- #


def test_resolves_cname_chain_to_a_rrset() -> None:
    out = query()
    assert out["status"] == "resolved"
    assert out["answer_addresses"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert [r["type"] for r in out["answer_section"]] == ["CNAME", "CNAME", "A"]
    assert out["answer_section"][-1]["record_count"] == 3
    assert out["fault_chain"] is None


def test_apex_a_record_resolves() -> None:
    out = query(
        zones=[{"name": "a.example.com",
                "records": [{"name": "a.example.com", "type": "A", "value": "10.9.9.9"}]}],
        qname="a.example.com",
    )
    assert out["status"] == "resolved"
    assert out["answer_addresses"] == ["10.9.9.9"]


def test_missing_record_returns_fault_chain_not_a_message() -> None:
    out = query(qname="nothere.a.example.com")
    assert out["status"] == "broken"
    assert out["fault_chain"]["category"] == "missing_record"
    assert out["fault_chain"]["detail"] == "nxdomain"
    assert out["fault_chain"]["chain"].endswith("无记录（NXDOMAIN）")
    assert out["full_response"] is None and out["udp_response"] is None


def test_nodata_distinguished_from_nxdomain() -> None:
    out = query(
        zones=[{"name": "a.example.com",
                "records": [{"name": "deep.empty.a.example.com", "type": "A",
                             "value": "10.0.0.1"}]}],
        qname="empty.a.example.com",
    )
    assert out["status"] == "broken"
    assert out["fault_chain"]["detail"] == "nodata"


def test_loop_returns_fault_chain() -> None:
    out = query(
        zones=[{"name": "a.example.com",
                "records": [
                    {"name": "x.a.example.com", "type": "CNAME",
                     "value": "y.a.example.com"},
                    {"name": "y.a.example.com", "type": "CNAME",
                     "value": "x.a.example.com"},
                ]}],
        qname="x.a.example.com",
    )
    assert out["status"] == "broken"
    assert out["fault_chain"]["category"] == "cname_loop"


def test_external_target_returns_fault_chain() -> None:
    out = query(
        zones=[{"name": "a.example.com",
                "records": [{"name": "www.a.example.com", "type": "CNAME",
                             "value": "svc.partner.example.org"}]}],
        qname="www.a.example.com",
    )
    assert out["status"] == "broken"
    assert out["fault_chain"]["category"] == "external_target"


# --------------------------------------------------------------------------- #
# Full response: compression, counts and OPT
# --------------------------------------------------------------------------- #


def test_full_response_structure_without_edns() -> None:
    out = query()
    full = out["full_response"]
    assert full["has_opt"] is False
    assert full["bytes"] == len(base64.b64decode(full["base64"]))
    parsed = parse(full)
    assert parsed.qr and parsed.aa and not parsed.tc
    assert parsed.qd == 1 and parsed.ar == 0
    assert parsed.question == [("alias.a.example.com", TYPE_A, 1)]
    # Two CNAME hops plus three A records = five RRs, three RRsets.
    assert parsed.an == 5 == full["rr_count"]
    assert full["rrset_count"] == 3
    assert [rr["type"] for rr in parsed.answer] == [
        TYPE_CNAME, TYPE_CNAME, TYPE_A, TYPE_A, TYPE_A
    ]
    assert [rr["value"] for rr in parsed.answer] == [
        "www.a.example.com", "svc.b.example.com",
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
    ]


def test_name_compression_is_enabled_and_effective() -> None:
    out = query()
    full = out["full_response"]
    wire = base64.b64decode(full["base64"])
    assert b"\xc0" in wire  # at least one pointer
    # Without compression the same answer is strictly larger.
    uncompressed = build_response(
        "alias.a.example.com",
        TYPE_A,
        [
            RRSet("alias.a.example.com", TYPE_CNAME, 300, ["www.a.example.com"]),
            RRSet("www.a.example.com", TYPE_CNAME, 300, ["svc.b.example.com"]),
            RRSet("svc.b.example.com", TYPE_A, 300,
                  ["10.0.0.1", "10.0.0.2", "10.0.0.3"]),
        ],
        compression=False,
    )
    assert full["bytes"] < len(uncompressed.wire)
    assert full["name_compression"] is True


def test_compression_pointer_targets_name_start() -> None:
    """The pointer for a repeated owner must point at a label-length byte."""
    wire = base64.b64decode(query()["full_response"]["base64"])
    pointer_at = wire.index(b"\xc0\x0c")
    # Offset 12 is the first label length of the question name.
    assert wire[12] == 5  # len("alias")
    target = wire[pointer_at + 1]
    assert wire[target] == 5  # pointer lands on a label length, not mid-label
    assert pointer_at >= 12 + 4 + 1 + 1 + 7 + 1 + 3 + 1 + 4  # after the question


def test_edns_adds_opt_to_both_messages_and_counts_it() -> None:
    without = query()
    with_edns = query(edns_udp_size=1232)
    assert with_edns["edns"]["present"] is True
    assert with_edns["edns"]["client_udp_size"] == 1232
    for key in ("full_response", "udp_response"):
        message = with_edns[key]
        assert message["has_opt"] is True
        parsed = parse(message)
        assert parsed.ar == 1
        opt = parsed.additional[0]
        assert opt["type"] == TYPE_OPT
        assert opt["name"] == ""
        assert opt["class"] == min(1232, 1232)  # server payload, capped by client
        # OPT bytes are included in the reported size.
        assert message["bytes"] == len(base64.b64decode(message["base64"]))
        assert message["bytes"] - without[key]["bytes"] == 11
    assert with_edns["full_response"]["bytes"] > without["full_response"]["bytes"]


def test_edns_opt_advertises_min_server_and_client_size() -> None:
    out = query(edns_udp_size=700, link_udp_size=2000)
    opt = parse(out["full_response"]).additional[0]
    assert opt["class"] == 700  # min(server 1232, client 700)
    out = query(edns_udp_size=4096)
    opt = parse(out["full_response"]).additional[0]
    assert opt["class"] == 1232  # server's own receive size


# --------------------------------------------------------------------------- #
# Budget arithmetic
# --------------------------------------------------------------------------- #


def test_budget_is_min_of_link_and_client() -> None:
    no_edns = query(link_udp_size=900)
    assert no_edns["udp_budget"]["client_udp_size"] == 512
    assert no_edns["udp_budget"]["effective"] == 512

    edns_link_smaller = query(link_udp_size=700, edns_udp_size=1400)
    assert edns_link_smaller["udp_budget"]["effective"] == 700

    edns_client_smaller = query(link_udp_size=1400, edns_udp_size=700)
    assert edns_client_smaller["udp_budget"]["effective"] == 700


def test_rejects_edns_below_512() -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 512"):
        make_request(edns_udp_size=100)


def test_full_response_fits_when_budget_large_enough() -> None:
    out = query(link_udp_size=1232, edns_udp_size=1232)
    udp = out["udp_response"]
    assert udp["truncated"] is False and udp["tc"] is False
    assert udp["dropped_rrsets"] == 0
    assert udp["base64"] == out["full_response"]["base64"]
    assert out["udp_budget_insufficient"] is False


def test_truncation_keeps_whole_rrsets_in_resolution_order() -> None:
    full_size = query()["full_response"]["bytes"]
    # Pick a budget that cannot hold the full message but is above overhead.
    out = query(link_udp_size=full_size - 20)
    assert out["udp_budget_insufficient"] is False
    udp = out["udp_response"]
    assert udp["truncated"] is True and udp["tc"] is True
    parsed = parse(udp)
    assert parsed.tc
    assert udp["bytes"] <= udp["budget"]
    # A prefix of the answer, in order, with the A RRset kept or dropped whole.
    kept = [(rr["name"], rr["type"]) for rr in parsed.answer]
    expected = [
        ("alias.a.example.com", TYPE_CNAME),
        ("www.a.example.com", TYPE_CNAME),
        ("svc.b.example.com", TYPE_A),
        ("svc.b.example.com", TYPE_A),
        ("svc.b.example.com", TYPE_A),
    ]
    assert kept == expected[:len(kept)]
    assert 0 < len(kept) < len(expected)
    assert udp["rr_count"] == len(kept)
    assert udp["dropped_rrsets"] == 3 - udp["rrset_count"]
    # Truncation never splits the 3-record A RRset.
    a_records = [rr for rr in parsed.answer if rr["type"] == TYPE_A]
    assert len(a_records) in (0, 3)


def test_truncated_udp_always_fits_budget_across_sizes() -> None:
    full_size = query()["full_response"]["bytes"]
    for budget in range(37, full_size + 2):
        out = query(link_udp_size=budget)
        udp = out["udp_response"]
        assert udp is not None, budget
        assert udp["bytes"] <= budget, budget
        assert udp["tc"] == (udp["base64"] != out["full_response"]["base64"])


def test_insufficient_budget_returns_only_full_response() -> None:
    out = query(link_udp_size=10)
    assert out["udp_budget_insufficient"] is True
    assert out["udp_response"] is None
    assert out["full_response"] is not None
    assert "都放不下" in out["message"]
    parse(out["full_response"])  # the full response is still valid


def test_insufficient_budget_with_edns_accounts_for_opt() -> None:
    overhead = fixed_overhead("alias.a.example.com", TYPE_A, payload=1232)
    out = query(link_udp_size=overhead - 1, edns_udp_size=1232)
    assert out["udp_budget_insufficient"] is True
    assert out["udp_overhead"] == overhead
    assert out["udp_response"] is None
    # Exactly at the overhead the empty (TC) message is still produced.
    out = query(link_udp_size=overhead, edns_udp_size=1232)
    assert out["udp_budget_insufficient"] is False
    assert out["udp_response"]["tc"] is True
    assert out["udp_response"]["rrset_count"] == 0
    assert parse(out["udp_response"]).an == 0


def test_every_budget_yields_decodable_message_within_limit() -> None:
    """Sweep the whole budget range with long names; never overrun the budget."""
    suffix = f"{'b' * 55}.{'c' * 55}.example.com"
    qname = f"{'a' * 55}.{suffix}"
    target = f"x.{suffix}"
    zones = [{
        "name": "example.com",
        "records": [
            {"name": qname, "type": "CNAME", "value": target},
            {"name": target, "type": "A", "value": "10.0.0.1"},
            {"name": target, "type": "A", "value": "10.0.0.2"},
        ],
    }]
    big = query(zones=zones, qname=qname, link_udp_size=65535)["full_response"]["bytes"]
    for budget in range(1, big + 2):
        out = query(zones=zones, qname=qname, link_udp_size=budget)
        udp = out["udp_response"]
        if udp is None:
            assert out["udp_budget_insufficient"], budget
            assert out["full_response"] is not None
            continue
        assert udp["bytes"] <= budget, budget
        parse(udp)
        if out["full_response"]["bytes"] <= budget:
            assert udp["tc"] is False
            assert udp["base64"] == out["full_response"]["base64"]
        else:
            assert udp["tc"] is True


def test_duplicate_a_addresses_are_deduplicated_with_lowest_ttl() -> None:
    out = query(zones=[{
        "name": "a.example.com",
        "records": [
            {"name": "www.a.example.com", "type": "A", "value": "10.0.0.1", "ttl": 300},
            {"name": "www.a.example.com", "type": "A", "value": "10.0.0.1", "ttl": 60},
        ],
    }], qname="www.a.example.com")
    parsed = parse(out["full_response"])
    assert [rr["value"] for rr in parsed.answer] == ["10.0.0.1"]
    assert parsed.answer[0]["ttl"] == 60


# --------------------------------------------------------------------------- #
# Request validation and HTTP
# --------------------------------------------------------------------------- #


def test_rejects_query_outside_submitted_zones() -> None:
    with pytest.raises(ValidationError, match="not inside any submitted zone"):
        make_request(qname="www.other.example.org")


def test_rejects_wildcard_query_name() -> None:
    with pytest.raises(ValidationError, match="invalid query name"):
        make_request(qname="*.a.example.com")


def test_rejects_nested_snapshot_zones() -> None:
    with pytest.raises(ValidationError, match="non-nested"):
        make_request(zones=[
            {"name": "a.example.com", "records": []},
            {"name": "sub.a.example.com", "records": []},
        ])


def test_rejects_record_outside_snapshot_zone() -> None:
    with pytest.raises(ValidationError, match="not owned by zone"):
        make_request(zones=[{"name": "a.example.com", "records": [
            {"name": "www.b.example.com", "type": "A", "value": "10.0.0.1"}]}])


def test_rejects_cname_and_a_at_same_name_in_snapshot() -> None:
    with pytest.raises(ValidationError, match="both A and CNAME"):
        make_request(zones=[{"name": "a.example.com", "records": [
            {"name": "www.a.example.com", "type": "A", "value": "10.0.0.1"},
            {"name": "www.a.example.com", "type": "CNAME",
             "value": "x.a.example.com"}]}])


def test_rejects_wrong_qtype_and_link_size() -> None:
    with pytest.raises(ValidationError):
        make_request(qtype="AAAA")
    with pytest.raises(ValidationError):
        make_request(link_udp_size=0)
    with pytest.raises(ValidationError):
        make_request(edns_udp_size=70000)


def test_query_endpoint_round_trip() -> None:
    response = client.post("/query", json={
        "zones": zones_cnames(),
        "qname": "alias.a.example.com.",
        "qtype": "a",
        "qclass": "in",
        "link_udp_size": 120,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "resolved"
    assert body["query"] == {"name": "alias.a.example.com", "type": "A",
                             "class": "IN"}
    assert body["udp_response"]["tc"] is True
    parse(body["udp_response"])


def test_query_endpoint_broken_returns_200_with_chain() -> None:
    response = client.post("/query", json={
        "zones": zones_cnames(),
        "qname": "gone.a.example.com",
        "link_udp_size": 512,
    })
    assert response.status_code == 200
    assert response.json()["status"] == "broken"


def test_query_endpoint_validation_error_is_422() -> None:
    response = client.post("/query", json={
        "zones": zones_cnames(),
        "qname": "alias.a.example.com",
        "link_udp_size": 0,
    })
    assert response.status_code == 422


def test_openapi_documents_query_endpoint() -> None:
    spec = client.get("/openapi.json").json()
    assert "/query" in spec["paths"]
    assert "/plan" in spec["paths"]
