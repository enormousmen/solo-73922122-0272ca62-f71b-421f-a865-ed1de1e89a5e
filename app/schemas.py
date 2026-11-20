"""Request/response shapes for the planner, documented for OpenAPI."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class TraceStep(BaseModel):
    name: str
    zone: str | None
    outcome: Literal[
        "cname", "a", "nodata", "nxdomain", "external", "loop", "too_long"
    ]
    target: str | None = None
    addresses: list[str] = Field(default_factory=list)


class ChainFailure(BaseModel):
    domain: str
    resolved: bool
    addresses: list[str]
    category: Literal[
        "missing_record", "cname_loop", "external_target", "chain_too_long"
    ]
    category_label: str | None
    detail: str | None = None
    message: str
    chain: str
    trace: list[TraceStep]


class FailureSummary(BaseModel):
    total: int
    by_category: dict[str, int]
    by_category_label: dict[str, int]


class PlanStep(BaseModel):
    step: int
    zone: str
    action: str
    addresses_before: dict[str, list[str]]
    addresses_after: dict[str, list[str]]
    all_required_resolvable: bool


class BlockedZone(BaseModel):
    zone: str
    categories: list[dict[str, str]]
    failures: list[ChainFailure]


class PlanResponse(BaseModel):
    mode: Literal["authoritative_no_cache"]
    zone_count: int
    domain_count: int
    assumptions: list[str]
    status: Literal["already_broken", "safe_order_found", "no_safe_order"]
    status_meaning: str
    message: str
    order: list[str]
    safe_prefix: list[str]
    safe_prefix_is_maximal: bool | None = None
    steps: list[PlanStep]
    final_state_resolvable: bool | None = None
    fault_chains: list[ChainFailure]
    blocked_zones: list[BlockedZone]
    failure_summary: FailureSummary

    model_config = {"extra": "allow"}


class HealthResponse(BaseModel):
    status: str
    version: str


class QueryInfo(BaseModel):
    name: str
    type: Literal["A"]
    class_: Literal["IN"] = Field(alias="class")

    model_config = {
        "populate_by_name": True,
        "serialize_by_alias": True,
        "protected_namespaces": (),
    }


class EdnsInfo(BaseModel):
    present: bool
    client_udp_size: int
    client_limit_source: Literal["edns_udp_size", "classic_512"]


class UdpBudgetInfo(BaseModel):
    link_udp_size: int
    client_udp_size: int
    effective: int
    rule: str


class RRSetInfo(BaseModel):
    index: int
    owner: str
    type: Literal["A", "CNAME"]
    ttl: int
    values: list[str]
    record_count: int


class EncodedMessage(BaseModel):
    format: Literal["dns_wire"]
    encoding: Literal["base64"]
    name_compression: bool
    has_opt: bool
    answer_rrsets: list[RRSetInfo]
    rr_count: int
    rrset_count: int
    bytes: int
    base64: str


class FullResponse(EncodedMessage):
    fits_udp_budget: bool


class UdpResponse(EncodedMessage):
    budget: int
    fits_budget: bool
    truncated: bool
    tc: bool
    dropped_rrsets: int


class QueryTraceStep(BaseModel):
    name: str
    zone: str | None
    outcome: Literal[
        "cname", "a", "nodata", "nxdomain", "external", "loop", "too_long"
    ]
    target: str | None = None
    addresses: list[str] = Field(default_factory=list)


class QueryFaultChain(BaseModel):
    domain: str
    category: Literal[
        "missing_record", "cname_loop", "external_target", "chain_too_long"
    ]
    detail: str | None = None
    chain: str
    trace: list[QueryTraceStep]


class QueryResponse(BaseModel):
    mode: Literal["authoritative_no_cache"]
    query: QueryInfo
    edns: EdnsInfo
    udp_budget: UdpBudgetInfo
    assumptions: list[str]
    status: Literal["resolved", "broken"]
    status_meaning: str
    message: str
    fault_chain: QueryFaultChain | None = None
    answer_section: list[RRSetInfo]
    answer_addresses: list[str] = Field(default_factory=list)
    udp_overhead: int | None = None
    udp_budget_insufficient: bool
    full_response: FullResponse | None = None
    udp_response: UdpResponse | None = None
