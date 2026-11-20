"""Minimal authoritative DNS message encoder for the offline query API.

Only what the planner's cache-less resolver can produce is encoded: an
NOERROR answer (a chain of CNAMEs followed by the A RRset) reached through at
most ``MAX_CNAME_HOPS`` aliases.  Unresolvable queries are reported as fault
chains by the API rather than turned into negative responses here.  The
encoder is deliberately independent of any DNS library so the byte accounting
is explicit and testable.

Design points
-------------
* **Name compression** (RFC 1035 section 4.1.4) is applied to every owner name
  and to the RDATA of CNAME records.  A name is written literally the first
  time it occurs and as a 14-bit pointer to the earliest suffix match on any
  later occurrence (a pointer is 2 bytes, always shorter than the literal form
  of a non-empty suffix, which is at least 3 bytes).
* **EDNS(0)** (RFC 6891): when the request advertises a UDP payload size, an
  OPT pseudo-RR is added to the additional section of *every* response,
  including truncated ones.  The OPT owner name is the root and is never
  compressed.
* **Truncation** (RFC 2181 section 9): a UDP response carries whole RRsets
  only.  If the full answer does not fit the budget the message keeps the
  longest prefix of RRsets in resolution order that fits and sets TC.  The
  header, question and OPT are never dropped; when they alone do not fit the
  caller is told there is no UDP response (only the full TCP-style one).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .models import normalize_name

TYPE_A = 1
TYPE_CNAME = 5
TYPE_OPT = 41

CLASS_IN = 1

FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200

# OPT RDATA is empty: no extended options, no NSID, no cookie.
OPT_RDLEN = 0

MAX_UDP_PAYLOAD = 65535
# RFC 6891 recommends advertising 1232 bytes to survive common MTUs.  This is
# the server's own receive size, not the client's.
DEFAULT_SERVER_PAYLOAD = 1232

MAX_MESSAGE = 65535
MAX_LABEL = 63
MAX_NAME_WIRE = 255


class EncodingError(ValueError):
    """Raised when a name or record cannot be encoded."""


@dataclass
class RRSet:
    """Records that must appear in the message as a whole unit."""

    name: str
    rtype: int
    ttl: int
    values: list[str]

    @property
    def count(self) -> int:
        return len(self.values)


@dataclass
class Message:
    """An encoded DNS message plus the bookkeeping the API reports."""

    wire: bytes
    kept_rrsets: int = 0
    dropped_rrsets: int = 0


class _Writer:
    """Byte buffer that tracks name suffixes for compression pointers."""

    def __init__(self, compression: bool) -> None:
        self.buf = bytearray()
        self.suffixes: dict[str, int] = {}
        self.compression = compression

    def name(self, value: str) -> None:
        canonical = normalize_name(value)
        if not canonical:
            self.buf.append(0)
            return
        labels = canonical.split(".")
        wire_length = sum(len(label) + 1 for label in labels) + 1
        if wire_length > MAX_NAME_WIRE:
            raise EncodingError(f"name {value!r} exceeds 255 wire bytes")
        for index, label in enumerate(labels):
            suffix = ".".join(labels[index:])
            if self.compression:
                known = self.suffixes.get(suffix)
                if known is not None and known <= 0x3FFF:
                    self.buf += struct.pack("!H", 0xC000 | known)
                    return
            encoded = label.encode("ascii")
            if not encoded or len(encoded) > MAX_LABEL:
                raise EncodingError(f"cannot encode label {label!r} of {value!r}")
            # Only the first occurrence is useful as a pointer target, and only
            # offsets within the 14-bit pointer range can be referenced.
            if (
                self.compression
                and suffix not in self.suffixes
                and len(self.buf) <= 0x3FFF
            ):
                self.suffixes[suffix] = len(self.buf)
            self.buf.append(len(encoded))
            self.buf += encoded
        self.buf.append(0)

    def rr(self, rrset: RRSet) -> None:
        # An RRset is emitted as one RR per value: same owner, type, class and
        # TTL, each with its own RDLENGTH.  ANCOUNT counts these RRs, while
        # truncation keeps the whole set as an atomic unit.
        for value in rrset.values:
            self.name(rrset.name)
            self.buf += struct.pack(
                "!HHIH", rrset.rtype, CLASS_IN, rrset.ttl & 0x7FFFFFFF, 0
            )
            rdata_length_at = len(self.buf) - 2
            rdata_at = len(self.buf)
            if rrset.rtype == TYPE_A:
                try:
                    packed = bytes(int(part) for part in value.split("."))
                except (TypeError, ValueError) as exc:  # pragma: no cover
                    raise EncodingError(f"invalid IPv4 address {value!r}") from exc
                if len(packed) != 4:
                    raise EncodingError(f"invalid IPv4 address {value!r}")
                self.buf += packed
            elif rrset.rtype == TYPE_CNAME:
                self.name(value)
            else:  # pragma: no cover - resolver only yields A/CNAME
                raise EncodingError(f"unsupported RR type {rrset.rtype}")
            length = len(self.buf) - rdata_at
            struct.pack_into("!H", self.buf, rdata_length_at, length)

    def opt(self, payload: int, flags: int = 0) -> None:
        # Extended RCODE bits stay zero (NOERROR); flags carry DO=0 and the
        # reserved Z bits as zero.
        ttl = (flags & 0x7FFF) << 16
        # Root owner name, never compressed and never added to the dictionary.
        self.buf += b"\x00" + struct.pack("!HHIH", TYPE_OPT, payload, ttl, OPT_RDLEN)


@dataclass
class _Skeleton:
    qname: str
    qtype: int
    payload: int | None
    compression: bool

    def write(self, answers: list[RRSet], tc: bool) -> bytes:
        writer = _Writer(self.compression)
        flags = FLAG_QR | FLAG_AA | (FLAG_TC if tc else 0)
        ancount = sum(rrset.count for rrset in answers)
        arcount = 1 if self.payload is not None else 0
        writer.buf += struct.pack("!HHHHHH", 0, flags, 1, ancount, 0, arcount)
        writer.name(self.qname)
        writer.buf += struct.pack("!HH", self.qtype, CLASS_IN)
        for rrset in answers:
            writer.rr(rrset)
        if self.payload is not None:
            writer.opt(self.payload)
        return bytes(writer.buf)


def build_response(
    qname: str,
    qtype: int,
    answers: list[RRSet],
    *,
    payload: int | None = None,
    compression: bool = True,
    limit: int | None = None,
) -> Message:
    """Encode a response, truncating to whole RRsets if ``limit`` is given.

    ``limit`` is the UDP byte budget.  None encodes the untruncated message
    (the complete response).  ``payload`` is the EDNS UDP payload size to
    advertise; None means the request had no EDNS and no OPT is emitted.

    Raises ``EncodingError`` if the header + question + OPT alone exceed
    ``limit``; callers check :func:`fixed_overhead` first and then report
    insufficient budget instead of a UDP message.
    """
    if payload is not None and not 0 <= payload <= MAX_UDP_PAYLOAD:
        raise EncodingError(f"UDP payload {payload} out of range")
    skeleton = _Skeleton(
        qname=qname, qtype=qtype, payload=payload, compression=compression
    )
    full = skeleton.write(answers, tc=False)
    if len(full) > MAX_MESSAGE:
        raise EncodingError("response exceeds the 65535-byte DNS message limit")
    if limit is None or len(full) <= limit:
        return Message(wire=full, kept_rrsets=len(answers))

    accepted: list[RRSet] = []
    for rrset in answers:
        if len(skeleton.write(accepted + [rrset], tc=True)) <= limit:
            accepted.append(rrset)
        else:
            break
    wire = skeleton.write(accepted, tc=True)
    if len(wire) > limit:  # header+question+OPT alone do not fit
        raise EncodingError(
            "header, question and OPT do not fit in the UDP budget"
        )
    return Message(
        wire=wire,
        kept_rrsets=len(accepted),
        dropped_rrsets=len(answers) - len(accepted),
    )


def fixed_overhead(
    qname: str,
    qtype: int,
    *,
    payload: int | None,
    compression: bool = True,
) -> int:
    """Bytes used by the header, question and optional OPT with no answers."""
    return len(
        _Skeleton(
            qname=qname, qtype=qtype, payload=payload, compression=compression
        ).write([], tc=False)
    )
