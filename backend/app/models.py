from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class EvidenceStatus(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    DERIVED = "DERIVED"
    CONFIGURED = "CONFIGURED"
    MODEL_PREDICTED = "MODEL_PREDICTED"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"
    UNKNOWN = "UNKNOWN"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class EvidenceItem(BaseModel):
    packet: int | None = None
    field: str | None = None
    payload: str | None = None
    detail: str | None = None


ValueT = TypeVar("ValueT")


class EvidenceValue(BaseModel, Generic[ValueT]):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    value: ValueT | None = None
    status: EvidenceStatus
    source: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    reason: str | None = None


class CaptureMetadata(BaseModel):
    capture_id: str
    filename: str
    content_type: str | None = None
    size_bytes: int = Field(ge=0)
    sha256: str
    format: str = "UNKNOWN"
    packet_count: int | None = Field(default=None, ge=0)
    created_at: str


class CaptureSummary(CaptureMetadata):
    analysis_status: str = "NOT_STARTED"


class AnalysisJob(BaseModel):
    job_id: str
    capture_id: str
    status: str
    progress: int = Field(ge=0, le=100)
    message: str
    created_at: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class ErrorResponse(BaseModel):
    detail: str


class AnalysisPlaceholder(BaseModel):
    capture_id: str
    status: str
    message: str
    protocol_analysis: dict[str, Any] = Field(default_factory=dict)


class ParserIssue(BaseModel):
    packet: int | None = None
    detail: str


class ParsedPacket(BaseModel):
    number: int
    timestamp: float
    length: int = Field(ge=0)
    protocol: str
    source_ip: str | None = None
    destination_ip: str | None = None
    ip_version: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    spi: str | None = None
    sequence: int | None = Field(default=None, ge=0)
    ike_version: str | None = None
    exchange_type: int | None = None
    nat_t: bool = False
    info: str
    raw_preview: str
    ike: "IKEMessage | None" = None


class ProtocolSummary(BaseModel):
    counts: dict[str, int] = Field(default_factory=dict)


class IKETransform(BaseModel):
    transform_type: int
    transform_id: int
    name: str | None = None
    attributes: dict[int, int | str] = Field(default_factory=dict)
    packet: int
    status: EvidenceStatus = EvidenceStatus.OBSERVED


class TrafficSelector(BaseModel):
    selector_type: int
    ip_protocol: int
    start_port: int
    end_port: int
    start_address: str
    end_address: str
    packet: int
    status: EvidenceStatus = EvidenceStatus.OBSERVED


class IKEProposal(BaseModel):
    proposal_number: int
    protocol_id: int
    spi: str | None = None
    transforms: list[IKETransform] = Field(default_factory=list)
    packet: int
    status: EvidenceStatus = EvidenceStatus.OBSERVED


class IKEMessage(BaseModel):
    initiator_spi: str
    responder_spi: str
    version: str
    next_payload: int
    exchange_type: int
    flags: int
    message_id: int
    length: int
    payload_types: list[int] = Field(default_factory=list)
    proposals: list[IKEProposal] = Field(default_factory=list)
    traffic_selectors_i: list[TrafficSelector] = Field(default_factory=list)
    traffic_selectors_r: list[TrafficSelector] = Field(default_factory=list)
    encrypted_payload: bool = False
    fragmented: bool = False
    fragment_number: int | None = Field(default=None, ge=1)
    fragment_total: int | None = Field(default=None, ge=1)
    packet: int
    status: EvidenceStatus = EvidenceStatus.OBSERVED


class CaptureAnalysis(BaseModel):
    format: str
    link_type: int
    packet_count: int = Field(ge=0)
    packets: list[ParsedPacket] = Field(default_factory=list)
    protocol_summary: ProtocolSummary
    issues: list[ParserIssue] = Field(default_factory=list)
    ike_sas: list["IKESecurityAssociation"] = Field(default_factory=list)
    child_sas: list["ChildSA"] = Field(default_factory=list)
    esp_flows: list["ESPFlow"] = Field(default_factory=list)
    events: list["IKEEvent"] = Field(default_factory=list)
    security: "SecurityAssessment | None" = None
    limitations: list[str] = Field(default_factory=list)


class ChildSA(BaseModel):
    spi: str | None = None
    initiator_spi: str | None = None
    responder_spi: str | None = None
    protocol: str
    proposal_packet: int
    ike_sa_key: str
    transforms: list[IKETransform] = Field(default_factory=list)
    offered_transforms: list[IKETransform] = Field(default_factory=list)
    selected_transforms: list[str] = Field(default_factory=list)
    pfs: bool | None = None
    lifetime_seconds: int | None = Field(default=None, ge=0)
    esn: bool | None = None
    proposal_role: str = "UNKNOWN"
    esp_packet_numbers: list[int] = Field(default_factory=list)
    traffic_selectors_i: list[TrafficSelector] = Field(default_factory=list)
    traffic_selectors_r: list[TrafficSelector] = Field(default_factory=list)
    lifecycle: str = "OBSERVED"
    direction: str = "UNKNOWN"
    status: EvidenceStatus
    evidence: list[EvidenceItem] = Field(default_factory=list)
    reason: str | None = None


class IKESecurityAssociation(BaseModel):
    key: str
    initiator_spi: str
    responder_spi: str
    version: str
    message_packets: list[int] = Field(default_factory=list)
    child_sa_indexes: list[int] = Field(default_factory=list)
    initiator_endpoint: str | None = None
    responder_endpoint: str | None = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED


class ESPFlow(BaseModel):
    spi: str
    packet_numbers: list[int] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    status: EvidenceStatus
    child_sa_index: int | None = None
    direction: str = "UNKNOWN"
    reason: str | None = None


class ESPSequenceAnalysis(BaseModel):
    spi: str
    packet_numbers: list[int] = Field(default_factory=list)
    sequences: list[int] = Field(default_factory=list)
    duplicate_sequences: list[int] = Field(default_factory=list)
    gaps: list[int] = Field(default_factory=list)
    out_of_order: bool = False
    max_forward_jump: int = 0
    status: EvidenceStatus
    evidence: list[EvidenceItem] = Field(default_factory=list)
    reason: str | None = None


class SecurityFinding(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    penalty: int = Field(ge=0)
    status: EvidenceStatus
    confidence: float = Field(ge=0, le=1)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    impact: str
    recommendation: str


class SecurityAssessment(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    evidence_coverage: float = Field(ge=0, le=1)
    findings: list[SecurityFinding] = Field(default_factory=list)
    sequence_analysis: list[ESPSequenceAnalysis] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class IKEEvent(BaseModel):
    packet: int
    exchange_type: int
    name: str
    ike_sa_key: str
    status: EvidenceStatus = EvidenceStatus.OBSERVED
