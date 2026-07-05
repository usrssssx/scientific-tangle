from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field

Role = Literal["external_partner", "researcher", "analyst", "manager", "admin"]
AnswerMode = Literal["auto", "review", "comparison", "protocol", "gap_analysis", "evidence_table"]
ExportApprovalFormat = Literal["markdown", "csv", "pdf", "zip", "jsonld", "rdf"]


class NumericFilter(BaseModel):
    property: str
    comparator: str = Field(default="<=", examples=["<=", ">=", "=", "between"])
    value: float | None = None
    min_value: float | None = None
    max_value: float | None = None
    unit: str | None = None


class SearchRequest(BaseModel):
    query: str
    answer_mode: AnswerMode = "auto"
    material: list[str] | None = None
    process: list[str] | None = None
    geography: list[str] | None = None
    year_from: int | None = None
    year_to: int | None = None
    min_confidence: float = 0.0
    include_internal: bool = True
    numeric_filters: list[NumericFilter] = Field(default_factory=list)
    strict_numeric_filters: bool = False
    top_k: int = 10


class IngestMetadata(BaseModel):
    title: str | None = None
    source_type: str = "uploaded_document"
    language: str | None = None
    geography: str | None = None
    year: int | None = None
    reliability_score: float = 0.55
    confidentiality: str = "internal"


class GraphRequest(BaseModel):
    entity: str
    depth: int = Field(default=2, ge=1, le=4)
    limit: int = Field(default=60, ge=1, le=500)


class AnswerResponse(BaseModel):
    query: str
    parsed_query: dict[str, Any]
    answer_markdown: str
    confidence: float
    sources: list[dict[str, Any]]
    facts: list[dict[str, Any]]
    experiments: list[dict[str, Any]]
    experts: list[dict[str, Any]]
    gaps: list[str]
    contradictions: list[dict[str, Any]]


class FactReviewRequest(BaseModel):
    action: Literal["verify", "reject", "comment", "mark_contradicted", "mark_superseded"]
    comment: str | None = None
    reviewer: str = "demo-expert"


class BulkFactReviewRequest(FactReviewRequest):
    fact_ids: list[int] = Field(min_length=1, max_length=500)


class FactAssignmentRequest(BaseModel):
    fact_ids: list[int] = Field(min_length=1, max_length=500)
    assignee: str
    reviewer: str = "demo-expert"
    due_at: str | None = None
    comment: str | None = None


class FactAssignmentReleaseRequest(BaseModel):
    fact_ids: list[int] = Field(min_length=1, max_length=500)
    reviewer: str = "demo-expert"
    comment: str | None = None


class FactSupersedeRequest(BaseModel):
    replacement_fact_id: int
    reviewer: str = "demo-expert"
    comment: str | None = None


DisputeSeverity = Literal["low", "medium", "high", "critical"]
DisputeResolutionStatus = Literal["candidate", "verified", "rejected", "contradicted", "superseded"]


class FactDisputeRequest(BaseModel):
    reason: str = Field(min_length=1)
    severity: DisputeSeverity = "medium"
    reviewer: str = "demo-expert"
    assignee: str | None = None
    due_at: str | None = None
    comment: str | None = None


class FactDisputeCommentRequest(BaseModel):
    author: str = "demo-expert"
    comment: str = Field(min_length=1)


class FactDisputeEscalateRequest(BaseModel):
    reviewer: str = "demo-expert"
    assignee: str | None = None
    comment: str | None = None


class FactDisputeResolveRequest(BaseModel):
    reviewer: str = "demo-expert"
    resolution: str = Field(min_length=1)
    fact_status: DisputeResolutionStatus | None = None


class EntityMergeRequest(BaseModel):
    survivor_id: int
    duplicate_id: int
    comment: str | None = None
    reviewer: str = "demo-expert"


class EntitySplitRequest(BaseModel):
    source_entity_id: int
    new_type: str
    new_name: str
    aliases: list[str] = Field(default_factory=list)
    move_fact_ids: list[int] = Field(default_factory=list)
    move_edge_ids: list[int] = Field(default_factory=list)
    comment: str | None = None
    reviewer: str = "demo-expert"


class ExportApprovalRequest(BaseModel):
    export_format: ExportApprovalFormat
    query: str | None = None
    top_k: int = Field(default=10, ge=1, le=100)
    answer_mode: AnswerMode | None = None
    requester: str = "demo-user"
    justification: str = Field(min_length=1)
    expires_at: str | None = None


class ExportApprovalReviewRequest(BaseModel):
    reviewer: str = "security-admin"
    comment: str | None = None
    expires_at: str | None = None
