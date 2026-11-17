from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CaseCreate(StrictModel):
    case_id: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)


class ScanRequest(StrictModel):
    evidence_id: str
    kind: Literal["file", "network"] = "file"
    model: Literal["xgboost", "iforest"] = "xgboost"
    split: Literal["random", "official"] = "random"
    threshold: float = Field(default=0.5, ge=0, le=1, allow_inf_nan=False)


class SearchRequest(StrictModel):
    query: str = Field(min_length=1, max_length=300)


class ReportRequest(StrictModel):
    evidence_id: str
    scan_id: str


class RootRequest(StrictModel):
    root_id: str


class MonitorRequest(StrictModel):
    root_ids: list[str] = Field(min_length=1, max_length=5)


class UrlRequest(StrictModel):
    url: str = Field(min_length=1, max_length=2048)


class Collection(BaseModel):
    items: list[dict[str, Any]]
    total: int
    page: int = 1
    page_size: int = 25


class JobView(BaseModel):
    id: str
    case_id: str
    status: str
    phase: str
    progress: dict[str, Any] | None = None
    result: Any = None
    error: str | None = None
    cancellable: bool
