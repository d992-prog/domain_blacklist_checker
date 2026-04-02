from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class CheckRequest(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=10_000)


class JobResponse(BaseModel):
    job_id: str
    status: str
    total_domains: int


class SourceResult(BaseModel):
    source: str
    listed: bool
    reason: str | None = None
    listed_since: datetime | None = None
    category: str | None = None
    severity: str | None = None


class LumenNotice(BaseModel):
    title: str
    notice_type: str
    sender: str | None = None
    date: datetime | None = None
    description: str | None = None


class LumenSummary(BaseModel):
    status: Literal["ok", "unknown"]
    total_notices: int
    trend: str | None = None
    notices: list[LumenNotice]
    note: str | None = None


class SafeBrowsingSummary(BaseModel):
    status: Literal["safe", "malware", "phishing", "unwanted", "unknown"]
    note: str | None = None


class EmailAuthSummary(BaseModel):
    spf: Literal["pass", "fail", "none"]
    dkim: Literal["pass", "fail", "none"]
    dmarc: Literal["pass", "fail", "none"]
    note: str | None = None


class ProviderSummary(BaseModel):
    name: str
    status: str
    listed: bool | None = None
    note: str | None = None


class DomainReportResponse(BaseModel):
    domain: str
    overall_status: Literal["clean", "warning", "listed"]
    risk_score: int
    blacklists: list[SourceResult]
    lumen: LumenSummary
    safe_browsing: SafeBrowsingSummary
    email_auth: EmailAuthSummary
    providers: list[ProviderSummary]
    recommendations: list[str]
    checked_at: datetime


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    total_domains: int
    completed_domains: int
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    last_error: str | None = None
    reports: list[DomainReportResponse]


class JobReportBundle(BaseModel):
    job_id: str
    status: str
    summary: dict
    reports: list[DomainReportResponse]


class HistoryItem(BaseModel):
    id: int
    job_id: str
    domain: str
    overall_status: str
    risk_score: int
    checked_at: datetime


class WebhookRequest(BaseModel):
    url: HttpUrl
    events: list[str] = Field(min_length=1)


class WebhookResponse(BaseModel):
    id: int
    url: HttpUrl
    events: list[str]
    created_at: datetime
