"""Detection rule schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.enums import IOCType, Severity
from app.schemas.common import ORMModel


class DetectionRuleRead(ORMModel):
    id: uuid.UUID
    rule_key: str
    name: str
    description: str
    severity: Severity
    enabled: bool
    config: dict[str, Any]
    mitre_tactic: str | None
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    updated_at: datetime


class DetectionRuleDetail(DetectionRuleRead):
    # What the code currently defaults to, so an operator can see how far a
    # tuned value has drifted and reset it deliberately.
    default_config: dict[str, Any]
    implemented: bool


class DetectionRuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: Severity | None = None
    config: dict[str, Any] | None = None


class IOCRead(ORMModel):
    id: uuid.UUID
    ioc_type: IOCType
    value: str
    description: str
    active: bool
    added_by_email: str | None
    created_at: datetime


class IOCCreate(BaseModel):
    ioc_type: IOCType
    value: str = Field(min_length=1, max_length=512)
    description: str = Field(default="", max_length=2000)


class IOCUpdate(BaseModel):
    active: bool | None = None
    description: str | None = Field(default=None, max_length=2000)
