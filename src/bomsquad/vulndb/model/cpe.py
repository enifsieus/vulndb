from datetime import datetime
from enum import Enum
from typing import List
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class Title(BaseModel):
    lang: str
    title: str


class ReferenceType(str, Enum):
    ADVISORY = "Advisory"
    CHANGE_LOG = "Change Log"
    PRODUCT = "Product"
    PROJECT = "Project"
    VENDOR = "Vendor"
    VERSION = "Version"


class Reference(BaseModel):
    type: Optional[ReferenceType]
    ref: str


class CPERef(BaseModel):
    cpeName: str
    cpeNameId: UUID


class CPE(BaseModel):
    deprecated: bool
    cpeName: str
    cpeNameId: UUID
    lastModified: datetime
    created: datetime
    titles: List[Title]
    refs: List[Reference] = []
    deprecatedBy: List[CPERef] = []
    deprecates: List[CPERef] = []
