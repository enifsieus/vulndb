from datetime import datetime
from enum import Enum
from typing import Dict
from typing import List
from typing import Optional
from uuid import UUID

from pydantic import BaseModel

from bomsquad.vulndb.model.cvss20 import CVSS20
from bomsquad.vulndb.model.cvss30 import CVSS30
from bomsquad.vulndb.model.cvss31 import CVSS31


class CVEStatus(str, Enum):
    RECEIVED = "Received"
    AWAITING_ANALYSIS = "Awaiting Analysis"
    UNDERGOING_ANALYSIS = "Undergoing Analysis"
    ANALYZED = "Analyzed"
    MODIFIED = "Modified"
    DEFERRED = "Deferred"
    REJECTED = "Rejected"


class Ordinal(str, Enum):
    PRIMARY = "Primary"
    SECONDARY = "Secondary"


class CVSSv2(BaseModel):
    source: str
    type: Ordinal
    cvssData: CVSS20
    baseSeverity: str
    exploitabilityScore: float
    impactScore: float
    acInsufInfo: Optional[bool] = None
    obtainAllPrivilege: Optional[bool] = None
    obtainUserPrivilege: Optional[bool] = None
    obtainOtherPrivilege: Optional[bool] = None
    userInteractionRequired: Optional[bool] = None


class CVSSv30(BaseModel):
    source: str
    type: Ordinal
    cvssData: CVSS30
    exploitabilityScore: Optional[float] = None
    impactScore: Optional[float] = None


class CVSSv31(BaseModel):
    source: str
    type: Ordinal
    cvssData: CVSS31
    exploitabilityScore: Optional[float] = None
    impactScore: Optional[float]


class Metrics(BaseModel):
    cvssMetricV2: List[CVSSv2] = []
    cvssMetricV30: List[CVSSv30] = []
    cvssMetricV31: List[CVSSv31] = []


class Weakness(BaseModel):
    source: str
    type: str
    description: List[Dict[str, str]] = []


class Operator(str, Enum):
    AND = "AND"
    OR = "OR"


class CPEMatch(BaseModel):
    vulnerable: bool
    criteria: str
    matchCriteriaId: UUID
    versionStartExcluding: str = "*"
    versionStartIncluding: str = "*"
    versionEndExcluding: str = "*"
    versionEndIncluding: str = "*"


class Node(BaseModel):
    operator: Optional[Operator] = None
    negate: bool = False
    cpeMatch: List[CPEMatch] = []


class Config(BaseModel):
    operator: Optional[Operator] = None
    negate: Optional[bool] = False
    nodes: List[Node]


class Reference(BaseModel):
    url: Optional[str] = None
    source: Optional[str] = None
    tags: Optional[List[str]] = None


class VendorComment(BaseModel):
    organization: str
    comment: str
    lastModified: datetime


class CVE(BaseModel):
    id: str
    sourceIdentifier: str
    published: datetime
    lastModified: datetime
    vulnStatus: CVEStatus
    descriptions: List[Dict[str, str]] = []
    metrics: Metrics
    weaknesses: List[Weakness] = []
    configurations: List[Config] = []
    references: List[Reference] = []
    vendorComments: List[VendorComment] = []
