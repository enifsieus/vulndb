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
    acInsufInfo: Optional[bool]
    obtainAllPrivilege: Optional[bool]
    obtainUserPrivilege: Optional[bool]
    obtainOtherPrivilege: Optional[bool]
    userInteractionRequired: Optional[bool]


class CVSSv30(BaseModel):
    source: str
    type: Ordinal
    cvssData: CVSS30
    exploitabilityScore: Optional[float]
    impactScore: Optional[float]


class CVSSv31(BaseModel):
    source: str
    type: Ordinal
    cvssData: CVSS31
    exploitabilityScore: Optional[float]
    impactScore: Optional[float]


class Metrics(BaseModel):
    cvssMetricV2: List[CVSSv2] = []
    cvssMetricV30: List[CVSSv30] = []
    cvssMetricV31: List[CVSSv31] = []


class Weakness(BaseModel):
    source: str
    type: str
    description: Dict[str, str]


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
    operator: Operator
    negate: bool = False
    cpeMatch: List[CPEMatch] = []


class Config(BaseModel):
    operator: Optional[Operator]
    negate: bool = False
    nodes: List[Node]


class Reference(BaseModel):
    url: str
    source: Optional[str]
    tags: Optional[List[str]]


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
    descriptions: Dict[str, str]
    metrics: Metrics
    weaknesses: List[Weakness] = []
    configurations: List[Config] = []
    references: List[Reference] = []
    vendorComments: List[VendorComment] = []
