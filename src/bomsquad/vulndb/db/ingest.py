import logging
from datetime import datetime
from typing import Optional

from bomsquad.vulndb.client.nvd import NVD
from bomsquad.vulndb.client.osv import OSV
from bomsquad.vulndb.db.nvddb import NVDDB
from bomsquad.vulndb.db.osvdb import OSVDB

logger = logging.getLogger(__name__)


class Ingest:
    @classmethod
    def cve(
        cls,
        offset: int = 0,
        limit: Optional[int] = None,
        last_mod_start_date: Optional[datetime] = None,
    ) -> None:
        db = NVDDB()
        api = NVD()
        for cve in api.vulnerabilities(offset, last_mod_start_date=last_mod_start_date):
            db.upsert_cve(cve)

    @classmethod
    def cpe(
        cls,
        offset: int = 0,
        limit: Optional[int] = None,
        last_mod_start_date: Optional[datetime] = None,
    ) -> None:
        db = NVDDB()
        api = NVD()
        for cpe in api.products(offset, last_mod_start_date=last_mod_start_date):
            db.upsert_cpe(cpe)

    @classmethod
    def all_osv(cls) -> None:
        for ecosystem in OSV.ECOSYSTEMS:
            logger.info(f"Ingesting {ecosystem}")
            cls.osv(ecosystem)
            logger.info(f"{ecosystem} complete")

    @classmethod
    def osv(cls, ecosystem: str, offset: int = 0, limit: Optional[int] = None) -> None:
        db = OSVDB()
        api = OSV()
        for openssf in api.all(ecosystem):
            db.upsert(ecosystem, openssf)
