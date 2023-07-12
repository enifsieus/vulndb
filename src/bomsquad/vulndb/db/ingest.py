import logging
from typing import Optional

from bomsquad.vulndb.client.nvd import NVD
from bomsquad.vulndb.client.osv import OSV
from bomsquad.vulndb.db.client import DataStoreClient

logger = logging.getLogger(__name__)


class Ingest:
    @classmethod
    def cve(cls, offset: int = 0, limit: Optional[int] = None) -> None:
        store = DataStoreClient()
        api = NVD()
        for cve in api.vulnerabilities(offset):
            store.insert_cve(cve)

    @classmethod
    def cpe(cls, offset: int = 0, limit: Optional[int] = None) -> None:
        store = DataStoreClient()
        api = NVD()
        for cpe in api.products(offset):
            store.insert_cpe(cpe)

    @classmethod
    def all_osv(cls) -> None:
        for ecosystem in OSV.ECOSYSTEMS:
            logger.info(f"Ingesting {ecosystem}")
            cls.osv(ecosystem)
            logger.info(f"{ecosystem} complete")

    @classmethod
    def osv(cls, ecosystem: str, offset: int = 0, limit: Optional[int] = None) -> None:
        store = DataStoreClient()
        api = OSV()
        for openssf in api.all(ecosystem):
            store.insert_osv(ecosystem, openssf)
