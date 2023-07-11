from functools import lru_cache

import psycopg2
from psycopg2.extensions import connection

from bomsquad.vulndb.config import config
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE
from bomsquad.vulndb.model.openssf import OpenSSF


class DataStoreClient:
    @lru_cache
    def _db(self) -> connection:
        return psycopg2.connect(
            user=config.username, password=config.password, database=config.database
        )

    def insert_cve(self, cve: CVE) -> None:
        conn = self._db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO cve(data) values(%s)", [cve.json()])
        if cursor.rowcount < 1:
            raise RuntimeError("Database did not register insertion")
        conn.commit()

    def insert_cpe(self, cpe: CPE) -> None:
        conn = self._db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO cpe(data) values(%s)", [cpe.json()])
        if cursor.rowcount < 1:
            raise RuntimeError("Database did not register insertion")
        conn.commit()

    def insert_osv(self, ecosystem: str, openssf: OpenSSF) -> None:
        conn = self._db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO osv(ecosystem, data) values(%s, %s)", [ecosystem, openssf.json()]
        )
        if cursor.rowcount < 1:
            raise RuntimeError("Database did not register insertion")
        conn.commit()
