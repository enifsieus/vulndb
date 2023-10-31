from datetime import datetime
from functools import cached_property
from typing import Any
from typing import cast
from typing import Dict
from typing import Iterable
from typing import Optional

import psycopg2
from psycopg2.extensions import connection

from bomsquad.vulndb.config import config
from bomsquad.vulndb.db.error import InvalidDataError
from bomsquad.vulndb.db.error import RecordNotFoundError
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE


class NVDDB:
    @cached_property
    def _db(self) -> connection:
        return psycopg2.connect(
            user=config.username, password=config.password, database=config.database
        )

    def upsert_cve(self, cve: CVE) -> None:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cve WHERE data->'id' ? %s", [cve.id])
        cursor.execute("INSERT INTO cve(data) values(%s)", [cve.json()])
        if cursor.rowcount < 1:
            raise RuntimeError("Database did not register insertion")
        conn.commit()

    def upsert_cpe(self, cpe: CPE) -> None:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cpe WHERE data->'cpeNameId' ? %s", [str(cpe.cpeNameId)])
        cursor.execute("INSERT INTO cpe(data) values(%s)", [cpe.json()])
        if cursor.rowcount < 1:
            raise RuntimeError("Database did not register insertion")
        conn.commit()

    def cve_last_modified(self) -> Optional[datetime]:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT (data->>'lastModified')::timestamp with time zone AS timestamp from cve ORDER BY timestamp DESC limit 1;
            """
        )
        if cursor.rowcount < 1:
            return None
        (timestamp,) = cursor.fetchone()
        return cast(datetime, timestamp)

    def cpe_last_modified(self) -> Optional[datetime]:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT (data->>'lastModified')::timestamp with time zone AS timestamp from cpe ORDER BY timestamp DESC limit 1;
            """
        )
        if cursor.rowcount < 1:
            return None
        (timestamp,) = cursor.fetchone()
        return cast(datetime, timestamp)

    def _materialize_cve(self, data: Dict[Any, Any]) -> CVE:
        from pydantic import ValidationError

        try:
            return CVE.model_validate(data)
        except ValidationError as ve:
            raise InvalidDataError(ve, data)

    def _materialize_cpe(self, data: Dict[Any, Any]) -> CPE:
        from pydantic import ValidationError

        try:
            return CPE.model_validate(data)
        except ValidationError as ve:
            raise InvalidDataError(ve, data)

    def cve_by_id(self, id: str) -> CVE:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT data FROM cve WHERE data->'id' ? %s
            """,
            [id],
        )
        if cursor.rowcount == 0:
            raise RecordNotFoundError(f"No such CVE for id {id}")

        (data,) = cursor.fetchone()
        return self._materialize_cve(data)

    def cve_all(self) -> Iterable[CVE]:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute("SELECT data FROM cve")
        while results := cursor.fetchmany(256):
            for row in results:
                (data,) = row
                yield self._materialize_cve(data)

    def cpe_all(self) -> Iterable[CPE]:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute("SELECT data FROM cpe")
        while results := cursor.fetchmany(256):
            for row in results:
                (data,) = row
                yield self._materialize_cpe(data)


instance = NVDDB()
