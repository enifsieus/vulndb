import logging
from functools import cached_property
from typing import Any
from typing import Dict
from typing import Iterable

import psycopg2
from packageurl import PackageURL
from psycopg2.extensions import connection

from bomsquad.vulndb.config import config
from bomsquad.vulndb.db.error import InvalidDataError
from bomsquad.vulndb.model.openssf import OpenSSF

logger = logging.getLogger(__name__)


class OSVDB:
    @cached_property
    def _db(self) -> connection:
        return psycopg2.connect(
            user=config.username, password=config.password, database=config.database
        )

    def upsert(self, ecosystem: str, openssf: OpenSSF) -> None:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM osv WHERE ecosystem = %s AND data->'id' ? %s", [ecosystem, str(openssf.id)]
        )
        cursor.execute(
            "INSERT INTO osv(ecosystem, data) values(%s, %s)", [ecosystem, openssf.json()]
        )
        if cursor.rowcount < 1:
            raise RuntimeError("Database did not register insertion")
        conn.commit()

    def _materialize_openssf(self, data: Dict[Any, Any]) -> OpenSSF:
        from pydantic import ValidationError

        try:
            return OpenSSF.model_validate(data)
        except ValidationError as ve:
            raise InvalidDataError(ve, data)

    def find_by_purl(self, purl: PackageURL) -> Iterable[OpenSSF]:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                DISTINCT data->'id' AS id, data
            FROM osv,jsonb_array_elements(data->'affected') AS affected
            WHERE data @@ %s;
            """,
            [f'$.affected[*].package.purl == "{purl.to_string()}"'],
        )
        while results := cursor.fetchmany(64):
            for row in results:
                _, data = row

                yield self._materialize_openssf(data)

    def ecosystems(self) -> Iterable[str]:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute("SELECT distinct ecosystem FROM osv")
        for row in cursor.fetchall():
            (ecosystem,) = row
            yield ecosystem

    def all(self) -> Iterable[OpenSSF]:
        for ecosystem in self.ecosystems():
            yield from self.all_from_ecosystem(ecosystem)

    def all_from_ecosystem(self, ecossytem: str) -> Iterable[OpenSSF]:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute("SELECT data FROM osv WHERE ecosystem = %s")
        while results := cursor.fetchmany(256):
            for row in results:
                (data,) = row
                yield self._materialize_openssf(data)

    def find_by_id_or_alias(self, id: str) -> Iterable[OpenSSF]:
        conn = self._db
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                DISTINCT data->'id', data
            FROM osv, jsonb_array_elements(data->'aliases') AS alias
            WHERE data->'id' ? %s OR alias ? %s
            """,
            [id, id],
        )
        for row in cursor.fetchall():
            _, data = row
            yield self._materialize_openssf(data)


instance = OSVDB()
