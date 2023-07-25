from functools import lru_cache
from typing import Iterable

import psycopg2
from packageurl import PackageURL
from psycopg2.extensions import connection

from bomsquad.vulndb.config import config
from bomsquad.vulndb.model.openssf import OpenSSF


class OSVDB:
    @lru_cache
    def _db(self) -> connection:
        return psycopg2.connect(
            user=config.username, password=config.password, database=config.database
        )

    def find_by_purl(self, purl: PackageURL) -> Iterable[OpenSSF]:
        conn = self._db()
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

                yield OpenSSF.model_validate(data)
