from functools import lru_cache
from typing import Optional

import psycopg2
from psycopg2.extensions import connection

from bomsquad.vulndb.config import config


class Query:
    @lru_cache
    def _db(self) -> connection:
        return psycopg2.connect(
            user=config.username, password=config.password, database=config.database
        )

    def join_purl_cve(self, ecosystem: str) -> None:
        conn = self._db()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT data->'id', affected->'package'->'purl', jsonb_array_elements(data->'aliases') as alias
                FROM osv, jsonb_array_elements(data->'affected')
                AS affected WHERE ecosystem = %s
            """,
            [ecosystem],
        )
        while results := cursor.fetchmany(64):
            for row in results:
                id, purl, alias = row
                print(f"{id} | {purl} | {alias}")
                cve_id: Optional[str] = None
                vulnerable: Optional[bool] = None
                criteria: Optional[str] = None
                cve_cursor = conn.cursor()
                cve_cursor.execute(
                    "SELECT data -> 'id' AS id,cpeMatch->'vulnerable' AS vulnerable, cpeMatch->'criteria' AS criteria FROM cve, jsonb_array_elements(data->'configurations') as config, jsonb_array_elements(config->'nodes') AS node,jsonb_array_elements(node->'cpeMatch') as cpeMatch WHERE data->>'id' = %s",
                    [alias],
                )
                if cve_cursor.rowcount > 0:
                    cve_id, vulnerable, criteria = cve_cursor.fetchone()
                print(f"{id} | {alias} | {purl} | {cve_id} | {vulnerable} | {criteria}")
