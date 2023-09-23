import logging
from dataclasses import dataclass
from typing import Dict
from typing import Set
from typing import Tuple

import typer
from packageurl import PackageURL
from rich import box
from rich.console import Console
from rich.table import Table
from univers.version_range import VersionRange

from bomsquad.vulndb.db.osvdb import OSVDB
from bomsquad.vulndb.matcher.factory import VersionRangeFactory

logger = logging.getLogger(__name__)

console = Console(record=True)
cve_app = typer.Typer(name="cve")


@dataclass
class _AffectedPURL:
    purl: PackageURL
    ids: Set[str]
    versions: Set[str]

    def add_id(self, id: str) -> None:
        self.ids.add(id)

    def add_version(self, version: VersionRange) -> None:
        self.versions.add(version.to_string())

    def to_row(self) -> Tuple[str, Table, Table]:
        itab = Table(box=None, show_header=False)
        itab.add_column("ids")
        vtab = Table(box=None, show_header=False)
        vtab.add_column("versions")
        for i in self.ids:
            itab.add_row(i)
        for v in self.versions:
            vtab.add_row(v)
        return (self.purl.to_string(), itab, vtab)

    @classmethod
    def for_purl(self, purl: str) -> "_AffectedPURL":
        return _AffectedPURL(PackageURL.from_string(purl), set(), set())


@cve_app.command(name="affected-purls")
def _affected_purls(id: str = typer.Argument()) -> None:
    osvdb = OSVDB()

    atab = Table(title=f"Affected packages for {id}", box=box.HORIZONTALS, show_lines=True)
    atab.add_column("Package")
    atab.add_column("Identifiers")
    atab.add_column("Version(s)")

    by_purl: Dict[str, _AffectedPURL] = {}
    for osv in osvdb.find_by_id_or_alias(id):
        for affected in osv.affected:
            if affected.package and affected.package.purl:
                entry: _AffectedPURL
                if affected.package.purl not in by_purl.keys():
                    entry = _AffectedPURL.for_purl(affected.package.purl)
                    by_purl[affected.package.purl] = entry
                else:
                    entry = by_purl[affected.package.purl]
                entry.add_id(osv.id)
                for alias in osv.aliases:
                    entry.add_id(alias)

                for range in affected.ranges:
                    entry.add_version(
                        VersionRangeFactory.for_osv_affected_package_range(entry.purl, range)
                    )

    for purl, entry in by_purl.items():
        purl, ids, versions = entry.to_row()
        atab.add_row(purl, ids, versions)

    console.print(atab)
