import logging

import typer
from packageurl import PackageURL
from rich import box
from rich.console import Console
from rich.table import Table

from bomsquad.vulndb.db.osvdb import OSVDB
from bomsquad.vulndb.matcher.purl import PURLMatcher
from bomsquad.vulndb.model.spec import Spec

logger = logging.getLogger(__name__)

console = Console(record=True)

purl_app = typer.Typer(name="purl")


@purl_app.command(name="lookup")
def _lookup(target: str = typer.Argument()) -> None:
    purl = PackageURL.from_string(target)
    osvdb = OSVDB()

    vtab = Table(
        title=f"Vulnerabilities for purl {purl.to_string()}", box=box.HORIZONTALS, show_lines=True
    )
    vtab.add_column("id")
    vtab.add_column("aliases")
    vtab.add_column("affected")

    basic_purl = PURLMatcher.simplify(purl)
    for osv in osvdb.find_by_purl(basic_purl):
        if PURLMatcher.is_affected(purl, osv) is False:
            continue

        aliases_tab = Table(box=None, show_header=False)
        aliases_tab.add_column("alias")

        for alias in osv.aliases:
            aliases_tab.add_row(alias)

        affected_tab = Table(box=None, show_header=False)
        affected_tab.add_column("version")
        for affected in osv.affected:
            if affected.package and affected.package.purl == basic_purl.to_string():
                for version in affected.versions:
                    affected_tab.add_row(f"version: {version}")
                for range in affected.ranges:
                    affected_tab.add_row(f"range: {Spec.range(range)}")
        vtab.add_row(osv.id, aliases_tab, affected_tab)

    console.print(vtab)
