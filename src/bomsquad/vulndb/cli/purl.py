import logging

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from bomsquad.vulndb.view.purl_vulnerabilities import query as vulnerabilities

logger = logging.getLogger(__name__)

console = Console(record=True)

purl_app = typer.Typer(name="purl")


@purl_app.command(name="lookup")
def _lookup(target: str = typer.Argument()) -> None:
    vtab = Table(title=f"Vulnerabilities for purl {target}", box=box.HORIZONTALS, show_lines=True)
    vtab.add_column("id")
    vtab.add_column("aliases")
    vtab.add_column("affected")

    for vuln in vulnerabilities.by_purl(target):
        alias_tab = Table(box=None, show_header=False)
        alias_tab.add_column("alias")

        for alias in vuln.aliases:
            alias_tab.add_row(alias)

        affected_tab = Table(box=None, show_header=False)
        affected_tab.add_column("version")

        for version in vuln.affected_versions:
            affected_tab.add_row(f"version: {version}")
        for range in vuln.affected_version_ranges:
            affected_tab.add_row(f"range: {range}")

        vtab.add_row(vuln.id, alias_tab, affected_tab)

    console.print(vtab)
