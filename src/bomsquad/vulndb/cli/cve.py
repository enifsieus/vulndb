import logging

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from bomsquad.vulndb.db.nvddb import instance as nvddb
from bomsquad.vulndb.view.affected_purls import query as affected_purls

logger = logging.getLogger(__name__)

console = Console(record=True)
cve_app = typer.Typer(name="cve")


@cve_app.command(name="affected-purls")
def _affected_purls(id: str = typer.Argument()) -> None:
    atab = Table(title=f"Affected packages for {id}", box=box.HORIZONTALS, show_lines=True)
    atab.add_column("Package")
    atab.add_column("Identifiers")
    atab.add_column("Version(s)")

    for affected in affected_purls.by_id(id):
        itab = Table(box=None, show_header=False)
        itab.add_column("ids")
        vtab = Table(box=None, show_header=False)
        vtab.add_column("versions")
        for i in affected.ids:
            itab.add_row(i)
        for v in affected.versions:
            vtab.add_row(v)
        atab.add_row(affected.purl.to_string(), itab, vtab)

    console.print(atab)


@cve_app.command(name="lookup")
def _lookup(id: str = typer.Argument()) -> None:
    cve = nvddb.cve_by_id(id)

    table = Table(title=cve.id, box=box.HORIZONTALS, show_lines=True, show_header=False)

    table.add_column("Field")
    table.add_column("Value")

    table.add_row("Source", cve.sourceIdentifier)
    table.add_row("Description", cve.description())

    rtab = Table(box=None, show_header=False)
    rtab.add_column("url)")
    for ref in cve.references:
        rtab.add_row(ref.url)

    table.add_row("References", rtab)

    console.print(table)
