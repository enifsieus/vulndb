# bomsquad.vulndb

'bomsquad.vulndb' implements models and APIs for ingesting National Vulnerability Database and OSV datasets
into a relational data store, and cross-querying the datasets.

vulndb is initially envisioned as a research tool for delving into correlations between these datasets. It
may evolve to incorporate additional datasets, or serve further use cases as we follow this research.

## Pre-requisites

1. You will need a gcloud account as you must provide a quote project to access OSV data files
2. You will need postgresql installed, with a database, and role created that ows it
3. You will need poetry and poethepoet installed to build and experimement with the python API
3. You may optionally acquire an API key for the National Vulnerability Database

## Installation

1. Run the create.sql as the owning user:
```
$ sql -U <username> -d <database> -a -f db/create.sql
```
3. Copy config.toml to ~/.vulndb/config.toml and edit to match your evironment

## CLI

The vulndb cli exposes the following commands:

### nvd

#### ingest

Ingest Vulnerability (CPE) and Product (CPE) records from the National Vulnerability Database (https://nvd.nist.gov).

```
$ vulndb nvd ingest --help
Usage: vulndb nvd ingest [OPTIONS]

Options:
  --scope TEXT      Ingest only cve or cpe
  --offset INTEGER  Offset into available entries to begin wtih  [default: 0]
  --limit INTEGER   Limit the number of entries to ingest
  --help            Show this message and exit.
```

### osv

#### ingest

Ingest records from the Open Source Vulnerability (https://osv.dev) dataset.

```
$ vulndb osv ingest --help
Usage: vulndb osv ingest [OPTIONS]

Options:
  --ecosystem TEXT  Ingest only a single ecosystem
  --offset INTEGER  Offset into available entries to begin wtih  [default: 0]
  --limit INTEGER   Limit the number of entries to ingest
  --help            Show this message and exit.
```

### purl

#### lookup

Perform a lookup for vulnerability records for a given PURL. If the PURL is unversioned, then
all known vulnerabilities associated with the PURL are reported. If the PRUL is versioned, then
only applicable vulnerabilities for the specified version are reported.

```
$ vulndb purl lookup --help
 Usage: vulndb purl lookup [OPTIONS] TARGET

Arguments:
  *    target      TEXT  [default: None] [required]                                                                                            │

Options:
  --help          Show this message and exit.                                                                                                  │
```