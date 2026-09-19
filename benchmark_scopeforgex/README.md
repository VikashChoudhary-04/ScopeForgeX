# ScopeForgeX Benchmark Evidence — Historical Raw Run

## Purpose

This directory contains raw stdout/stderr evidence from an earlier ScopeForgeX benchmark run.

It is retained as **historical benchmark evidence only**. It is not the canonical independent baseline package and should not be used as the source of aggregate benchmark statistics.

## Classification

| Property | Value |
|---|---|
| Evidence type | Raw historical execution output |
| Structured metadata | Not present in this directory |
| Aggregate statistics | Not present in this directory |
| Reproducibility metadata | Not fully characterized |
| Canonical benchmark package | No |
| Canonical independent baseline | `benchmark/baseline_standard_clean/` |

The canonical independent STANDARD baseline is documented in:

```text
benchmark/README.md
```

and its machine-readable summary is:

```text
benchmark/baseline_standard_clean/summary.json
```

## Contents

The directory contains raw stdout/stderr captures for the following tools from the historical run:

| Sequence | Tool | Files |
|---:|---|---|
| 1 | Amass | `01_amass.stdout`, `01_amass.stderr` |
| 2 | Subhunt | `02_subhunt.stdout`, `02_subhunt.stderr` |
| 3 | Nmap | `03_nmap.stdout`, `03_nmap.stderr` |
| 4 | `dig` | `04_dig.stdout`, `04_dig.stderr` |
| 5 | Katana | `05_katana.stdout`, `05_katana.stderr` |
| 6 | Jsluice | `06_jsluice.stdout`, `06_jsluice.stderr` |
| 7 | httpx | `07_httpx.stdout`, `07_httpx.stderr` |
| 8 | ffuf | `08_ffuf.stdout`, `08_ffuf.stderr` |
| 9 | WhatWeb | `09_whatweb.stdout`, `09_whatweb.stderr` |
| 10 | Kiterunner | `10_kiterunner.stdout`, `10_kiterunner.stderr` |
| 11 | Wapiti | `11_wapiti.stdout`, `11_wapiti.stderr` |

There are 22 raw files in total.

## Important Limitation

These files do not by themselves establish:

- the exact benchmark start/end timestamps;
- a complete machine/environment specification;
- the exact command line for every execution;
- run validity criteria;
- aggregate timing statistics;
- the number of repeated runs;
- a complete comparison methodology.

Therefore, this directory should not be presented as a complete standalone benchmark report.

## Relationship to the Canonical Benchmark

The independently measured STANDARD benchmark was subsequently captured under:

```text
benchmark/baseline_standard_clean/
```

That package contains five sequential baseline runs, per-tool stdout/stderr captures, Wapiti JSON reports, per-run `results.json`, and the aggregate `summary.json`.

The canonical recorded comparison is documented in:

```text
benchmark/README.md
```

The historical raw evidence in this directory is preserved separately so that older execution artifacts remain available without being confused with the characterized benchmark package.

## Preservation Policy

Do not modify or reinterpret the raw output files solely to make them conform to the newer benchmark format.

If the historical run is ever re-characterized, add separate metadata rather than altering the original raw evidence. The original captures should remain byte-for-byte evidence of the historical execution.

