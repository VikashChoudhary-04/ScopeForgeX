# ScopeForgeX Benchmark Evidence

## Overview

This directory contains the complete evidence package for the independent sequential Python baseline benchmark used to compare execution time against the ScopeForgeX **STANDARD** workflow.

The benchmark is intentionally independent of ScopeForgeX's internal timing implementation. The baseline invokes the same logical security tools sequentially and measures the total wall-clock duration with Python's `time.perf_counter()`.

## Benchmark Summary

| Metric | Value |
|---|---|
| Target | `https://warrantyindia.com/` |
| ScopeForgeX profile | `STANDARD` |
| ScopeForgeX reference run | `outputs/https_warrantyindia.com_/20260917_150445_145_cd69e9ad` |
| ScopeForgeX duration | `1060.6487560272217 s` |
| Logical tools | `13` |
| `dig` queries | `7` |
| Baseline runs requested | `5` |
| Baseline runs completed | `5` |
| Valid baseline runs | `4` |
| Invalid baseline runs | `1` |
| Baseline mean | `1025.2667539512497 s` |
| Baseline minimum | `984.8302501480002 s` |
| Baseline maximum | `1060.8447160859996 s` |

## Logical Tool Set

The benchmark uses the same logical tool sequence represented by the STANDARD workflow:

1. Amass
2. Subhunt
3. Nmap
4. `dig` — 7 queries grouped as one logical tool
5. Katana
6. Jsluice
7. httpx
8. ffuf
9. WhatWeb
10. Kiterunner
11. Wapiti
12. Nikto
13. testssl.sh

The baseline is sequential: each logical tool is executed after the previous one completes.

## Methodology

The benchmark compares:

- **ScopeForgeX STANDARD:** the measured duration from the reference ScopeForgeX run.
- **Independent Python baseline:** a standalone Python runner that invokes the corresponding commands sequentially and measures total elapsed time with `time.perf_counter()`.

The baseline is not intended to reproduce ScopeForgeX's internal architecture. Its purpose is to provide an independent execution-time reference for the same logical workload.

### Timing

The baseline measures total wall-clock execution time:

```python
start = time.perf_counter()
# execute the complete sequential tool workload
elapsed = time.perf_counter() - start
```

The ScopeForgeX reference duration is taken from the recorded reference run.

### Executable Selection

The ProjectDiscovery Go `httpx` executable used by the valid benchmark runs is:

```text
/home/kali/go/bin/httpx
```

This distinction matters because `/usr/local/bin/httpx` on the benchmark system resolves to a different Python CLI and is not the ProjectDiscovery `httpx` binary required by this benchmark.

## Run Validity

Five baseline runs were completed.

| Run | Duration | Validity |
|---|---:|---|
| Run 1 | `1060.7696018240003 s` | Valid |
| Run 2 | `984.8302501480002 s` | Valid |
| Run 3 | `1060.8447160859996 s` | Valid |
| Run 4 | — | Invalid |
| Run 5 | `994.6224477469987 s` | Valid |

Run 4 was excluded because `nikto` returned `-13` (SIGPIPE). It is therefore not included in the baseline mean.

The four valid totals are:

```text
1060.7696018240003
984.8302501480002
1060.8447160859996
994.6224477469987
```

Mean:

```text
1025.2667539512497 s
```

## ScopeForgeX vs. Independent Baseline

Reference ScopeForgeX STANDARD duration:

```text
1060.6487560272217 s
```

Independent baseline mean:

```text
1025.2667539512497 s
```

Absolute difference:

```text
35.38200207597197 s
```

Relative overhead versus the independent baseline mean:

```text
3.4510045253700232%
```

The calculation is:

```text
(ScopeForgeX duration - baseline mean) / baseline mean * 100

= (1060.6487560272217 - 1025.2667539512497)
  / 1025.2667539512497 * 100

= 3.4510045253700232%
```

This benchmark should be interpreted as an execution-overhead measurement for this specific workload and environment, not as a universal performance claim.

## Evidence Layout

The complete independent baseline evidence is stored under:

```text
benchmark/baseline_standard_clean/
```

It contains five sequential baseline-run directories:

```text
benchmark/baseline_standard_clean/
├── run_01/
├── run_02/
├── run_03/
├── run_04/
├── run_05/
└── summary.json
```

Each run contains the captured per-tool stdout/stderr, Wapiti JSON output, and a `results.json` record.

`summary.json` records the benchmark metadata, reference ScopeForgeX run, valid/invalid run counts, valid totals, and aggregate statistics.

## Reproduction

Run the independent baseline from the ScopeForgeX repository environment using the same target and command sequence represented by the recorded evidence.

For a reproducible comparison, preserve:

- the same target;
- the same tool configuration;
- the same wordlists;
- the same tool executables;
- the same logical command grouping;
- sequential execution;
- the same network/environment conditions as closely as practical.

The benchmark is sensitive to external factors such as DNS response time, target response time, network conditions, tool versions, rate limiting, and transient failures.

## Limitations

This benchmark does not establish that ScopeForgeX is universally faster or slower than manual/sequential execution.

Important limitations include:

1. The benchmark uses one target: `https://warrantyindia.com/`.
2. The comparison uses one ScopeForgeX STANDARD reference run.
3. The independent baseline has four valid runs and one invalid run.
4. Network-facing security tools are affected by target and network variability.
5. Tool versions and local system conditions can materially affect execution time.
6. The benchmark measures wall-clock execution time, not CPU time or resource efficiency.
7. The baseline is sequential and is intended as an independent timing reference rather than a reconstruction of ScopeForgeX internals.
8. The measured percentage is workload-specific.

## Interpretation

The recorded benchmark shows that the ScopeForgeX STANDARD reference run completed in:

```text
1060.6487560272217 s
```

while the four valid independent sequential baseline runs averaged:

```text
1025.2667539512497 s
```

The resulting absolute difference was:

```text
35.38200207597197 s
```

and the conventional relative-overhead calculation was:

```text
3.4510045253700232%
```

The benchmark therefore documents the measured execution overhead of the framework for this particular STANDARD workload without treating the result as a general performance guarantee.

## Metadata Source

The machine-readable benchmark metadata is stored in:

```text
benchmark/baseline_standard_clean/summary.json
```

That file is the authoritative source for the recorded aggregate benchmark values.

