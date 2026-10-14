# LinuxDFIR Toolkit

Read-only Linux host collector plus a Windows-side analyzer for authorized DFIR work.

## Layout

- `collector/linux_collector.py` — single-file, stdlib-only Linux collector.
  Run on the target host: `python3 collector/linux_collector.py -o /safe/outside/evidence`
- `linuxdfir/` — analyzer package (Python 3.11+): verify, parse, detect, report.
- `sample_evidence/generate.py` — deterministic infected/clean fixture generator for tests.

## Analyzer quick start

```console
pip install .
linuxdfir verify evidence.tar.gz
linuxdfir run evidence.tar.gz -o case-out
```

Tune detections without code changes via `linuxdfir/detection.toml`
(`linuxdfir detect --config my.toml`).
