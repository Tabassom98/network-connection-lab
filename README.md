# Network Connection Investigation Lab

Explore two simple network hypotheses: a source contacting several destination ports in a short window, and a large transfer between two addresses. This offline Python lab produces evidence IDs that can be traced to synthetic connection records.

## Run

Python 3.10+; standard library only. From the repository directory:

```sh
python analyze.py data/connections.jsonl
python -m unittest discover -s tests -v
```

Substitute `python3` if needed. No network calls, packet capture privileges, dependencies, or credentials. Exit 0 means successful analysis; 2 means invalid input. Output is JSON. The demo produces two findings matching `examples/expected.json`.

## Rules and data

- NET-001: at least five distinct destination ports for the same source/destination pair in an inclusive trailing 60-second window; emits once per pair per batch.
- NET-002: at least 10,000,000 outbound bytes for a pair across the whole input file. This is a batch aggregate, not a rate or time-window rule.

Input is normalized JSONL with unique nonempty `id`, timezone-aware ISO timestamp, IP literals `src`/`dst`, integer `dst_port` (1-65535), and nonnegative integer `bytes_out`. IPs are canonicalized; events are sorted by timestamp then ID. Port findings precede transfer findings in the report. This schema omits protocol; use only a consistently scoped source or add protocol before mixing transports. There is no native PCAP or Zeek ingestion; use a separate normalization adapter for those sources.

## Investigate

The fixture shows `192.0.2.10` contacting ports 22-26 on `198.51.100.10` over four seconds, then sending 12,000,000 bytes in a later connection. These observations do not establish scanning or exfiltration. Authorized administration and backups are alternative explanations. There are no TCP flags, connection outcomes, packet payloads, process identities, or destination ownership context.

Review the source records and service context, then seek packet or endpoint evidence. Do not claim the transfer and port activity came from the same process merely because the addresses match. See `docs/case-report.md` for the worked example.

## Limits and provenance

AI-assisted educational starter using invented data and documentation-range IPs. No real investigation, production deployment, threat attribution, or effectiveness claim. Small files only: input and recent state are held in memory. Repeated exports can double-count bytes; unique IDs alone cannot identify overlapping source records. Distributed and slow activity may evade the first rule.

Tests cover distinct counting, boundaries, pair isolation, ordering, suppression, validation, and expected results. GitHub CI is configured for Windows/Linux and Python 3.10/3.12; remote execution must be verified after publication. MIT licensed.
