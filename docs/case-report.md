# Synthetic case report

Question: does one host show broad port access and a large outbound byte total?

At 00:00:00-00:00:04 UTC, records net-1 through net-5 cover ports 22-26 for the same pair. They cross NET-001's five-port threshold. At 00:10:00, net-6 records 12,000,000 outbound bytes and causes the batch total to cross NET-002. An unrelated small connection produces no finding.

Conclusion: two defined patterns match. There is no evidence of successful compromise, malicious payloads, or unauthorized data access. A connection count and byte count cannot establish intent. In a real case, check source ownership, approved scanning, service results, process telemetry, destination purpose, and transfer authorization.

Practice: add repeated connections to a single port and show they do not satisfy NET-001; move the fifth distinct port beyond 60 seconds and rerun. Explain why NET-002 still aggregates the whole batch. Record your own changes and understanding before describing the project in an interview.
