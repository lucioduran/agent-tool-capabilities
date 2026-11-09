# Evidence protocol

The fixed sequential matrix includes three accepted controls and 22 rejected
requests. Each case creates a fresh store and grant. The report records the exact
non-secret request, expected reason, actual admission decision, complete before
and after store snapshots, and SHA-256 hashes of those snapshots. Forged-token
cases record the case name but never serialize a capability token.

Both concurrency cohorts submit 64 identical two-byte requests using eight
threads, synchronized in groups by a barrier. One has seven calls and 128 bytes;
the other has 64 calls and 14 bytes. Each must admit seven requests. Full decision
ledgers preserve admission order, charges and remaining budgets. No timing or
throughput is measured. These small cohorts exercise an actual shared broker and
actual in-memory effects; they are not simulated scheduler outcomes.

The revocation case pauses an admitted callback at an event, revokes the token,
attempts a second call, then releases the original callback. The original call
must finish, the second must be denied, and the store must contain one append.
Tests separately exercise argument copies and policy immutability.

`experiments.verify` reruns the sequential cases, recomputes their store hashes,
checks the exact concurrent ledgers against independent integer budget arithmetic,
and validates in-flight decisions and effects. Tampered decisions, hashes,
resource snapshots, budgets and cohort sizes fail verification. The verifier and
experiment share the sequential runner; independent unit assertions test boundary
behavior, but shared bugs remain possible. Metadata is descriptive, not signed.

The report's revision identifies the clean implementation commit before evidence
was added. The release commit adds documentation/evidence without changing measured
Python sources. Source hashes bind evidence to runtime and experiment code at both
commits. CI checks those hashes with LF checkout on all three operating systems.
There are no model downloads, API calls, rented GPUs or monetary charges. Local
hardware and electricity cost are not measured. This project reports no statistical
confidence interval because a fixed regression matrix is not a sampled population.
