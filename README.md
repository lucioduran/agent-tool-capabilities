# Agent Tool Capabilities

[![CI](https://github.com/lucioduran/agent-tool-capabilities/actions/workflows/ci.yml/badge.svg)](https://github.com/lucioduran/agent-tool-capabilities/actions/workflows/ci.yml)

Limit an agent's tool authority by tool, arguments, resource subtree, expiry and
atomic budgets. Inspect the decisions and reproduce attacks against owned tools.

## Problem

Giving an agent a tool name does not limit what it can do with that tool. A caller
can change arguments, cross resource boundaries, replay old grants or race a
budget check. Authorization must sit on the execution path before side effects.

## Scope

Project 17 of the engineering evidence series. A Python library with no runtime
dependencies, opaque process-local bearer grants, owned in-memory note tools and
a fixed synthetic adversarial experiment. All execution is local and free of paid
APIs. This is an application authorization boundary, not a sandbox.

## Quick start

Use Python 3.11 or newer, from a clone of this repository:

```sh
git clone https://github.com/lucioduran/agent-tool-capabilities.git
cd agent-tool-capabilities
python -m examples.demo
python -m experiments.verify results/reference.json
```

The demo appends `Hello`, revokes its grant, and prints the subsequent denial and
unchanged note. The verifier exits with `0` on success and `2` on invalid evidence.
To import the library from another project, run `python -m pip install .`.

## Usage

```python
from agent_capabilities import Argument, Broker, Denied, Scope
from agent_capabilities.synthetic import MemoryNotes

notes = MemoryNotes()
broker = Broker({"append": notes.append})
token = broker.issue(
    Scope("append", "/owned", {"text": Argument(32)}),
    calls=2, bytes=64, ttl=60,
)
result = broker.execute(token, "append", "/owned/note", {"text": "Hello"})
broker.revoke(token)
try:
    broker.execute(token, "append", "/owned/note", {"text": "blocked"})
except Denied as error:
    assert error.decision.reason == "revoked"
```

The trusted host owns `issue`, `revoke`, tool registration and the store. Expose
only `execute` to the untrusted agent. `Argument(max_bytes, choices)` makes each
field required, limits UTF-8 bytes and optionally restricts exact string values.
Extra fields and non-string values fail. The call budget counts admissions; the
byte budget sums all argument value bytes. Failures consume reserved budgets.
`ToolFailed` reports a callback exception without refunding or rolling back effects.

`broker.decisions()` returns immutable ordered records without tokens or argument
values. An allow record indicates admission, not completion. Denial reasons include
`unknown_capability`, `revoked`, `expired`, `tool_scope`, `invalid_resource`,
`resource_scope`, `argument_schema`, `argument_encoding`, `argument_scope`,
`call_budget` and `byte_budget`. Revoking an unknown token returns `False`.

## Architecture

```text
Trusted issuer -> immutable scope + opaque bearer token
                                     |
Agent request -> locked admission -> decision log
                    |
          scope + expiry + revocation
          atomic call/byte reservation
                    |
          unlocked trusted callback -> owned in-memory resource
```

The broker serializes admissions, not callbacks. Revocation shares the admission
lock and blocks subsequent admissions. Already admitted work may finish after
revocation or expiry. Logical resource canonicalization happens before scope
matching; the same canonical path reaches the callback. See the full
[design and trust boundaries](docs/design.md).

## Reproduction

```sh
python -m experiments.reproduce --output build/my-run.json
python -m experiments.verify build/my-run.json
```

Output must be a new file. On the original shared project host, run the experiment
through its mandatory exclusive benchmark wrapper:

```sh
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 python3 /Users/luchoduran/Sites/open-source-projects/.coordination/benchmark_lock.py .venv/bin/python -m experiments.reproduce --output build/my-run.json
```

The experiment uses 25 fixed sequential cases, two 64-attempt cohorts with eight
worker threads, and an event-controlled in-flight revocation. It uses no randomness
for case selection; bearer tokens are random and omitted from the report. A
trusted injected clock makes the exact expiry boundary reproducible. There is no
trained model, held-out evaluation split, external service or human review.

The [raw report](results/reference.json) records source hashes, clean source commit,
Python, OS, CPU, memory, UTC time, decisions and resource snapshots. The verifier
replays the sequential cases and independently checks concurrent budget arithmetic
and expected effects. It does not rerun the concurrent schedule or authenticate
historical measurements. Source changes require new evidence. Environment metadata
and tokens vary; case outcomes should match.

## Results

The reference run and its environment are recorded in [results/reference.json](results/reference.json).
This is a correctness experiment, with no throughput or latency claims.

| Check | Observed result |
| --- | --- |
| Permitted sequential controls | 3 / 3 admitted |
| Adversarial or exhausted sequential cases | 22 / 22 denied |
| Sequential denials changing owned store | 0 / 22 |
| Call-limited race, 64 requests, 7 calls | 7 admitted, 57 denied |
| Byte-limited race, 64 requests, 14 bytes, 2 bytes each | 7 admitted, 57 denied |
| In-flight revocation | Admitted call finished; subsequent call denied |

The recorded host is an Intel Xeon W-3223 with 48 GiB RAM, macOS and Python
3.11.13. These are observations for the fixed fixtures, not a general attack
resistance estimate. See [measurement notes](docs/evidence.md).

## Testing

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m coverage run -m unittest discover -v
python -m coverage report
python -m experiments.verify results/reference.json
```

On Windows, activate with `.venv\Scripts\Activate.ps1`. CI runs on Linux, macOS and
Windows with Python 3.11.9, a 95% statement/branch coverage gate on the runtime
package, strict runtime-package type checking, lint, formatting, evidence replay
and package installation. Tests cover concurrency, no store changes on denial,
expiry, forged grants, canonicalization, exact argument constraints, policy and
request mutation, failure charging, revocation and report tampering. Pinned action
commits were resolved from the official action repositories.

## Limitations

- Arbitrary Python in the broker process can bypass enforcement. Trusted tools
  must obey the authorized resource and must not expose broader authority.
- Bearer token theft transfers its remaining authority. Tokens are process-local;
  there is no authentication, persistent grant store or distributed enforcement.
- Virtual paths are not filesystem paths or URLs. Symlinks, filesystem races,
  network redirects and operating-system resource access are not implemented.
- Revocation and expiry do not cancel admitted calls. Failures can leave partial
  effects. Budgets charge attempts and input bytes, not output, CPU or money.
- In-memory decision logs can grow without bound and are not durable or signed.
  External request-size limits, rate limits and secret-safe tool logging are needed
  for a production service. Denials intentionally append audit records.
- Evidence is synthetic and author-known. No independent security review, external
  interoperability, deployment isolation or production performance is claimed.
- Source hashes and replay establish consistency, not measurement authenticity.
  Eight-thread tests do not exhaust all possible interleavings or process failures.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Add regression tests and document changed
trust boundaries. Report suspected vulnerabilities using [SECURITY.md](SECURITY.md).

## License

Code, original synthetic fixtures, documentation and recorded results use the
[MIT license](LICENSE). Development dependencies retain their upstream licenses.
