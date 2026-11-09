# Enforcement design

A trusted host registers tools and issues opaque bearer capabilities. An untrusted
agent receives only a token and access to `Broker.execute`. Each grant fixes one
tool, a logical resource subtree, an exact argument schema with per-field choices
and UTF-8 byte bounds, an expiry, a call budget, and a byte budget. Costs are
computed by the broker as the sum of argument value bytes, never supplied by the
caller. Every admitted attempt consumes one call and its bytes, even on failure.

The broker holds one lock across lookup, revocation/expiry checks, scope checks,
budget reservation, and decision logging. This is the admission linearization
point. Tool callbacks execute outside the lock. Revocation takes the same lock:
when it returns, future admissions fail, but already admitted work can finish.
Revocation does not cancel or roll back effects. Expiry is also checked only at
admission. Independent grants have independent budgets; separate broker instances
do not share grants, budgets, or revocations.

Resources are virtual ASCII absolute paths. Repeated slashes, dot segments and
trailing slashes normalize; parent segments, percent escapes, backslashes,
non-ASCII characters and punctuation outside letters, numbers, underscore,
hyphen and dot are rejected. Subtree matching uses a slash boundary. The callback
receives the same canonical resource that was authorized. These are NOT OS paths:
there are no filesystem operations, symlinks, URL decoders or network adapters.
Connecting a filesystem requires a separate race-resistant adapter and threat model.

Only exact builtin strings and dictionaries cross the execution boundary. The
broker copies arguments before checking and dispatching and passes an immutable
mapping to callbacks. Policy mappings and choices are copied on grant issuance.
Tokens use 256 random bits and are stored only as SHA-256 lookup keys. Tokens are
not signed policy documents and cannot be edited to change authority. Revocation
is idempotent for a known token. Tokens from another broker are unknown.

Decision logs are immutable snapshots in admission order, with sequence, grant ID,
tool, canonical resource, reason, charge and remaining budget. They omit tokens
and argument values. An allow record proves admission, not callback success.
Denied calls do not invoke tools or consume budgets; writing a denial audit record
is an intentional broker-side effect. Logs are in memory, unauthenticated, and
neither crash-durable nor tamper-proof against the trusted host.

# Trust boundaries

The issuer, broker process, clock, tool registrations and callback implementations
are trusted. Arbitrary Python code in that process can bypass the broker. This is
an application authorization boundary, not an OS sandbox or isolation mechanism.
The agent must not receive the issuer interface or direct tool/store access.
Bearer token theft grants the thief the remaining authority. Transport security,
identity authentication, durable storage, distributed transactions, rate limiting,
resource quotas for logs, and secret management are outside scope. The default
clock is monotonic; injected clocks must be finite, trusted and nondecreasing.
Tools may fail after partial effects; consumed budgets are never refunded.
