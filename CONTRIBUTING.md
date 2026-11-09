# Contributing

Keep changes focused and add tests for changed behavior. Use Python 3.11 or newer
and the pinned development requirements. Run the lint, format, type, unit test,
coverage and evidence verification commands from the README before submitting.
Changes to enforcement or experiments require a new measured report with source
hashes and a clean source revision; do not hand-edit outcomes to pass verification.
Keep documentation and fixtures in English and do not use em dash characters.

Tests must use owned synthetic resources only. Never use live user data or hosted
inference. Explain altered trust boundaries and budget/revocation semantics in
`docs/design.md`. Include tests for concurrency using events or barriers rather
than sleep-based timing assumptions.
