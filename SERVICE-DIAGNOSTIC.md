# Bounded service-diagnostic mandate

This integration is one closed consumer of Standing's existing act-grant state
machine. It does not make Standing an observability system.

An operator first creates and activates an ordinary grant whose scope is:

- action: `nq.service-diagnostic/v1`
- target: `diagnostic::target(subject_digest, scope_digest)`

The operator then signs `standing.service-diagnostic-enrollment/v1`, binding the
installed genesis receipt, exact grant, distinct workload public key, audience,
subject, scope, NQ profile, configuration digest, and exclusive expiry. The
workload signs each `standing.service-diagnostic-request/v1`, additionally binding
the exact Maude plan digest, Nightshift run, PlanNode, request identity, and a
maximum five-minute interval.

`standing-diagnostic` verifies both signatures against its deployment-pinned
operator key and consumes the active grant transactionally before returning an
admission receipt. Expired, revoked, mismatched, replayed, or concurrently spent
grants refuse. The diagnostic provider has not been invoked when the tool returns
a refusal. Its successful result also does not claim the diagnostic succeeded or
that the service is healthy.

`standing-diagnostic-sign` is a separate control-process utility. Private keys do
not belong in a browser, PlanDocument, handoff, inspector, or Standing receipt.
Deployment configuration and key custody remain external responsibilities.

The store directory, signed enrollment file, and pinned-key file are assumed to
be deployment-owned trusted paths. The CLI uses bounded no-follow file reads, but
this route is not a cross-account pathname-confinement mechanism.
