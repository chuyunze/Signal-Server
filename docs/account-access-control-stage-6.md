# Account access control (stage 6)

Accounts persist an administrative state (`ACTIVE`, `SUSPENDED`, `DISABLED`, or `PURGED`) and a monotonic state version. Legacy records without these attributes remain active.

Operators can apply reversible transitions with the `set-account-status` command. Every command requires an actor and reason, emits a structured audit event, and disconnects every online device when access is restricted. The command intentionally cannot set `PURGED`; permanent deletion must use the existing destructive deletion workflow.

Normal REST, authenticated gRPC, and WebSocket traffic use `AccountAuthenticator` and therefore reject restricted accounts. Recovery performs an explicit state check before checking recovery credentials. The central message delivery layer also rejects restricted destinations so anonymous delivery, stories, receipts, and future callers cannot queue messages for them.

This private deployment requires attributable senders for strict revocation. The anonymous messages gRPC service is not registered, and anonymous REST message submissions return `401`. Signal-iOS retries ordinary sends with identified authentication. This does not disable end-to-end payload encryption, but anonymous-only story/group optimizations require separate product validation.

The client status endpoint is deliberately outside normal authentication so a restricted device can learn why normal authentication fails. It still verifies the primary device's high-entropy Basic credential and returns only that account's state, version, and update time.

Example operator usage:

```text
service set-account-status \
  --account-id <aci> \
  --status SUSPENDED \
  --actor <operator-id> \
  --reason <ticket-or-reason>
```

Use `ACTIVE` to restore access and `DISABLED` for a longer-lived reversible shutdown.

