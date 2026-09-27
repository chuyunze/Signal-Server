# Numberless registration invitations

Numberless registration and invitation claiming are disabled by default. Enable `numberlessRegistration.enabled` in dynamic configuration only after the iOS client and registration endpoint have been deployed together.

## Create a batch

Run the service command in the same environment as the server:

```text
create-invitation-batch server.yml --batch-id launch-001 --count 100 --valid-days 7
```

The command writes each plaintext invitation once to standard output. Redirect it only to an approved secrets-handling destination. The server stores an HMAC digest, batch identifier, status, and expiration; it does not store the plaintext code.

## Claim protocol

An unauthenticated client sends `POST /v1/invitations/claim` with `invitationCode` and a serialized `receiptCredentialRequest`. A successful response contains a LOGIN-level `receiptCredentialResponse`. The client verifies it locally and submits only its presentation to `POST /v1/registration`; this prevents the registration record from being linked to the invitation record.

Claims are conditional and single-use. Retrying the same code with the same credential request returns the original response. A different request, an expired code, a revoked code, and an unknown code all return the same generic error. The endpoint is rate-limited by source IP.

## Operational notes

- Keep the issued-receipt generator secret stable; it is also the HMAC pepper for invitation lookup.
- Do not log request bodies on the claim route.
- Disable `numberlessRegistration.enabled` to stop new claims and numberless account creation without affecting existing accounts.
- Revocation and extension are exposed by `InvitationsManager` for the later administration module; only invitations in `AVAILABLE` state may be changed.

## Message-history backup policy

This private deployment does not register `ArchiveController`; `/v1/archives` and its message/media backup credential endpoints are therefore unavailable. Account recovery restores only the account identity and Username. It must not restore messages, attachments, or call history. The paired iOS client also disables remote backup, local-file backup, and background export entry points.

## Strict single-device policy

This deployment rejects device linking, provisioning messages, device-transfer negotiation, transfer archives, and authentication by any non-primary device. The paired iOS client hides linked-device UI, ignores provisioning and Quick Restore QR codes, always skips device transfer, and does not offer Link & Sync. Existing secondary devices must be removed before rollout; after rollout they cannot authenticate over HTTP, WebSocket, or gRPC and therefore cannot continue receiving account messages.
