# Administration API and console (stage 7)

The administration surface is disabled by default and is registered only on the normal HTTP application when `admin.enabled` is true. It is never registered on the chat WebSocket environment. Production routing must expose `/admin` and `/v1/admin/*` only through an isolated admin hostname and OIDC-aware gateway; the public chat hostname must deny both prefixes.

## Gateway token contract

After OIDC login, the gateway creates a short-lived HS512 JWT for the service. The browser should keep only the gateway's `Secure`, `HttpOnly`, `SameSite=Strict` session cookie; the gateway injects the JWT into the upstream `Authorization: Bearer …` header. Do not store the token in JavaScript storage.

Required claims:

- `iss` and `aud` match server configuration.
- `sub` is the stable administrator identity.
- `exp` is short lived.
- `roles` contains one or more of `INVITATION_OPERATOR`, `ACCOUNT_OPERATOR`, `AUDITOR`, `SUPER_ADMIN`.
- `amr` contains `mfa` and `auth_time` is less than five minutes old for mutations.

Example configuration (secret-store syntax depends on the deployment):

```yaml
admin:
  enabled: true
  issuer: https://admin-gateway.example.com
  audience: signal-admin
  gatewayTokenSecret: config/admin-gateway-token-secret
```

The gateway signing secret must have at least 32 characters, be stored in the existing secret store, and be distinct from Signal user authentication and cryptographic keys.

## Network boundary

Route `admin.example.com/admin` and `admin.example.com/v1/admin/*` to the service. Permit access only through the corporate identity-aware proxy or private network. Explicitly return `404` or `403` for these paths on `chat.example.com`. Rate-limit login at the gateway, enforce OIDC MFA, and disable caching and body logging for invitation batch responses.

## Capabilities

- Exact Account ID lookup with state, state version, device count, and primary-device last activity.
- Reversible `ACTIVE`, `SUSPENDED`, and `DISABLED` transitions with recent MFA, explicit confirmation, reason, online-device disconnection, and audit.
- Explicit force-disconnect action.
- Invitation batch creation and one-time plaintext download.
- Aggregate invitation batch state; extension and revocation require possession of the original code.
- Append-only audit search and JSON export.

The service never returns Recovery Keys, application passwords, identity keys, auth tokens, message bodies, profile keys, or invitation plaintext after creation.

## Deliberate data-model boundary

Signal does not store Username plaintext. The current admin API therefore does not support plaintext or fuzzy Username search. Adding such a database would create a new privacy leak. Exact Username administration requires a later privacy-preserving lookup contract compatible with Signal's username hashing/proof flow.

Account-wide dashboards and status/time filtering also require a dedicated administrative projection/index. They must not be implemented by synchronously scanning the production accounts table from an HTTP request. Invitation and audit records are currently small and use bounded admin-only scans; move them to dedicated indexed tables before large-scale production use.

