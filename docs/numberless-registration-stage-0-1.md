# Numberless Registration: Stage 0/1 Baseline

## Scope

This document records the backend baseline and the Stage 0/1 implementation boundary for the private numberless-registration project. Invitation issuance, iOS registration UI, account suspension, and the administration console are intentionally deferred to later stages.

## Repository baseline

- Repository: `Signal-Server`
- Development branch: `jack-patch`
- Base branch: `main`
- Base commit: `33bf9ccae5766a768605d7502321e917df72d3a2`

## Existing capabilities retained

The server already provides the cryptographic account primitives needed by the project:

- New accounts without a phone number can be created with a valid LOGIN receipt credential presentation.
- Receipt serial redemption and account creation are committed in one DynamoDB transaction.
- Accounts without numbers store neither an E164 nor a PNI.
- A recovery password is mandatory for numberless accounts and is stored as a salted verifier.
- An existing account can be recovered by supplying its ACI and recovery password.
- Username operations already support accounts without phone numbers.

These primitives remain the foundation for invitation-backed registration. The invitation service added in a later stage will issue a LOGIN receipt; it will not introduce a second account-creation implementation.

## Stage 1 changes

### Independent feature control

Numberless account creation and ACI-based account recovery are controlled by a dedicated dynamic configuration setting:

```yaml
numberlessRegistration:
  enabled: false
```

The setting is disabled by default. This control is independent from `loginPurchase`, which continues to control purchase-related receipt issuance. Test and production environments must explicitly enable numberless registration before clients can use the flow.

### Numberless recovery contract

Recovery key-material requirements now depend on the account being recovered:

- Accounts with a phone number must provide a complete PNI identity/prekey bundle.
- Accounts without a phone number may omit all PNI identity/prekey material.
- Partial PNI bundles remain invalid at request validation time.

This removes the need for numberless clients to generate and transmit unused PNI key material while retaining the existing contract for phone-number accounts.

### Recovery rate limiting

ACI-based recovery has a dedicated `accountRecovery` limiter. Its default policy allows five attempts per account identifier per hour and can be overridden through the existing dynamic limiter configuration.

The limiter runs before account lookup and recovery-password verification. TOTP verification retains its separate limiter.

## Feature flags

| Setting | Default | Stage 0/1 responsibility |
|---|---:|---|
| `numberlessRegistration.enabled` | `false` | Allows numberless creation and ACI-based recovery |
| `loginPurchase.enabled` | `false` | Allows purchase receipt issuance; no longer gates registration itself |

Future invitation settings will be introduced separately so invitation issuance can be disabled without disabling recovery for existing numberless accounts.

## API behavior

The existing `POST /v1/registration` endpoint remains the single account creation and recovery endpoint:

| Operation | Basic-auth username | Verification material | PNI material |
|---|---|---|---|
| New numberless account | Ignored non-E164/non-UUID value | LOGIN receipt presentation | Absent |
| Recover numberless account | Account ACI | Recovery password | May be absent |
| Recover phone-number account by ACI | Account ACI | Recovery password | Required |

Account identity responses for numberless accounts continue to return empty `number` and `pni` values and include the numberless auth-credential salt.

## Verification coverage

Stage 1 tests cover:

- The numberless-registration setting defaults to disabled and can be enabled.
- Numberless account creation succeeds only when the feature is enabled.
- Numberless recovery succeeds without PNI key material.
- Phone-number account recovery still rejects missing PNI material.
- ACI-based recovery is rejected when its rate limit is exceeded.
- Existing malformed receipt, expired receipt, wrong receipt level, duplicate receipt, recovery-password, TOTP, and device-transfer tests remain applicable.

## Deferred work

The following work belongs to later stages:

- Invitation generation, storage, redemption, and idempotent LOGIN receipt issuance.
- iOS numberless identity and registration support.
- User-facing Account ID and Recovery Key flows.
- Account suspension, global authorization enforcement, and device disconnection.
- Administration APIs and Web console.
- Production TLS, deployment, and operational hardening.

## Rollback

Operational rollback is performed first by setting `numberlessRegistration.enabled` to `false`. This blocks new numberless account creation and ACI-based recovery without deleting existing accounts. Code rollback can then be performed independently if necessary.

Before enabling the feature in any environment, operators must verify that clients support nullable E164/PNI account identity responses.
