# Azure, Entra ID and Defender adapters (WP1.2)

Five read-only adapters read certificate data Microsoft services already
hold (ADR-0016: leverage first). They call the documented REST APIs with
plain `net/http` (no SDK), only read, and never scan or connect to anything
but the Microsoft API hosts named below.

| Adapter | Reads | Minimum permission | Requirement |
|---|---|---|---|
| `azure_key_vault` | Key Vault certificates (`GET /certificates`, `GET /certificates/{name}`, REST 7.4); secrets whose content type is `application/x-pem-file` or `application/x-pkcs12` | certificates list + get; secrets list (`include_pem_pfx_entries`, default true); secrets get only with `read_pem_entries=true` | FR-DISC-024 |
| `azure_app_service` | `Microsoft.Web/certificates` and the SSL host-name bindings of `Microsoft.Web/sites` per subscription (api-version 2023-12-01) | Reader on the subscriptions | FR-DISC-025 |
| `azure_app_gateway` | `Microsoft.Network/applicationGateways` per subscription: SSL certificates (`publicCertData`) and HTTPS listeners (api-version 2024-05-01) | Reader on the subscriptions | FR-DISC-025 |
| `entra_id` | Graph `GET /v1.0/applications/delta` with `$select=id,appId,displayName,keyCredentials,passwordCredentials` | Graph application permission `Application.Read.All` | FR-DISC-026 |
| `defender_tvm` | Graph `POST /v1.0/security/runHuntingQuery` over `DeviceTvmCertificateInfo` (joined with `DeviceInfo` for the device name) | Graph application permission `ThreatHunting.Read.All` | FR-DISC-030 |

## What they never touch

- No key objects: Key Vault `kid` and `sid` are URLs that are not followed;
  no `keys/*` call is made.
- Key Vault secrets are read only when `read_pem_entries=true`, and then
  only PEM secrets: the first `CERTIFICATE` block is parsed, a `PRIVATE KEY`
  block is recognised by its type only (custody `present`), its bytes are
  overwritten and never decoded, and the value is never logged, stored or
  returned. PKCS#12 secrets are never fetched or opened; they are reported
  with the finding `secret_not_read` and custody `unknown`.
- Entra password credentials: only `keyId`, `startDateTime` and
  `endDateTime` are decoded; `hint` and `secretText` are not declared in the
  decoder and never leave the process. Key credentials: the `key` property
  is never requested.
- App Gateway `data` and `password` (write-only) are not declared.

## Authentication

`auth` is `client_credentials` (default) or `managed_identity`.

- Client credentials: settings `tenant_id`, `client_id`; the client secret
  is named under `credentials.client_secret` and resolved just in time
  through `credential.Source`. A certificate (JWT assertion) credential is
  not supported yet: it would need the collector to sign with a private key.
- Managed identity: the IMDS endpoint
  `http://169.254.169.254/metadata/identity/oauth2/token`, reached directly
  (never through the proxy); `client_id` selects a user-assigned identity.

Tokens are cached in memory for one sync, per audience (ARM, Key Vault,
Graph), never logged or written to disk. A token is sent only to the API host
of its audience: a `nextLink` or `deltaLink` pointing anywhere else stops the
sync. A 401 refreshes the token once; a 403 stops the sync with `ErrAuth`.
Token-endpoint errors report only the short OAuth code (for example
`invalid_client`), never the description.

## Delta, paging and rate limits

| Adapter | Paging | Delta |
|---|---|---|
| Key Vault | `nextLink` | per vault, the newest `attributes.updated` seen (and the IDs at that second); unchanged certificates are not fetched again |
| App Service, App Gateway | `nextLink` | a digest per resource ID; only changed resources are reported |
| Entra ID | `@odata.nextLink` | Graph delta query; the `@odata.deltaLink` is the cursor; `410 Gone` restarts a full read |
| Defender | keyset on `DeviceId`, `Thumbprint`, `hash_sha256(Path)` (`page_size`, default 10000) | the table is a snapshot without change times: a full read at most every `min_interval` (default 24h); the core de-duplicates |

`429` and `5xx` are retried up to four times with exponential back-off,
honouring `Retry-After` up to five minutes. Default rates: 5 calls a second
(Graph hunting: one call every two seconds, inside its 45-a-minute limit);
`rate_per_second` overrides.

## Contract and feature switches

| Observation | Shape | Sent when |
|---|---|---|
| Key Vault, App Service, App Gateway, Entra | target kind `cloud_resource` with adapter evidence (PROPOSED contract 0.10.0, `api/proposed/collector-0.10.0-proposed.yaml`) | `MEISCOPE_FEATURE_CLOUD_RESOURCE_V1=true` |
| Defender | target kind `store` (`windows/LocalMachine/<store>`, `windows/CurrentUser/<store>`, else `windows/defender/other` with `path`) with adapter evidence (contract 0.9.0) | `MEISCOPE_FEATURE_LOCAL_STORE_V1=true` |

With a switch off, those observations are counted as
`skipped_feature_disabled`, a warning names the switch, and the cursor is
not advanced. The vendored contract 0.9.0 cannot carry an App Service or App
Gateway host name as a `host_port_sni` target: adapter evidence is required
with method `adapter` and is allowed only with store and file targets, so
bindings travel as `adapter.bindings` of the cloud resource instead.

`renewal_mode` is set only from what the source proves: Key Vault issuer
`Unknown` is `manual`, a known issuer with an `AutoRenew` lifetime action is
`external_automated`; an App Service certificate with a `canonicalName` (a
managed certificate) is `external_automated`, one imported from Key Vault is
`unknown`, an uploaded one `manual`; an App Gateway certificate linked to Key
Vault is `unknown`, an uploaded one `manual`.

## Configuration example

```json
[{"name": "kv-prod", "adapter": "azure_key_vault",
  "settings": {"tenant_id": "<tenant GUID>", "client_id": "<app GUID>", "vaults": "kv-contoso-prod"},
  "credentials": {"client_secret": "azure_reader_secret"}},
 {"name": "web", "adapter": "azure_app_service",
  "settings": {"auth": "managed_identity", "subscriptions": "<subscription GUID>"}}]
```

Fixtures under `testdata/adapters/azure/` are synthetic; its README lists
what must be re-recorded against a test tenant.
