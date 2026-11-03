# The probe

**Meiscope probes only the endpoints you list.** A signed scope names each endpoint (a host name or an IP address, a port, and optionally how TLS starts). The collector connects to exactly those endpoints and to nothing else. There are no address ranges and no port sweeps; a closed port is simply reported as `refused` or `timeout`.

## What one probe does

For each listed endpoint, and for each server name the scope gives for an IP endpoint (`names_by_ip`), the collector:

1. opens **one** TCP connection, after the scope's pacing allows it;
2. sends only the protocol's request to start TLS, if the protocol needs one: SMTP `EHLO` + `STARTTLS`, IMAP `STARTTLS`, POP3 `STLS`, the LDAP StartTLS extended operation, the RDP X.224 negotiation, the PostgreSQL or MySQL SSL request, or the SQL Server PRELOGIN. It never sends a user name, password, database name or query;
3. starts TLS and **stops straight after the server's certificate**. No client certificate, key exchange, Finished message or application data is ever sent;
4. reports one observation: `cert_seen` (with the certificate chain), `refused`, `timeout`, `reached` (connected, but no TLS) or `tls_failed`.

The safety model and its tests are listed at the top of [`pkg/probe/probe.go`](../pkg/probe/probe.go). Link-local and cloud metadata addresses are refused, both after DNS resolution and again at dial time.

## The scope

The core signs each scope with Ed25519. The collector refuses a scope in any of these cases:

- it is unsigned, or signed by a key that was not pinned at enrolment (up to two keys are pinned, so the signing key can rotate);
- it is expired or not yet valid;
- it lacks an authorisation record;
- it is older than, or conflicts with, a version already accepted;
- it carries `cidrs`, `hosts` or `ports`, which are reserved and not supported in v1.

The policy in a scope sets:

- the connection rate and burst per /24 (IPv4) or /64 (IPv6);
- the connect timeout;
- the UTC scan windows;
- a deny list;
- the canary share, which runs first on a new scope version;
- dry run, which lists the targets and connects to nothing;
- the rescan interval: 5 minutes in the demo profile, 24 hours by default.

## Running it (development enrolment path)

Until enrolment with the core is available, the scope and the pinned keys come from files:

| Variable | Meaning |
|---|---|
| `MEISCOPE_SCOPE_FILE` | A signed scope `{"payload": …, "signature": …, "key_id": …}`, or `{"scopes": [ … ]}` as the core serves them. It is re-read every 5 s. |
| `MEISCOPE_SCOPE_KEYS` | The pinned scope-signing keys: `[{"key_id": "…", "public_key": "<base64 Ed25519>"}]`. Required when a scope file is set. |
| `MEISCOPE_SCOPE_STATE_FILE` | Remembers the accepted scope versions, so a replayed older scope is refused after a restart too. |
| `MEISCOPE_CORE_URL` | Where observations are submitted. When unset, they are written to standard output. |

```sh
meiscope-collector run
curl -X POST http://127.0.0.1:8090/pause    # stops all probing at once; open connections close
curl -X POST http://127.0.0.1:8090/resume
```

Pause takes effect at once: open connections are cancelled and no new one starts until resume.
