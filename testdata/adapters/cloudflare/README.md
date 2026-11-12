# Cloudflare adapter fixtures — SYNTHETIC

**Nothing here was recorded against Cloudflare.** No Cloudflare account was
available (WP1.2). Every exchange is hand-made from the documented shapes of
the Cloudflare API v4 (`GET /zones`, `/zones/{id}/ssl/certificate_packs`,
`/zones/{id}/custom_certificates`, `/certificates?zone_id=`). Zone IDs,
object IDs and names are synthetic (`*.example.test`); the Origin CA
certificate is issued by a throw-away "Synthetic Test CA" whose keys were
deleted. No token appears. PEM armour is written with JSON `-` escapes
(see ../aws/README.md).

| Directory | Contents |
|---|---|
| `synthetic-full/` | Zones over two pages (`result_info.total_pages`). Zone A: a universal certificate pack with two certificates, a custom certificate, an Origin CA certificate. Zone B: an advanced pack pending validation, no custom or Origin CA certificates. |
| `synthetic-auth-failure/` | `GET /zones` answering 403 with error code 10000. |

429 with `Retry-After` is injected by the tests.

## To re-record against a test account

With a token holding Zone:Read and SSL and Certificates:Read only:

1. Certificate packs with `status=all` for universal, advanced and total TLS
   packs; confirm the `primary_certificate` and `certificates[].serial_number`
   fields and whether custom certificates also appear as packs.
2. Custom certificates (legacy and SNI), including the timestamp format.
3. `GET /certificates?zone_id=` with an API token (rather than an Origin CA
   key); confirm the token permission it needs and the `expires_on` format.
4. Real 429 (`Retry-After`), 401 and 403 bodies.
