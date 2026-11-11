# Meiscope hands-on test: find the certificates on your servers and network devices

This guide is for the IT administrator who runs the test. It takes about 30 minutes.

> **Draft.** The `scan` command, its flags and the report format are still being finalised. Every place marked **TODO (scan flags)** will be filled in from the released command before this guide is used.

## What the test is

You download one program, `meiscope-collector`, and run it on a machine inside your network. You give it a list of servers and network devices (one line per endpoint). For each one, it opens a single TLS connection, reads the certificate the endpoint presents, and closes the connection.

The result is a report on your own disk: which certificates were found, who issued them, when they expire, and which endpoints didn't answer.

- **Nothing is installed:** no service, no agent, and no account at Meiscope.
- **Nothing is sent anywhere.** You decide afterwards whether to share the report.

## What it does, and what it does not do, on your network

**It does:**
- connect only to the endpoints in your list, nothing else
- for each endpoint, resolve its name with your normal DNS, open one TCP connection, and start TLS
- for protocols that start TLS inside the connection (SMTP, IMAP, POP3, LDAP, RDP, PostgreSQL, MySQL, SQL Server), send only the standard "please start TLS" request
- stop as soon as the endpoint has shown its certificate, then close the connection
- write the report to a folder you choose, on the machine where it runs

**It does not:**
- scan address ranges or sweep ports; a port that isn't open is reported as `refused` or `timeout`
- send any user name, password, client certificate or query, or log in to anything (it needs no credentials)
- finish the TLS handshake or send application data
- connect to link-local or cloud metadata addresses (refused even if they're in the list)
- send your list, the report or any telemetry to Meiscope or anyone else
- open a listening port, or need administrator rights to run

**What your network team may see:** one short TLS connection per endpoint in the list, from the machine running the test. An IDS may log these as incomplete TLS handshakes. Tell your security team before you start.

## 1. Before you start

- **A machine inside your network** that can reach the endpoints you want to check, running Linux (x86-64 or ARM64) or Windows (x86-64). A normal user account is enough.
- **The list of endpoints** you're allowed to test: host name or IP address, and port. Only list systems you're responsible for, or have permission to test.
- **About 50 MB of free disk** for the program (about 12 MB) and the report.

## 2. Download and verify the program

Download from the release page your Meiscope contact sends you (`https://github.com/uvamai/meiscope-collector/releases/tag/<version>`):
- the binary for your system: `meiscope-collector_linux_amd64`, `meiscope-collector_linux_arm64` or `meiscope-collector_windows_amd64.exe`
- `SHA256SUMS`
- the binary's `.sigstore.json` file (the signature)

### Check the checksum (required)

The checksum proves the file wasn't damaged or changed in transit.

Linux:
```sh
sha256sum --check --ignore-missing SHA256SUMS
# expect: meiscope-collector_linux_amd64: OK
```

Windows (PowerShell):
```powershell
(Get-FileHash .\meiscope-collector_windows_amd64.exe -Algorithm SHA256).Hash.ToLower()
Select-String meiscope-collector_windows_amd64.exe .\SHA256SUMS
# the two hashes must be identical
```

### Check the signature (recommended)

The signature proves the file was built by Meiscope's public release pipeline from the published source. It needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

```sh
cosign verify-blob \
  --bundle meiscope-collector_linux_amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/uvamai/meiscope-collector/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  meiscope-collector_linux_amd64
# expect: Verified OK
```

Use the same command for the Windows `.exe` and its `.sigstore.json`.

**Windows SmartScreen:** the Windows binary is not yet Authenticode-signed, so Windows may warn that it's from an unknown publisher. The checksum and the cosign signature above are what show it's genuine.

On Linux, make it executable: `chmod +x meiscope-collector_linux_amd64`.

## 3. Prepare `targets.csv`

One endpoint per line: **explicit endpoints only.** Address ranges (CIDR) and port ranges are not accepted.

**TODO (scan flags):** column names and order, comment syntax and the STARTTLS column, from the `scan` command.

```csv
# host,port,protocol,name
www.example.com,443,,
mail.example.com,25,smtp,
ldap01.example.com,389,ldap,
10.0.20.15,443,,fw01.example.com
```

Tips:
- **Servers:** web servers (443, 8443), mail (25, 465, 587, 993, 995), LDAP and AD (389 with StartTLS, 636), RDP (3389), databases (5432, 3306, 1433).
- **Network devices:** firewall and VPN portals, load balancers, switch and router management pages, wireless controllers, printers. Use the management address and its HTTPS port.
- **An IP address that serves several names:** add the name in the last column, so the endpoint shows the right certificate.

## 4. Run the scan

**TODO (scan flags):** the exact command, flags and defaults, from the `scan` command. Expected shape:

```sh
./meiscope-collector_linux_amd64 scan --targets targets.csv --out ./meiscope-report
```

- **Dry run first:** try **TODO (dry-run flag)** to list what it would connect to, without connecting to anything.
- **Pacing:** connections are paced, so a list of a few hundred endpoints takes a few minutes.
- **Stopping:** Ctrl+C stops at once; open connections are closed.

## 5. Read the report

**TODO (scan flags):** the report files (for example an HTML summary and a JSON file) and what each column means.

Each endpoint has one result:
- `cert_seen`: a certificate was read (subject, issuer, expiry, key type and chain)
- `refused`: the port is closed
- `timeout`: no answer
- `reached`: it connected, but no TLS was offered
- `tls_failed`: TLS started but failed

**What the report contains:**
- host names, IP addresses and ports from your list
- the certificates' **public** contents, which any client connecting to those endpoints can already see

**What it never contains:** private keys, passwords or anything else from inside your systems.

## 6. Sending the report back (only if you choose to)

You don't have to share anything. If you want Meiscope to walk through the results with you:

1. Read the report first. Remove any line you don't want to share, or replace host names with placeholders.
2. Send the report folder (zipped) to your Meiscope contact by the channel you agreed, or bring it to the review call. Don't send `targets.csv` unless you want to.

## 7. Firewall notes

- **Outbound only:** the test machine needs outbound TCP to the endpoints in your list, on their ports. No inbound rule is needed.
- **No internet access** is needed for the scan itself, only to download the program.
- **Host firewalls on the targets** that block the test machine will show as `timeout` or `refused`. That's a result too.
- **Throttling:** if your IDS or firewall throttles new TLS connections, run the scan from a machine your network team has allow-listed for the test.

## 8. Afterwards

Delete the program, `targets.csv` and the report folder when you're done. Nothing else was installed or changed, so there's nothing to uninstall.

## Questions and security

- **About the test:** your Meiscope contact.
- **To report a security issue:** `security@meiscope.cloud` (see [SECURITY.md](../../SECURITY.md)).
- **How the probe works and its safety rules:** [docs/probe.md](../probe.md).
