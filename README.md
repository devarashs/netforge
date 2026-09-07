# netforge

[![CI](https://github.com/devarashs/netforge/actions/workflows/ci.yml/badge.svg)](https://github.com/devarashs/netforge/actions/workflows/ci.yml)
[![Release](https://github.com/devarashs/netforge/actions/workflows/release.yml/badge.svg)](https://github.com/devarashs/netforge/actions/workflows/release.yml)

A single-binary **network and security toolkit** written in Go, with **zero
third-party dependencies** — everything is built on the standard library,
including hand-assembled IPv4/TCP packets, a from-scratch PBKDF2 key derivation,
and a small command-tree framework.

It bundles four groups of tools:

| Group    | What it does                                                            |
| -------- | ----------------------------------------------------------------------- |
| `stress` | Load / resilience testing for infrastructure you own (HTTP, TCP, UDP, ICMP, raw SYN) |
| `cert`   | Generate and inspect X.509 certificates (self-signed CAs, leaf/server certs, RSA/ECDSA/Ed25519) |
| `crypto` | Hashing, secure random, AES-256-GCM passphrase encryption, RSA keygen + OAEP |
| `net`    | Read-only diagnostics: TCP port scan, latency ping, uptime monitor, DNS lookups, interface listing |

## Why it exists

I wanted a low-level look at how network stress tools actually work — building an
IP header byte by byte, computing the one's-complement checksum, sending raw SYN
segments through a `SOCK_RAW` socket — rather than calling a library that hides
it. That grew into a general-purpose toolkit I reach for when testing my own
homelab: generate a cert, encrypt a file, scan a box, watch a service.

## Install

```bash
# Prebuilt binaries: grab one from the Releases page
#   https://github.com/devarashs/netforge/releases/latest

go install github.com/devarashs/netforge@latest
# or from a clone:
make build      # produces ./netforge (version stamped from git)
make cross      # cross-compiles linux/darwin/windows into dist/

netforge version   # prints version, commit and build date
```

Go 1.24+ required. No `go.sum`, no modules to download — it builds offline.

## Releases & versioning

Releases are automated. Every push to `main` runs CI (gofmt, `go vet`,
race-enabled tests, build); if it's green, the release workflow computes the
next [semantic version](https://semver.org) and publishes a GitHub Release with
cross-compiled binaries (linux/darwin/windows, amd64/arm64) and a
`checksums.txt`.

The version bump is derived from the commit messages since the last tag
([Conventional Commits](https://www.conventionalcommits.org)):

| Commit contains          | Bump    |
| ------------------------ | ------- |
| `BREAKING CHANGE` or `!:`| major   |
| `feat:` / `feat(scope):` | minor   |
| anything else            | patch   |

The version is baked into the binary via `-ldflags`, so `netforge version`
reports exactly what was built. Add `[skip release]` to a commit message to push
to `main` without cutting a release.

## Usage

```
netforge <group> <command> [flags]
netforge <group> <command> -h     # flags for any command
```

### stress — authorized load testing

These commands are for systems **you own or are explicitly authorized to test**.
They refuse to run unless you pass `-i-am-authorized`, and they send from your
**real source address** — no spoofing. (Spoofing adds nothing to a legitimate
load test and is dropped by any network doing egress filtering.)

```bash
# HTTP request-rate test against your own service
netforge stress http -url http://127.0.0.1:8080/ -threads 50 -duration 30 -i-am-authorized

# UDP / TCP / ICMP
netforge stress udp  -target 127.0.0.1 -port 9000 -duration 15 -i-am-authorized
netforge stress tcp  -target 127.0.0.1 -port 8080 -duration 15 -i-am-authorized
sudo netforge stress icmp -target 127.0.0.1 -duration 10 -i-am-authorized

# Raw SYN test (Linux only, needs root for SOCK_RAW)
sudo netforge stress syn -target 127.0.0.1 -port 80 -duration 10 -i-am-authorized
```

### cert — X.509 generation

```bash
# Quick self-signed server cert with SANs
netforge cert server -cn dev.local -dns dev.local,localhost -ip 127.0.0.1 -out server

# A local CA, then a leaf signed by it
netforge cert ca -cn "My Dev CA" -out ca
netforge cert server -dns api.dev.local -ca-cert ca.pem -ca-key ca.key -out api

# Inspect any cert
netforge cert inspect -file server.pem
```

Key types: `rsa`, `rsa4096`, `ecdsa` (P-256), `p384`, `ed25519`.

### crypto — everyday cryptography

```bash
netforge crypto hash -algo sha256 -file ./bigfile.iso
netforge crypto rand -bytes 32 -format base64
netforge crypto rand -password

# AES-256-GCM with a passphrase (PBKDF2-HMAC-SHA256, 200k iterations)
netforge crypto encrypt -in secret.txt -out secret.enc -pass 's3cr3t'
netforge crypto decrypt -in secret.enc -pass 's3cr3t'
# ...or read the passphrase from NETFORGE_PASS instead of the command line

# RSA
netforge crypto rsa-keygen -bits 3072 -out id
echo "hi" | netforge crypto rsa-encrypt -pub id.pub.pem | netforge crypto rsa-decrypt -priv id.pem
```

The encrypted file format is `"NFE1" || salt(16) || nonce(12) || ciphertext+tag`.
GCM authenticates the data, so tampering or a wrong passphrase fails cleanly.

### net — diagnostics

```bash
netforge net scan    -host 192.168.1.10 -ports 22,80,443,8000-8100
netforge net ping    -host example.com -port 443 -count 5
netforge net monitor -targets "db:5432,api:8080,cache:6379" -interval 5
netforge net dns     -name example.com -type mx
netforge net ifaces
```

## Design notes

- **No dependencies.** The whole thing imports only `std`. PBKDF2 is implemented
  on top of `crypto/hmac`; the CLI dispatch is a ~90-line tree in `internal/cli`.
- **Raw packet crafting.** `internal/stress/syn_linux.go` builds the IPv4 and TCP
  headers directly and checksums them, then writes to a raw socket. A build-tagged
  stub keeps non-Linux builds green.
- **Honest by construction.** Real source addresses, an explicit authorization
  gate on every load-test command, and GCM-authenticated encryption.

## Legal / authorized use

The `stress` tools generate real traffic. Only point them at systems you own or
have written permission to test. Using them against third-party systems without
authorization is illegal in most jurisdictions and is not a supported use of this
project. You are responsible for how you use it.

## License

MIT — see [LICENSE](LICENSE).
