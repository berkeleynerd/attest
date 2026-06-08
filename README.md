# attest

`attest` is a small Go command-line utility for signing and verifying single-file HTML documents. It signs the exact HTML bytes with a GPG detached OpenPGP signature, then appends a hidden HTML-comment evidence trailer containing the signature and metadata.

## What it proves

With `--trusted FULL_FINGERPRINT`, successful verification proves `AUTHENTIC`: the signed bytes match the detached signature, and the signer fingerprint exactly matches a verifier-supplied trusted fingerprint.

Without `--trusted`, successful cryptographic verification is only `CRYPTO-VALID`: some key available in the local GPG keyring made a mathematically valid signature over these bytes. Authenticity is not established.

## What it does not prove

- It does not prove the intended person or organization signed the file unless a trusted fingerprint matches.
- It does not auto-import keys, trust embedded keys, or retrieve keys from the network.
- Verification depends on local GPG keyring contents; two users may see different results for the same file.
- `created_utc` is metadata only, not a trusted timestamp.
- Evidence hashes are diagnostic. The OpenPGP detached signature is the adversary-resistant integrity check.
- Post-quantum signatures are not implemented in this MVP. Do not use ML-KEM/Kyber as signatures; they are for key establishment/encryption.

Do not put real production signing keys into cloud workspaces or other untrusted environments.

## Build and test

```sh
go build -o attest .
go test ./...
```

The application uses only the Go standard library. The only external runtime dependency is the local `gpg` executable.

## Usage

Options must appear before the input file because the CLI uses Go's standard `flag` package.

Correct:

```sh
attest sign -k ABCD1234 page.html
```

Not supported:

```sh
attest sign page.html -k ABCD1234
```

### Sign

```sh
attest sign -k KEY page.html
```

By default this writes `page.attest.html`. Use `--force` to overwrite and `--strip-existing` to remove a well-formed existing trailer before re-signing the original payload.

### Verify with a trusted fingerprint

Use full fingerprints for trust decisions:

```sh
attest verify --trusted ABCD1234EF567890ABCD1234EF567890ABCD1234 page.attest.html
```

Success prints:

```text
AUTHENTIC: signature verified and trusted fingerprint matched
HASH: sha256 and sha512 match
SIGNER: ABCD1234EF567890ABCD1234EF567890ABCD1234
TRUST: trusted fingerprint matched
```

### Verify without a trusted fingerprint

```sh
attest verify page.attest.html
```

A cryptographically valid signature without a trust anchor prints `CRYPTO-VALID` and exits 3:

```text
CRYPTO-VALID: signature math verified
HASH: sha256 and sha512 match
SIGNER: ABCD1234EF567890ABCD1234EF567890ABCD1234
WARNING: no trusted fingerprint supplied; authenticity is not established
```

### Extract manually

```sh
attest extract page.attest.html \
  --payload-out page.payload.html \
  --sig-out page.sig.asc \
  --evidence-out page.evidence.json

gpg --verify page.sig.asc page.payload.html
```

`extract` does not run GPG verification.

## Trailer format

The final file is:

```text
[signed HTML bytes][attestation trailer]
```

The signed payload is every byte before this exact start marker:

```text
\n<!--ATTEST EVIDENCE V1\n
```

The trailer body is standard Base64-encoded JSON wrapped at 76 characters per line, followed by this exact end marker:

```text
\nATTEST END-->\n
```

The trailer is not part of the signed payload. The tool does not parse HTML, canonicalize HTML, normalize line endings, trim whitespace, or rewrite signed payload bytes.

## Git EOL warning

Git EOL normalization can break signatures because the payload is signed as raw bytes. This repository includes:

```gitattributes
*.attest.html -text
```

Use the same rule for repositories that store signed artifacts.
