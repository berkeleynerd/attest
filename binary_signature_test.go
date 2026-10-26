package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegrationRejectsTextModeSignatures(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	home := newGNUPGHome(t)
	t.Cleanup(func() { killGPGAgent(home); os.RemoveAll(home) })
	t.Setenv("GNUPGHOME", home)
	fingerprint := generateKey(t, home, "Binary Signature Test <binary@example.invalid>", "binary@example.invalid")
	dir := t.TempDir()
	lf := []byte("<!DOCTYPE html>\n<html><head><title>Test</title></head><body>Signed</body></html>\n")
	crlf := []byte(strings.ReplaceAll(string(lf), "\n", "\r\n"))
	input, signature := filepath.Join(dir, "payload.html"), filepath.Join(dir, "signature.asc")
	if err := os.WriteFile(input, lf, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("gpg", "--batch", "--yes", "--textmode", "--armor", "--detach-sign", "--local-user", fingerprint, "--output", signature, input)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("text-mode sign: %v %s", err, out)
	}
	armor, err := os.ReadFile(signature)
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{"original LF": lf, "modified CRLF": crlf} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(input, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			// Demonstrate the gap: raw GPG accepts both byte sequences.
			cmd := exec.Command("gpg", "--batch", "--verify", signature, input)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("GPG should accept text-normalized input: %v %s", err, out)
			}
			attested, err := buildAttestedFile(payload, newEvidence(payload, string(armor), time.Now()))
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "attested.html")
			if err := os.WriteFile(file, attested, 0o600); err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			if code := run([]string{"attest", "verify", "--trusted", fingerprint, file}, &out, &stderr); code != 1 || !strings.Contains(out.String()+stderr.String(), "binary-document") {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, &out, &stderr)
			}
		})
	}
	// Signing ignores a textmode setting and creates a byte-exact signature.
	if err := os.WriteFile(filepath.Join(home, "gpg.conf"), []byte("textmode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary, err := gpgDetachSign("gpg", fingerprint, lf)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := verifyDetachedWithGPG("gpg", lf, binary)
	if err != nil || !valid.CryptoValid {
		t.Fatalf("binary signature: %#v, %v", valid, err)
	}
	changed, err := verifyDetachedWithGPG("gpg", crlf, binary)
	if err != nil || changed.CryptoValid {
		t.Fatalf("modified bytes accepted: %#v, %v", changed, err)
	}
}
