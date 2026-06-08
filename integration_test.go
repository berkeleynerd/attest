package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegrationGPGWorkflow(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	oldHome, hadHome := os.LookupEnv("GNUPGHOME")
	defer func() {
		if hadHome {
			os.Setenv("GNUPGHOME", oldHome)
		} else {
			os.Unsetenv("GNUPGHOME")
		}
	}()

	home := newGNUPGHome(t)
	defer killGPGAgent(home)
	os.Setenv("GNUPGHOME", home)
	fprA := generateKey(t, home, "Attest Test A <a@example.invalid>", "a@example.invalid")
	fprB := generateKey(t, home, "Attest Test B <b@example.invalid>", "b@example.invalid")

	dir := t.TempDir()
	input := filepath.Join(dir, "page.html")
	payload := []byte("<html>\n<body>Hello</body>\n</html>\n")
	if err := os.WriteFile(input, payload, 0644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"attest", "sign", "-k", fprA, input}, &out, &errOut); code != 0 {
		t.Fatalf("sign code %d stdout %s stderr %s", code, out.String(), errOut.String())
	}
	attested := filepath.Join(dir, "page.attest.html")

	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", "--trusted", fprA, attested}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "AUTHENTIC:") {
		t.Fatalf("trusted verify code %d out %s err %s", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", attested}, &out, &errOut); code != 3 || !strings.Contains(out.String(), "CRYPTO-VALID:") || !strings.Contains(out.String(), "authenticity is not established") {
		t.Fatalf("untrusted code %d out %s err %s", code, out.String(), errOut.String())
	}

	payloadOut := filepath.Join(dir, "payload.html")
	sigOut := filepath.Join(dir, "sig.asc")
	evidenceOut := filepath.Join(dir, "evidence.json")
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "extract", "--payload-out", payloadOut, "--sig-out", sigOut, "--evidence-out", evidenceOut, attested}, &out, &errOut); code != 0 {
		t.Fatalf("extract code %d out %s err %s", code, out.String(), errOut.String())
	}
	extracted, _ := os.ReadFile(payloadOut)
	if !bytes.Equal(extracted, payload) {
		t.Fatal("extracted payload differs")
	}

	tamperedHash := filepath.Join(dir, "tampered-hash.html")
	data, _ := os.ReadFile(attested)
	data[1] ^= 1
	os.WriteFile(tamperedHash, data, 0644)
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", "--trusted", fprA, tamperedHash}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "hash mismatch") {
		t.Fatalf("tampered hash code %d out %s err %s", code, out.String(), errOut.String())
	}

	tamperedSig := filepath.Join(dir, "tampered-sig.html")
	fixed := rewriteEvidenceHashesForPayload(t, data)
	os.WriteFile(tamperedSig, fixed, 0644)
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", "--trusted", fprA, tamperedSig}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "INVALID: OpenPGP signature verification failed") {
		t.Fatalf("tampered sig code %d out %s err %s", code, out.String(), errOut.String())
	}

	appended := filepath.Join(dir, "appended.html")
	orig, _ := os.ReadFile(attested)
	os.WriteFile(appended, append(append([]byte{}, orig...), []byte("<p>unsigned</p>")...), 0644)
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", appended}, &out, &errOut); code != 1 {
		t.Fatalf("appended code %d out %s err %s", code, out.String(), errOut.String())
	}

	truncated := filepath.Join(dir, "truncated.html")
	os.WriteFile(truncated, orig[:len(orig)-1], 0644)
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", truncated}, &out, &errOut); code != 1 {
		t.Fatalf("truncated code %d out %s err %s", code, out.String(), errOut.String())
	}

	corruptSig := filepath.Join(dir, "corrupt-sig.html")
	os.WriteFile(corruptSig, corruptEmbeddedSignature(t, orig), 0644)
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", corruptSig}, &out, &errOut); code != 1 {
		t.Fatalf("corrupt sig code %d out %s err %s", code, out.String(), errOut.String())
	}

	resigned := filepath.Join(dir, "page.resigned.html")
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "sign", "--strip-existing", "-k", fprB, "--out", resigned, attested}, &out, &errOut); code != 0 {
		t.Fatalf("resign code %d out %s err %s", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", "--trusted", fprA, resigned}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "did not match") {
		t.Fatalf("old trust code %d out %s err %s", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", "--trusted", fprB, resigned}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "AUTHENTIC:") {
		t.Fatalf("new trust code %d out %s err %s", code, out.String(), errOut.String())
	}

	missingHome := newGNUPGHome(t)
	defer killGPGAgent(missingHome)
	os.Setenv("GNUPGHOME", missingHome)
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", "--trusted", fprA, attested}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "UNKNOWN: signer's public key is not available") {
		t.Fatalf("missing pub code %d out %s err %s", code, out.String(), errOut.String())
	}

	os.Setenv("GNUPGHOME", home)
	out.Reset()
	errOut.Reset()
	if code := run([]string{"attest", "verify", "--trusted", strings.Repeat("0", 40), attested}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "did not match") {
		t.Fatalf("mismatch code %d out %s err %s", code, out.String(), errOut.String())
	}
}

func newGNUPGHome(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ahg")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	return d
}
func killGPGAgent(home string) {
	cmd := exec.Command("gpgconf", "--kill", "all")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	_ = cmd.Run()
}

func generateKey(t *testing.T, home, uid, email string) string {
	t.Helper()
	args := []string{"--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", uid, "ed25519", "sign", "1d"}
	cmd := exec.Command("gpg", args...)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	if out, err := cmd.CombinedOutput(); err != nil {
		args = []string{"--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", uid, "rsa2048", "sign", "1d"}
		cmd = exec.Command("gpg", args...)
		cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
		if out2, err2 := cmd.CombinedOutput(); err2 != nil {
			t.Fatalf("generate key failed: %v %s / fallback: %v %s", err, out, err2, out2)
		}
	}
	cmd = exec.Command("gpg", "--batch", "--with-colons", "--list-keys", email)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			return fields[9]
		}
	}
	t.Fatalf("fingerprint not found in %s", out)
	return ""
}

func rewriteEvidenceHashesForPayload(t *testing.T, data []byte) []byte {
	t.Helper()
	payload, _, e, err := parseTrailer(data)
	if err != nil {
		t.Fatal(err)
	}
	e.SignedPrefix.SHA256, e.SignedPrefix.SHA512 = payloadHashes(payload)
	e.SignedPrefix.Length = int64(len(payload))
	out, err := buildAttestedFile(payload, e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func corruptEmbeddedSignature(t *testing.T, data []byte) []byte {
	t.Helper()
	payload, _, e, err := parseTrailer(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range e.Signatures {
		if e.Signatures[i].Kind == "openpgp-detached" {
			e.Signatures[i].Armor = strings.Replace(e.Signatures[i].Armor, "A", "B", 1)
			break
		}
	}
	j, _ := json.Marshal(e)
	return []byte(string(payload) + StartMarker + wrapBase64NoTrailingNewline(base64.StdEncoding.EncodeToString(j)) + EndMarker)
}
