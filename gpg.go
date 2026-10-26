package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type GPGRunResult struct {
	Stdout  string
	Stderr  string
	Exit    int
	Started bool
}

func runGPG(gpgPath string, env []string, args ...string) (GPGRunResult, error) {
	cmd := exec.Command(gpgPath, args...)
	if env != nil {
		cmd.Env = env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := GPGRunResult{Stdout: stdout.String(), Stderr: stderr.String(), Exit: 0, Started: true}
	if err == nil {
		return res, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.Exit = exitErr.ExitCode()
		return res, nil
	}
	res.Started = false
	res.Exit = -1
	return res, err
}

func gpgDetachSign(gpgPath, key string, payload []byte) (string, error) {
	dir, err := os.MkdirTemp("", "attest-gpg-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	payloadPath := filepath.Join(dir, "payload.html")
	sigPath := filepath.Join(dir, "payload.sig.asc")
	if err := os.WriteFile(payloadPath, payload, 0600); err != nil {
		return "", err
	}
	res, err := runGPG(gpgPath, nil, "--batch", "--yes", "--no-textmode", "--armor", "--detach-sign", "--local-user", key, "--output", sigPath, payloadPath)
	if err != nil {
		return "", fmt.Errorf("could not start gpg: %w", err)
	}
	if res.Exit != 0 {
		return "", fmt.Errorf("gpg signing failed: %s", strings.TrimSpace(res.Stderr+"\n"+res.Stdout))
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return "", err
	}
	return string(sig), nil
}

type Verdict string

const (
	VerdictAuthentic   Verdict = "AUTHENTIC"
	VerdictCryptoValid Verdict = "CRYPTO-VALID"
	VerdictInvalid     Verdict = "INVALID"
	VerdictExpired     Verdict = "EXPIRED"
	VerdictRevoked     Verdict = "REVOKED"
	VerdictUnknown     Verdict = "UNKNOWN"
)

type SignatureStatus struct {
	GoodSig        bool
	ValidSig       bool
	BadSig         bool
	ExpSig         bool
	ExpKeySig      bool
	RevKeySig      bool
	ErrSig         bool
	ErrSigRC       string
	NoPubKey       bool
	Fingerprint    string
	SignatureClass string
	UnknownStatus  []string
}

type VerificationClassification struct {
	Verdict     Verdict
	Message     string
	Fingerprint string
	CryptoValid bool
}

func parseGPGStatus(output string) SignatureStatus {
	var st SignatureStatus
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "[GNUPG:] ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "[GNUPG:] "))
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "GOODSIG":
			st.GoodSig = true
		case "VALIDSIG":
			st.ValidSig = true
			if len(fields) > 1 {
				st.Fingerprint = normalizeFingerprint(fields[1])
			}
			if len(fields) > 9 {
				st.SignatureClass = fields[9]
			}
		case "BADSIG":
			st.BadSig = true
		case "EXPSIG":
			st.ExpSig = true
		case "EXPKEYSIG":
			st.ExpKeySig = true
		case "REVKEYSIG":
			st.RevKeySig = true
		case "ERRSIG":
			st.ErrSig = true
			if len(fields) > 6 {
				st.ErrSigRC = fields[6]
			}
		case "NO_PUBKEY":
			st.NoPubKey = true
		default:
			st.UnknownStatus = append(st.UnknownStatus, fields[0])
		}
	}
	return st
}

func classifyGPGStatus(st SignatureStatus, processExit int) VerificationClassification {
	if st.ValidSig && st.SignatureClass != "00" {
		return VerificationClassification{Verdict: VerdictInvalid, Message: "only byte-exact binary-document signatures are accepted", Fingerprint: st.Fingerprint}
	}
	if st.ValidSig && st.ExpSig {
		return VerificationClassification{Verdict: VerdictExpired, Message: "signature or signing key is expired", Fingerprint: st.Fingerprint}
	}
	if st.ValidSig && st.ExpKeySig {
		return VerificationClassification{Verdict: VerdictExpired, Message: "signature or signing key is expired", Fingerprint: st.Fingerprint}
	}
	if st.ValidSig && st.RevKeySig {
		return VerificationClassification{Verdict: VerdictRevoked, Message: "signing key is revoked", Fingerprint: st.Fingerprint}
	}
	if st.BadSig {
		return VerificationClassification{Verdict: VerdictInvalid, Message: "OpenPGP signature verification failed", Fingerprint: st.Fingerprint}
	}
	if st.ErrSig {
		if st.ErrSigRC == "9" || st.NoPubKey {
			return VerificationClassification{Verdict: VerdictUnknown, Message: "signer's public key is not available", Fingerprint: st.Fingerprint}
		}
		return VerificationClassification{Verdict: VerdictUnknown, Message: "GPG could not check the signature", Fingerprint: st.Fingerprint}
	}
	if st.NoPubKey {
		return VerificationClassification{Verdict: VerdictUnknown, Message: "signer's public key is not available", Fingerprint: st.Fingerprint}
	}
	if st.GoodSig && st.ValidSig && processExit == 0 {
		return VerificationClassification{Verdict: VerdictCryptoValid, Message: "signature math verified", Fingerprint: st.Fingerprint, CryptoValid: true}
	}
	return VerificationClassification{Verdict: VerdictUnknown, Message: "GPG did not produce a usable signature verdict", Fingerprint: st.Fingerprint}
}

func verifyDetachedWithGPG(gpgPath string, payload []byte, armor string) (VerificationClassification, error) {
	dir, err := os.MkdirTemp("", "attest-verify-")
	if err != nil {
		return VerificationClassification{}, err
	}
	defer os.RemoveAll(dir)
	payloadPath := filepath.Join(dir, "payload.html")
	sigPath := filepath.Join(dir, "payload.sig.asc")
	if err := os.WriteFile(payloadPath, payload, 0600); err != nil {
		return VerificationClassification{}, err
	}
	if err := os.WriteFile(sigPath, []byte(armor), 0600); err != nil {
		return VerificationClassification{}, err
	}
	res, err := runGPG(gpgPath, nil, "--batch", "--no-auto-key-retrieve", "--status-fd", "1", "--verify", sigPath, payloadPath)
	if err != nil {
		return VerificationClassification{}, fmt.Errorf("could not start gpg: %w", err)
	}
	st := parseGPGStatus(res.Stdout)
	cls := classifyGPGStatus(st, res.Exit)
	return cls, nil
}

func errSigLine(rc int) string {
	return "[GNUPG:] ERRSIG ABCD 1 8 00 0 " + strconv.Itoa(rc) + "\n"
}
