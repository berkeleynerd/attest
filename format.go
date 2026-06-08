package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	ToolName    = "attest"
	ToolVersion = "0.1.0"

	StartMarker = "\n<!--ATTEST EVIDENCE V1\n"
	EndMarker   = "\nATTEST END-->\n"
)

var (
	errMissingStart     = errors.New("attestation start marker is missing")
	errMissingEnd       = errors.New("attestation end marker is missing")
	errDuplicateStart   = errors.New("attestation start marker appears more than once")
	errDuplicateEnd     = errors.New("attestation end marker appears more than once")
	errEndBeforeStart   = errors.New("attestation end marker appears before start marker")
	errTrailingBytes    = errors.New("bytes appear after attestation end marker")
	errMalformedBase64  = errors.New("attestation evidence base64 is malformed")
	errMalformedJSON    = errors.New("attestation evidence JSON is malformed")
	errUnsupportedSig   = errors.New("no supported OpenPGP detached signature object exists")
	errPayloadStartMark = errors.New("signed payload contains attestation start marker")
	errPayloadEndMark   = errors.New("signed payload contains attestation end marker")
	errEvidenceRequired = errors.New("required evidence fields are missing or invalid")
	errPayloadLen       = errors.New("signed payload length does not match evidence")
	errPayloadHash      = errors.New("signed payload hash mismatch")
)

type Evidence struct {
	Format       string          `json:"format"`
	Version      int             `json:"version"`
	CreatedUTC   string          `json:"created_utc"`
	SignedPrefix SignedPrefix    `json:"signed_prefix"`
	Signatures   []SignatureInfo `json:"signatures"`
	Tool         ToolInfo        `json:"tool"`
}

type SignedPrefix struct {
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

type SignatureInfo struct {
	Kind    string `json:"kind"`
	Profile string `json:"profile"`
	Armor   string `json:"armor"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ParsedAttestation struct {
	Payload      []byte
	Evidence     Evidence
	EvidenceJSON []byte
	Signature    SignatureInfo
}

func newEvidence(payload []byte, armor string, now time.Time) Evidence {
	sha256Hex, sha512Hex := payloadHashes(payload)
	return Evidence{
		Format:     "attest-evidence-v1",
		Version:    1,
		CreatedUTC: now.UTC().Format(time.RFC3339),
		SignedPrefix: SignedPrefix{
			Length: int64(len(payload)),
			SHA256: sha256Hex,
			SHA512: sha512Hex,
		},
		Signatures: []SignatureInfo{{Kind: "openpgp-detached", Profile: "gpg-classical", Armor: armor}},
		Tool:       ToolInfo{Name: ToolName, Version: ToolVersion},
	}
}

func payloadHashes(payload []byte) (string, string) {
	s256 := sha256.Sum256(payload)
	s512 := sha512.Sum512(payload)
	return hex.EncodeToString(s256[:]), hex.EncodeToString(s512[:])
}

func ensurePayloadHasNoMarkers(payload []byte) error {
	if bytes.Contains(payload, []byte(StartMarker)) {
		return errPayloadStartMark
	}
	if bytes.Contains(payload, []byte(EndMarker)) {
		return errPayloadEndMark
	}
	return nil
}

func encodeEvidenceJSON(e Evidence) ([]byte, error) {
	return json.Marshal(e)
}

func wrapBase64NoTrailingNewline(s string) string {
	if len(s) <= 76 {
		return s
	}
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76])
		b.WriteByte('\n')
		s = s[76:]
	}
	b.WriteString(s)
	return b.String()
}

func buildAttestedFile(payload []byte, evidence Evidence) ([]byte, error) {
	if err := ensurePayloadHasNoMarkers(payload); err != nil {
		return nil, err
	}
	j, err := encodeEvidenceJSON(evidence)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(j)
	wrapped := wrapBase64NoTrailingNewline(encoded)
	out := make([]byte, 0, len(payload)+len(StartMarker)+len(wrapped)+len(EndMarker))
	out = append(out, payload...)
	out = append(out, StartMarker...)
	out = append(out, wrapped...)
	out = append(out, EndMarker...)
	return out, nil
}

func stripASCIIWhitespace(s []byte) []byte {
	out := make([]byte, 0, len(s))
	for _, c := range s {
		switch c {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			continue
		default:
			out = append(out, c)
		}
	}
	return out
}

func parseTrailer(data []byte) (payload []byte, evidenceJSON []byte, evidence Evidence, err error) {
	start := []byte(StartMarker)
	end := []byte(EndMarker)
	firstStart := bytes.Index(data, start)
	if firstStart < 0 {
		err = errMissingStart
		return
	}
	if bytes.Index(data[firstStart+len(start):], start) >= 0 {
		err = errDuplicateStart
		return
	}
	firstEnd := bytes.Index(data, end)
	if firstEnd < 0 {
		err = errMissingEnd
		return
	}
	if bytes.Index(data[firstEnd+len(end):], end) >= 0 {
		err = errDuplicateEnd
		return
	}
	if firstEnd < firstStart {
		err = errEndBeforeStart
		return
	}
	if firstEnd+len(end) != len(data) {
		err = errTrailingBytes
		return
	}
	payload = data[:firstStart]
	body := data[firstStart+len(start) : firstEnd]
	compact := stripASCIIWhitespace(body)
	evidenceJSON, err = base64.StdEncoding.Strict().DecodeString(string(compact))
	if err != nil {
		err = fmt.Errorf("%w: %v", errMalformedBase64, err)
		return
	}
	if err = json.Unmarshal(evidenceJSON, &evidence); err != nil {
		err = fmt.Errorf("%w: %v", errMalformedJSON, err)
		return
	}
	return
}

func validateEvidenceShape(e Evidence) error {
	if e.Format != "attest-evidence-v1" || e.Version != 1 || e.SignedPrefix.Length < 0 || e.SignedPrefix.SHA256 == "" || e.SignedPrefix.SHA512 == "" || len(e.Signatures) == 0 {
		return errEvidenceRequired
	}
	return nil
}

func firstOpenPGPSignature(e Evidence) (SignatureInfo, bool) {
	for _, sig := range e.Signatures {
		if sig.Kind == "openpgp-detached" {
			return sig, true
		}
	}
	return SignatureInfo{}, false
}

func parseAndValidateAttestation(data []byte) (ParsedAttestation, error) {
	payload, evidenceJSON, evidence, err := parseTrailer(data)
	if err != nil {
		return ParsedAttestation{}, err
	}
	if err := validateEvidenceShape(evidence); err != nil {
		return ParsedAttestation{}, err
	}
	if int64(len(payload)) != evidence.SignedPrefix.Length {
		return ParsedAttestation{}, errPayloadLen
	}
	sha256Hex, sha512Hex := payloadHashes(payload)
	if !strings.EqualFold(sha256Hex, evidence.SignedPrefix.SHA256) || !strings.EqualFold(sha512Hex, evidence.SignedPrefix.SHA512) {
		return ParsedAttestation{}, errPayloadHash
	}
	sig, ok := firstOpenPGPSignature(evidence)
	if !ok || sig.Armor == "" {
		return ParsedAttestation{}, errUnsupportedSig
	}
	return ParsedAttestation{Payload: payload, Evidence: evidence, EvidenceJSON: evidenceJSON, Signature: sig}, nil
}

func payloadForSigning(input []byte, stripExisting bool) ([]byte, error) {
	if !stripExisting {
		if bytes.Contains(input, []byte(StartMarker)) {
			return nil, errors.New("input already contains an attestation trailer; use --strip-existing to re-sign")
		}
		if bytes.Contains(input, []byte(EndMarker)) {
			return nil, errors.New("input contains attestation marker bytes")
		}
		return input, nil
	}
	if !bytes.Contains(input, []byte(StartMarker)) && !bytes.Contains(input, []byte(EndMarker)) {
		return input, nil
	}
	payload, _, _, err := parseTrailer(input)
	if err != nil {
		return nil, fmt.Errorf("existing attestation trailer is malformed: %w", err)
	}
	return payload, nil
}

func normalizeFingerprint(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}
