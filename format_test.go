package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func sampleEvidence(payload []byte) Evidence {
	return newEvidence(payload, "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n", time.Unix(0, 0).UTC())
}
func sampleAttested(t *testing.T, payload []byte) []byte {
	t.Helper()
	out, err := buildAttestedFile(payload, sampleEvidence(payload))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEvidenceEncodeDecodeRoundtrip(t *testing.T) {
	payload := []byte("<html>hello</html>\n")
	out := sampleAttested(t, payload)
	parsed, err := parseAndValidateAttestation(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatal("payload changed")
	}
	if parsed.Evidence.Tool.Version != ToolVersion {
		t.Fatal("tool version mismatch")
	}
}

func TestTrailerStructuralRejections(t *testing.T) {
	good := sampleAttested(t, []byte("abc"))
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"missing start", []byte("abc"), errMissingStart},
		{"duplicate start", append(good, []byte(StartMarker)...), errDuplicateStart},
		{"duplicate end", append(good, []byte(EndMarker)...), errDuplicateEnd},
		{"missing end", good[:len(good)-len(EndMarker)], errMissingEnd},
		{"extra bytes", append(append([]byte{}, good...), 'x'), errTrailingBytes},
		{"end before start", []byte(EndMarker + StartMarker), errEndBeforeStart},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseTrailer(tc.data)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestPayloadMarkerRejectedAtSignTime(t *testing.T) {
	if err := ensurePayloadHasNoMarkers([]byte("x" + StartMarker)); !errors.Is(err, errPayloadStartMark) {
		t.Fatalf("start got %v", err)
	}
	if err := ensurePayloadHasNoMarkers([]byte("x" + EndMarker)); !errors.Is(err, errPayloadEndMark) {
		t.Fatalf("end got %v", err)
	}
}

func TestMalformedBase64InvalidJSONAndWrappedBase64(t *testing.T) {
	_, _, _, err := parseTrailer([]byte("p" + StartMarker + "!!!!" + EndMarker))
	if !errors.Is(err, errMalformedBase64) {
		t.Fatalf("got %v", err)
	}
	badJSON := base64.StdEncoding.EncodeToString([]byte("{"))
	_, _, _, err = parseTrailer([]byte("p" + StartMarker + badJSON + EndMarker))
	if !errors.Is(err, errMalformedJSON) {
		t.Fatalf("got %v", err)
	}
	j, _ := json.Marshal(sampleEvidence([]byte("p")))
	enc := base64.StdEncoding.EncodeToString(j)
	wrapped := enc[:10] + "\n\t " + enc[10:]
	_, _, _, err = parseTrailer([]byte("p" + StartMarker + wrapped + EndMarker))
	if err != nil {
		t.Fatalf("wrapped failed: %v", err)
	}
}

func TestUnknownFieldsIgnoredUnknownSignatureSkippedMissingOpenPGP(t *testing.T) {
	payload := []byte("abc")
	e := sampleEvidence(payload)
	j := `{"extra":true,"format":"attest-evidence-v1","version":1,"created_utc":"x","signed_prefix":{"length":3,"sha256":"` + e.SignedPrefix.SHA256 + `","sha512":"` + e.SignedPrefix.SHA512 + `"},"signatures":[{"kind":"future","armor":"x"},{"kind":"openpgp-detached","armor":"sig"}],"tool":{"name":"x","version":"x"}}`
	out := []byte(string(payload) + StartMarker + base64.StdEncoding.EncodeToString([]byte(j)) + EndMarker)
	p, err := parseAndValidateAttestation(out)
	if err != nil {
		t.Fatal(err)
	}
	if p.Signature.Armor != "sig" {
		t.Fatal("did not skip unknown kind")
	}
	e.Signatures = []SignatureInfo{{Kind: "future", Armor: "x"}}
	out, _ = buildAttestedFile(payload, e)
	_, err = parseAndValidateAttestation(out)
	if !errors.Is(err, errUnsupportedSig) {
		t.Fatalf("got %v", err)
	}
}

func TestHashMismatchDetected(t *testing.T) {
	out := sampleAttested(t, []byte("abc"))
	out[0] = 'z'
	_, err := parseAndValidateAttestation(out)
	if !errors.Is(err, errPayloadHash) {
		t.Fatalf("got %v", err)
	}
}

func TestStripExistingLogic(t *testing.T) {
	payload := []byte("abc\n")
	att := sampleAttested(t, payload)
	got, err := payloadForSigning(att, true)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("strip got %q err %v", got, err)
	}
	got, err = payloadForSigning([]byte("whole"), true)
	if err != nil || string(got) != "whole" {
		t.Fatalf("no trailer got %q err %v", got, err)
	}
	corrupt := append([]byte{}, att...)
	corrupt = corrupt[:len(corrupt)-1]
	_, err = payloadForSigning(corrupt, true)
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("wanted malformed, got %v", err)
	}
}

func TestFingerprintNormalization(t *testing.T) {
	got := normalizeFingerprint(" ab cd\nef 123 ")
	if got != "ABCDEF123" {
		t.Fatalf("got %q", got)
	}
}
