package main

import "testing"

const fpr = "ABCD1234EF567890ABCD1234EF567890ABCD1234"

func TestGPGStatusParserClassifications(t *testing.T) {
	cases := []struct {
		name, out string
		exit      int
		verdict   Verdict
		crypto    bool
		msg       string
	}{
		{"good", "[GNUPG:] GOODSIG 1 Test\n[GNUPG:] VALIDSIG " + fpr + " 2026 0 0 0 0 0 0 0\n", 0, VerdictCryptoValid, true, ""},
		{"expsig", "[GNUPG:] VALIDSIG " + fpr + "\n[GNUPG:] EXPSIG 1 Test\n", 1, VerdictExpired, false, ""},
		{"expkeysig", "[GNUPG:] VALIDSIG " + fpr + "\n[GNUPG:] EXPKEYSIG 1 Test\n", 1, VerdictExpired, false, ""},
		{"revkeysig", "[GNUPG:] VALIDSIG " + fpr + "\n[GNUPG:] REVKEYSIG 1 Test\n", 1, VerdictRevoked, false, ""},
		{"badsig", "[GNUPG:] BADSIG 1 Test\n", 1, VerdictInvalid, false, ""},
		{"nopubkey", "[GNUPG:] NO_PUBKEY ABCD\n", 1, VerdictUnknown, false, "signer's public key is not available"},
		{"errsig9", errSigLine(9), 1, VerdictUnknown, false, "signer's public key is not available"},
		{"future", "[GNUPG:] FUTURE x\n[GNUPG:] GOODSIG 1 Test\n[GNUPG:] VALIDSIG " + fpr + "\n", 0, VerdictCryptoValid, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cls := classifyGPGStatus(parseGPGStatus(tc.out), tc.exit)
			if cls.Verdict != tc.verdict || cls.CryptoValid != tc.crypto {
				t.Fatalf("got %#v", cls)
			}
			if tc.msg != "" && cls.Message != tc.msg {
				t.Fatalf("msg %q", cls.Message)
			}
		})
	}
}
