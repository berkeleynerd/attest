package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type trustedList []string

func (t *trustedList) String() string { return strings.Join(*t, ",") }
func (t *trustedList) Set(v string) error {
	*t = append(*t, v)
	return nil
}

func main() { os.Exit(run(os.Args, os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 || args[1] == "-h" || args[1] == "--help" || args[1] == "help" {
		printHelp(stdout)
		return 0
	}
	switch args[1] {
	case "sign":
		return runSign(args[2:], stdout, stderr)
	case "verify":
		return runVerify(args[2:], stdout, stderr)
	case "extract":
		return runExtract(args[2:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n", args[1])
		return 2
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func runSign(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("sign", stderr)
	var key, out, gpgPath string
	var force, stripExisting bool
	fs.StringVar(&key, "k", "", "GPG key ID or fingerprint")
	fs.StringVar(&key, "key", "", "GPG key ID or fingerprint")
	fs.StringVar(&out, "o", "", "output path")
	fs.StringVar(&out, "out", "", "output path")
	fs.StringVar(&gpgPath, "gpg", "gpg", "GPG binary path")
	fs.BoolVar(&force, "force", false, "overwrite output")
	fs.BoolVar(&stripExisting, "strip-existing", false, "remove well-formed trailer before signing")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if key == "" || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: usage: attest sign -k KEY [options] INPUT.html")
		return 2
	}
	inputPath := fs.Arg(0)
	if out == "" {
		out = defaultOutputPath(inputPath)
	}
	input, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: read input: %v\n", err)
		return 2
	}
	payload, err := payloadForSigning(input, stripExisting)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if err := ensurePayloadHasNoMarkers(payload); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if !force {
		if _, err := os.Stat(out); err == nil {
			fmt.Fprintf(stderr, "error: output already exists: %s\n", out)
			return 2
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "error: check output: %v\n", err)
			return 2
		}
	}
	armor, err := gpgDetachSign(gpgPath, key, payload)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	evidence := newEvidence(payload, armor, time.Now())
	attested, err := buildAttestedFile(payload, evidence)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if err := atomicWriteFile(out, attested, 0644); err != nil {
		fmt.Fprintf(stderr, "error: write output: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "signed: %s\n", out)
	return 0
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	var gpgPath, payloadOut, sigOut, evidenceOut string
	var trusted trustedList
	fs.Var(&trusted, "t", "trusted fingerprint")
	fs.Var(&trusted, "trusted", "trusted fingerprint")
	fs.StringVar(&gpgPath, "gpg", "gpg", "GPG binary path")
	fs.StringVar(&payloadOut, "payload-out", "", "write signed payload")
	fs.StringVar(&sigOut, "sig-out", "", "write detached signature")
	fs.StringVar(&evidenceOut, "evidence-out", "", "write decoded evidence JSON")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: usage: attest verify [options] INPUT.attest.html")
		return 2
	}
	parsed, code := readParsed(fs.Arg(0), stdout, stderr)
	if code != 0 {
		return code
	}
	cls, err := verifyDetachedWithGPG(gpgPath, parsed.Payload, parsed.Signature.Armor)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if cls.CryptoValid {
		actual := normalizeFingerprint(cls.Fingerprint)
		if len(trusted) > 0 {
			matched := false
			for _, t := range trusted {
				if normalizeFingerprint(t) == actual {
					matched = true
				}
			}
			if !matched {
				fmt.Fprintln(stdout, "INVALID: signer fingerprint did not match trusted fingerprint")
				fmt.Fprintf(stdout, "SIGNER: %s\n", actual)
				return 1
			}
			if err := writeVerifyOutputs(payloadOut, sigOut, evidenceOut, parsed); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return 2
			}
			fmt.Fprintln(stdout, "AUTHENTIC: signature verified and trusted fingerprint matched")
			fmt.Fprintln(stdout, "HASH: sha256 and sha512 match")
			fmt.Fprintf(stdout, "SIGNER: %s\n", actual)
			fmt.Fprintln(stdout, "TRUST: trusted fingerprint matched")
			return 0
		}
		if err := writeVerifyOutputs(payloadOut, sigOut, evidenceOut, parsed); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, "CRYPTO-VALID: signature math verified")
		fmt.Fprintln(stdout, "HASH: sha256 and sha512 match")
		fmt.Fprintf(stdout, "SIGNER: %s\n", actual)
		fmt.Fprintln(stdout, "WARNING: no trusted fingerprint supplied; authenticity is not established")
		return 3
	}
	printNonValidVerdict(stdout, cls)
	return 1
}

func runExtract(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("extract", stderr)
	var payloadOut, sigOut, evidenceOut string
	fs.StringVar(&payloadOut, "payload-out", "", "write signed payload")
	fs.StringVar(&sigOut, "sig-out", "", "write detached signature")
	fs.StringVar(&evidenceOut, "evidence-out", "", "write decoded evidence JSON")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if fs.NArg() != 1 || (payloadOut == "" && sigOut == "" && evidenceOut == "") {
		fmt.Fprintln(stderr, "error: usage: attest extract [options] INPUT.attest.html; at least one output option is required")
		return 2
	}
	parsed, code := readParsed(fs.Arg(0), stdout, stderr)
	if code != 0 {
		return code
	}
	if err := writeVerifyOutputs(payloadOut, sigOut, evidenceOut, parsed); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	fmt.Fprintln(stdout, "extracted")
	return 0
}

func readParsed(path string, stdout, stderr io.Writer) (ParsedAttestation, int) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: read input: %v\n", err)
		return ParsedAttestation{}, 2
	}
	parsed, err := parseAndValidateAttestation(data)
	if err != nil {
		if errors.Is(err, errPayloadHash) {
			fmt.Fprintln(stdout, "INVALID: signed payload hash mismatch")
			return ParsedAttestation{}, 1
		}
		fmt.Fprintf(stdout, "INVALID: %v\n", err)
		return ParsedAttestation{}, 1
	}
	return parsed, 0
}

func printNonValidVerdict(stdout io.Writer, cls VerificationClassification) {
	switch cls.Verdict {
	case VerdictInvalid:
		fmt.Fprintln(stdout, "INVALID: OpenPGP signature verification failed")
	case VerdictExpired:
		fmt.Fprintln(stdout, "EXPIRED: signature or signing key is expired")
	case VerdictRevoked:
		fmt.Fprintln(stdout, "REVOKED: signing key is revoked")
	case VerdictUnknown:
		if cls.Message == "signer's public key is not available" {
			fmt.Fprintln(stdout, "UNKNOWN: signer's public key is not available")
		} else {
			fmt.Fprintf(stdout, "UNKNOWN: %s\n", cls.Message)
		}
	default:
		fmt.Fprintf(stdout, "UNKNOWN: %s\n", cls.Message)
	}
}

func writeVerifyOutputs(payloadOut, sigOut, evidenceOut string, p ParsedAttestation) error {
	if payloadOut != "" {
		if err := os.WriteFile(payloadOut, p.Payload, 0644); err != nil {
			return err
		}
	}
	if sigOut != "" {
		if p.Signature.Armor == "" {
			return errUnsupportedSig
		}
		if err := os.WriteFile(sigOut, []byte(p.Signature.Armor), 0644); err != nil {
			return err
		}
	}
	if evidenceOut != "" {
		if err := os.WriteFile(evidenceOut, p.EvidenceJSON, 0644); err != nil {
			return err
		}
	}
	return nil
}

func defaultOutputPath(input string) string {
	dir := filepath.Dir(input)
	base := filepath.Base(input)
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".html") {
		base = base[:len(base)-5] + ".attest.html"
	} else if strings.HasSuffix(lower, ".htm") {
		base = base[:len(base)-4] + ".attest.html"
	} else {
		base += ".attest.html"
	}
	if dir == "." {
		return base
	}
	return filepath.Join(dir, base)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".attest-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func printHelp(w io.Writer) {
	fmt.Fprintf(w, `%s %s

Usage:
  attest sign [options] INPUT.html
  attest verify [options] INPUT.attest.html
  attest extract [options] INPUT.attest.html
  attest help

Options must appear before the input file.

sign options:
  -k, --key KEY        Required. GPG key ID or fingerprint passed to gpg --local-user.
  -o, --out FILE       Output path. Default: derived from input path.
  --gpg PATH           GPG binary path. Default: gpg.
  --force              Overwrite output if it already exists.
  --strip-existing     Remove a well-formed existing trailer and re-sign its payload.

verify options:
  -t, --trusted FPR    Expected signer fingerprint. May be repeated.
  --gpg PATH           GPG binary path. Default: gpg.
  --payload-out FILE   Write signed payload bytes to FILE.
  --sig-out FILE       Write embedded OpenPGP signature to FILE.
  --evidence-out FILE  Write decoded evidence JSON to FILE.

extract options:
  --payload-out FILE   Write signed payload bytes.
  --sig-out FILE       Write OpenPGP detached signature.
  --evidence-out FILE  Write decoded evidence JSON.
`, ToolName, ToolVersion)
}
