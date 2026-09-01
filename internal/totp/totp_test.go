package totp

import (
	"strings"
	"testing"
	"time"
)

func TestRFC6238AppendixBSixDigits(t *testing.T) {
	secret := []byte("12345678901234567890")
	// Appendix B SHA-1 8-digit 94287082 at t=59 → 6-digit 287082.
	step, ok := Verify(secret, "287082", time.Unix(59, 0).UTC())
	if !ok || step != 1 {
		t.Fatalf("t=59 got ok=%v step=%d code=%s", ok, step, Code(secret, time.Unix(59, 0).UTC()))
	}
	if Code(secret, time.Unix(59, 0).UTC()) != "287082" {
		t.Fatalf("code %s", Code(secret, time.Unix(59, 0).UTC()))
	}
}

func TestWindowAndWrongCode(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(59, 0).UTC()
	cur := Code(secret, now)
	prev := Code(secret, now.Add(-Period*time.Second))
	next := Code(secret, now.Add(Period*time.Second))
	if _, ok := Verify(secret, prev, now); !ok {
		t.Fatal("prev step")
	}
	if _, ok := Verify(secret, next, now); !ok {
		t.Fatal("next step")
	}
	if _, ok := Verify(secret, cur, now); !ok {
		t.Fatal("current")
	}
	if _, ok := Verify(secret, "000000", now); ok {
		t.Fatal("wrong code")
	}
}

func TestParsePaddedAndUnpadded(t *testing.T) {
	raw := []byte("12345678901234567890")
	padded := EncodeSecret(raw)
	// Raw encoding is unpadded; add padding for StdEncoding.
	withPad := padded
	for len(withPad)%8 != 0 {
		withPad += "="
	}
	got, err := ParseSecret([]byte("# comment\n" + withPad + "\n"))
	if err != nil || string(got) != string(raw) {
		t.Fatalf("padded %v %q", err, got)
	}
	got, err = ParseSecret([]byte(padded))
	if err != nil || string(got) != string(raw) {
		t.Fatalf("unpadded %v %q", err, got)
	}
}

func TestOTPAuthUnpadded(t *testing.T) {
	sec, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b32 := EncodeSecret(sec)
	if strings.Contains(b32, "=") {
		t.Fatal("enroll secret must be unpadded")
	}
	u := OTPAuth("alice smith", b32)
	if !strings.Contains(u, "otpauth://totp/") || !strings.Contains(u, "digits=6") {
		t.Fatal(u)
	}
}
