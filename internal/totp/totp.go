package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Period    = 30
	Digits    = 6
	MinSecret = 10
	Issuer    = "LabSSO"
	ACR       = "urn:labsso:acr:mfa"
	TimeSync  = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
)

var rawStd = base32.StdEncoding.WithPadding(base32.NoPadding)

func ParseSecret(raw []byte) ([]byte, error) {
	var b32 string
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		b32 = s
		break
	}
	if b32 == "" {
		return nil, fmt.Errorf("empty totp secret")
	}
	b32 = strings.ReplaceAll(b32, " ", "")
	secret, err := base32.StdEncoding.DecodeString(b32)
	if err != nil {
		secret, err = rawStd.DecodeString(strings.TrimRight(b32, "="))
	}
	if err != nil {
		return nil, fmt.Errorf("invalid totp secret: %w", err)
	}
	if len(secret) < MinSecret {
		return nil, fmt.Errorf("totp secret shorter than %d bytes", MinSecret)
	}
	return secret, nil
}

func EncodeSecret(secret []byte) string {
	return rawStd.EncodeToString(secret)
}

func Generate() ([]byte, error) {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return b[:], nil
}

func OTPAuth(username, secretB32 string) string {
	label := Issuer + ":" + url.QueryEscape(username)
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", Issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func Code(secret []byte, now time.Time) string {
	return hotp(secret, now.Unix()/Period)
}

func Verify(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	t := now.Unix() / Period
	for _, step := range []int64{t, t - 1, t + 1} {
		want := hotp(secret, step)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func hotp(secret []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (int(sum[off])&0x7f)<<24 | int(sum[off+1])<<16 | int(sum[off+2])<<8 | int(sum[off+3])
	n := bin % 1_000_000
	return fmt.Sprintf("%06d", n)
}
