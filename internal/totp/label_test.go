package totp

import (
	"net/url"
	"strings"
	"testing"
)

func TestOTPAuthLabelEscaping(t *testing.T) {
	for _, name := range []string{"first last", "user/name", "a:b", "Zoë"} {
		raw := OTPAuth(name, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(u.Path, ":"+name) {
			t.Fatalf("label %q decoded as %q", name, u.Path)
		}
	}
}
