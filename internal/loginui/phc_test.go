package loginui

import "testing"

func TestUnknownPHCFailClosed(t *testing.T) {
	err := verifyPHC("$argon2i$v=19$m=16,t=1,p=1$YWFh$YmJi", []byte("x"))
	if err == nil || err.Error() == "" {
		t.Fatal("unknown id must fail")
	}
}

func TestUnsaltedReject(t *testing.T) {
	if err := verifyPHC("$argon2id$plain", []byte("x")); err == nil {
		t.Fatal("unsalted must reject")
	}
}

func TestPHCParamsPinned(t *testing.T) {
	err := verifyPHC("$argon2id$v=19$m=16,t=1,p=1$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE", []byte("x"))
	if err == nil {
		t.Fatal("non-lab argon2 params must reject")
	}
}
