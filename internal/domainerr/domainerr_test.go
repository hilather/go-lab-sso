package domainerr_test

import (
	"fmt"
	"testing"

	"github.com/hilather/go-lab-sso/internal/domainerr"
)

func TestCodeOfUnwraps(t *testing.T) {
	err := fmt.Errorf("operations[0]: %w", domainerr.Validation("unknown target"))
	if domainerr.CodeOf(err) != domainerr.CodeValidation {
		t.Fatalf("got %q", domainerr.CodeOf(err))
	}
}
