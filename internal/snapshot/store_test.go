package snapshot_test

import (
	"testing"

	"github.com/hilather/go-lab-sso/internal/snapshot"
)

func TestInstallBootstrapNilIsNoop(t *testing.T) {
	st := snapshot.NewStore()
	if st.InstallBootstrap(nil) != nil {
		t.Fatal("nil install should be noop")
	}
	if st.Load() != nil {
		t.Fatal("live snapshot must stay empty")
	}
}

func TestSwapAndPrevious(t *testing.T) {
	st := snapshot.NewStore()
	a := &snapshot.Snapshot{Revision: "sha256:a", Generation: 1}
	b := &snapshot.Snapshot{Revision: "sha256:b", Generation: 2}
	st.InstallBootstrap(a)
	st.Swap(b)
	if st.Load().Revision != "sha256:b" {
		t.Fatal(st.Load().Revision)
	}
	if st.Previous().Revision != "sha256:a" {
		t.Fatal(st.Previous().Revision)
	}
	if st.Bootstrap().Revision != "sha256:a" {
		t.Fatal("bootstrap pointer must not change on swap")
	}
}
