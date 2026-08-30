package snapshot

import "sync/atomic"

type Store struct {
	active    atomic.Pointer[Snapshot]
	previous  atomic.Pointer[Snapshot]
	bootstrap atomic.Pointer[Snapshot]
}

func NewStore() *Store { return &Store{} }

func (s *Store) Load() *Snapshot {
	if s == nil {
		return nil
	}
	return s.active.Load()
}

func (s *Store) Previous() *Snapshot {
	if s == nil {
		return nil
	}
	return s.previous.Load()
}

func (s *Store) Bootstrap() *Snapshot {
	if s == nil {
		return nil
	}
	return s.bootstrap.Load()
}

func (s *Store) SetBootstrap(next *Snapshot) {
	if s == nil {
		return
	}
	s.bootstrap.Store(next)
}

func (s *Store) Swap(next *Snapshot) *Snapshot {
	if s == nil || next == nil {
		return nil
	}
	prev := s.active.Swap(next)
	if prev != nil {
		s.previous.Store(prev)
	}
	return prev
}

func (s *Store) InstallBootstrap(next *Snapshot) *Snapshot {
	if s == nil || next == nil {
		return nil
	}
	s.SetBootstrap(next)
	return s.Swap(next)
}
