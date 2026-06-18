package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryAllowsUpToLimitThenDenies(t *testing.T) {
	m := NewMemory()
	defer m.Close()
	ctx := context.Background()

	// burst of 2 per minute: first two allowed, third denied.
	for i := range 2 {
		ok, err := m.Allow(ctx, "k", 2, time.Minute)
		if err != nil || !ok {
			t.Fatalf("event %d: ok=%v err=%v, want allowed", i, ok, err)
		}
	}
	ok, err := m.Allow(ctx, "k", 2, time.Minute)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if ok {
		t.Error("third event allowed, want denied")
	}
}

func TestMemoryKeysAreIndependent(t *testing.T) {
	m := NewMemory()
	defer m.Close()
	ctx := context.Background()

	// Exhaust key "a".
	m.Allow(ctx, "a", 1, time.Minute)
	if ok, _ := m.Allow(ctx, "a", 1, time.Minute); ok {
		t.Fatal("key a not exhausted")
	}
	// Key "b" is unaffected.
	if ok, _ := m.Allow(ctx, "b", 1, time.Minute); !ok {
		t.Error("key b denied, want allowed")
	}
}

func TestMemoryUnconfiguredRateAllows(t *testing.T) {
	m := NewMemory()
	defer m.Close()
	for i := range 100 {
		if ok, _ := m.Allow(context.Background(), "k", 0, 0); !ok {
			t.Fatalf("event %d denied under zero rate, want always allowed", i)
		}
	}
}
