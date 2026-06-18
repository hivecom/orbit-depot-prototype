package quota

import (
	"context"
	"errors"
	"testing"
)

// fakeUsage returns a fixed usage total, or an error.
type fakeUsage struct {
	used int64
	err  error
}

func (f fakeUsage) Usage(context.Context, string, string) (int64, error) {
	return f.used, f.err
}

func TestEnforcerLimit(t *testing.T) {
	e := New(nil, 500, map[string]int64{"vip": 5000})
	if got := e.Limit("vip"); got != 5000 {
		t.Errorf("Limit(vip) = %d, want 5000 (override)", got)
	}
	if got := e.Limit("someone"); got != 500 {
		t.Errorf("Limit(someone) = %d, want 500 (default)", got)
	}
}

func TestEnforcerCheck(t *testing.T) {
	ctx := context.Background()

	t.Run("under limit passes", func(t *testing.T) {
		e := New(fakeUsage{used: 10}, 100, nil)
		if err := e.Check(ctx, "u1", "iss", 50); err != nil {
			t.Fatalf("Check() = %v, want nil", err)
		}
	})

	t.Run("at the limit passes", func(t *testing.T) {
		e := New(fakeUsage{used: 90}, 100, nil)
		if err := e.Check(ctx, "u1", "iss", 10); err != nil {
			t.Fatalf("Check() = %v, want nil (boundary is inclusive)", err)
		}
	})

	t.Run("over limit is ErrExceeded", func(t *testing.T) {
		e := New(fakeUsage{used: 90}, 100, nil)
		if err := e.Check(ctx, "u1", "iss", 11); !errors.Is(err, ErrExceeded) {
			t.Fatalf("Check() = %v, want ErrExceeded", err)
		}
	})

	t.Run("override replaces the default", func(t *testing.T) {
		e := New(fakeUsage{used: 200}, 100, map[string]int64{"bot": 1000})
		if err := e.Check(ctx, "bot", "iss", 50); err != nil {
			t.Fatalf("Check() with override = %v, want nil", err)
		}
		// A different account still gets the default and is over it.
		if err := e.Check(ctx, "u1", "iss", 50); !errors.Is(err, ErrExceeded) {
			t.Fatalf("Check() default = %v, want ErrExceeded", err)
		}
	})

	t.Run("non-positive limit is unlimited", func(t *testing.T) {
		e := New(fakeUsage{used: 1 << 40}, 0, nil)
		if err := e.Check(ctx, "u1", "iss", 1<<30); err != nil {
			t.Fatalf("Check() unlimited = %v, want nil", err)
		}
	})

	t.Run("usage read error is not ErrExceeded", func(t *testing.T) {
		boom := errors.New("db down")
		e := New(fakeUsage{err: boom}, 100, nil)
		err := e.Check(ctx, "u1", "iss", 1)
		if errors.Is(err, ErrExceeded) {
			t.Fatalf("Check() = ErrExceeded, want the underlying read error")
		}
		if !errors.Is(err, boom) {
			t.Fatalf("Check() = %v, want wrapped %v", err, boom)
		}
	})
}
