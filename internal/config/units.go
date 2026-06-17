package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ByteSize is a size in bytes parsed from human-friendly TOML values like
// "100MB" or "5GB". Suffixes are base-1024 (MB = 1024*1024). A bare number is
// taken as bytes.
type ByteSize int64

const (
	kb = 1024
	mb = 1024 * kb
	gb = 1024 * mb
	tb = 1024 * gb
)

// UnmarshalText implements encoding.TextUnmarshaler so TOML strings decode
// directly into a ByteSize.
func (b *ByteSize) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	if s == "" {
		return fmt.Errorf("empty size")
	}

	upper := strings.ToUpper(s)
	mult := int64(1)
	switch {
	case strings.HasSuffix(upper, "TB"):
		mult, s = tb, s[:len(s)-2]
	case strings.HasSuffix(upper, "GB"):
		mult, s = gb, s[:len(s)-2]
	case strings.HasSuffix(upper, "MB"):
		mult, s = mb, s[:len(s)-2]
	case strings.HasSuffix(upper, "KB"):
		mult, s = kb, s[:len(s)-2]
	case strings.HasSuffix(upper, "B"):
		mult, s = 1, s[:len(s)-1]
	}

	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return fmt.Errorf("invalid size %q: %w", text, err)
	}
	if n < 0 {
		return fmt.Errorf("invalid size %q: negative", text)
	}
	*b = ByteSize(n * float64(mult))
	return nil
}

// String renders the size back in a compact human-friendly form.
func (b ByteSize) String() string {
	switch {
	case b >= tb && b%tb == 0:
		return fmt.Sprintf("%dTB", int64(b)/tb)
	case b >= gb && b%gb == 0:
		return fmt.Sprintf("%dGB", int64(b)/gb)
	case b >= mb && b%mb == 0:
		return fmt.Sprintf("%dMB", int64(b)/mb)
	case b >= kb && b%kb == 0:
		return fmt.Sprintf("%dKB", int64(b)/kb)
	default:
		return fmt.Sprintf("%dB", int64(b))
	}
}

// Rate is a request rate parsed from values like "30/min". It is the unit the
// Limiter seam consumes: a count of events permitted per window.
type Rate struct {
	Count  int
	Window time.Duration
}

// UnmarshalText implements encoding.TextUnmarshaler for values like "30/min",
// "120/min", "10/sec", "5/hour".
func (r *Rate) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	count, unit, ok := strings.Cut(s, "/")
	if !ok {
		return fmt.Errorf("invalid rate %q: expected <count>/<unit>", text)
	}

	n, err := strconv.Atoi(strings.TrimSpace(count))
	if err != nil {
		return fmt.Errorf("invalid rate %q: %w", text, err)
	}
	if n <= 0 {
		return fmt.Errorf("invalid rate %q: count must be positive", text)
	}

	var window time.Duration
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "s", "sec", "second":
		window = time.Second
	case "m", "min", "minute":
		window = time.Minute
	case "h", "hour":
		window = time.Hour
	default:
		return fmt.Errorf("invalid rate %q: unknown unit %q (use sec, min, hour)", text, unit)
	}

	r.Count, r.Window = n, window
	return nil
}

// Zero reports whether the rate is unset.
func (r Rate) Zero() bool { return r.Count == 0 || r.Window == 0 }

// String renders the rate back to its "<count>/<unit>" form.
func (r Rate) String() string {
	switch r.Window {
	case time.Second:
		return fmt.Sprintf("%d/sec", r.Count)
	case time.Minute:
		return fmt.Sprintf("%d/min", r.Count)
	case time.Hour:
		return fmt.Sprintf("%d/hour", r.Count)
	default:
		return fmt.Sprintf("%d/%s", r.Count, r.Window)
	}
}
