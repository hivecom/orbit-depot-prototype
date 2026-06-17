package config

import (
	"testing"
	"time"
)

func TestByteSizeUnmarshal(t *testing.T) {
	tests := []struct {
		in   string
		want ByteSize
	}{
		{"100MB", 100 * mb},
		{"500MB", 500 * mb},
		{"5GB", 5 * gb},
		{"10KB", 10 * kb},
		{"2TB", 2 * tb},
		{"1.5GB", ByteSize(1.5 * float64(gb))},
		{"1024", 1024},
		{"512B", 512},
		{"0", 0},
		{" 100MB ", 100 * mb},
		{"100mb", 100 * mb}, // case-insensitive suffix
	}
	for _, tt := range tests {
		var b ByteSize
		if err := b.UnmarshalText([]byte(tt.in)); err != nil {
			t.Errorf("UnmarshalText(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if b != tt.want {
			t.Errorf("UnmarshalText(%q) = %d, want %d", tt.in, b, tt.want)
		}
	}
}

func TestByteSizeUnmarshalErrors(t *testing.T) {
	for _, in := range []string{"", "abc", "-1", "10Z", "MB", "1.2.3GB"} {
		var b ByteSize
		if err := b.UnmarshalText([]byte(in)); err == nil {
			t.Errorf("UnmarshalText(%q) = nil error, want error", in)
		}
	}
}

func TestByteSizeString(t *testing.T) {
	tests := []struct {
		in   ByteSize
		want string
	}{
		{100 * mb, "100MB"},
		{5 * gb, "5GB"},
		{2 * tb, "2TB"},
		{10 * kb, "10KB"},
		{512, "512B"},
		{0, "0B"},
	}
	for _, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("ByteSize(%d).String() = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRateUnmarshal(t *testing.T) {
	tests := []struct {
		in     string
		count  int
		window time.Duration
	}{
		{"30/min", 30, time.Minute},
		{"120/minute", 120, time.Minute},
		{"10/sec", 10, time.Second},
		{"2/s", 2, time.Second},
		{"5/hour", 5, time.Hour},
		{"1/h", 1, time.Hour},
		{" 30 / min ", 30, time.Minute},
	}
	for _, tt := range tests {
		var r Rate
		if err := r.UnmarshalText([]byte(tt.in)); err != nil {
			t.Errorf("UnmarshalText(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if r.Count != tt.count || r.Window != tt.window {
			t.Errorf("UnmarshalText(%q) = {%d, %v}, want {%d, %v}", tt.in, r.Count, r.Window, tt.count, tt.window)
		}
	}
}

func TestRateUnmarshalErrors(t *testing.T) {
	for _, in := range []string{"", "30", "0/min", "-1/min", "30/day", "abc/min", "/min", "30/"} {
		var r Rate
		if err := r.UnmarshalText([]byte(in)); err == nil {
			t.Errorf("UnmarshalText(%q) = nil error, want error", in)
		}
	}
}

func TestRateString(t *testing.T) {
	tests := []struct {
		in   Rate
		want string
	}{
		{Rate{30, time.Minute}, "30/min"},
		{Rate{10, time.Second}, "10/sec"},
		{Rate{5, time.Hour}, "5/hour"},
	}
	for _, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("Rate%v.String() = %q, want %q", tt.in, got, tt.want)
		}
	}
}
