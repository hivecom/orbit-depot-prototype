package place

import (
	"strings"
	"testing"
	"time"
)

func dumpPlace() Place {
	return Place{Name: "uploads", Prefix: "uploads", Strategy: StrategyDump, MaxSize: 1 << 20}
}

func TestDeriveKeyDumpAuthenticated(t *testing.T) {
	p := dumpPlace()
	key, err := p.DeriveKey("user-123", "https://id.example.com", false, Request{Filename: "screenshot.png"})
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	parts := strings.Split(key, "/")
	if len(parts) != 4 {
		t.Fatalf("key = %q, want 4 segments", key)
	}
	if parts[0] != "uploads" {
		t.Errorf("prefix = %q, want uploads", parts[0])
	}
	if len(parts[1]) != 16 { // 8 bytes hex
		t.Errorf("owner = %q, want 16-char hash", parts[1])
	}
	if !strings.Contains(parts[2], "-") || !strings.Contains(parts[2], "T") {
		t.Errorf("unique segment = %q, want timestamp-random form", parts[2])
	}
	if parts[3] != "screenshot.png" {
		t.Errorf("filename = %q, want screenshot.png", parts[3])
	}
}

func TestDeriveKeyAnonymousUsesReservedOwner(t *testing.T) {
	p := dumpPlace()
	key, err := p.DeriveKey("", "", true, Request{Filename: "f.txt"})
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if owner := strings.Split(key, "/")[1]; owner != anonymousOwner {
		t.Errorf("owner = %q, want %q", owner, anonymousOwner)
	}
}

// The owner segment must derive from the immutable subject, never the username,
// so a rename does not move files. DeriveKey takes only subject+issuer, and the
// owner must be stable for a subject and distinct across subjects.
func TestDeriveKeyOwnerStableBySubject(t *testing.T) {
	p := dumpPlace()
	owner := func(sub, iss string) string {
		key, err := p.DeriveKey(sub, iss, false, Request{Filename: "f"})
		if err != nil {
			t.Fatalf("DeriveKey: %v", err)
		}
		return strings.Split(key, "/")[1]
	}

	if owner("sub-1", "iss") != owner("sub-1", "iss") {
		t.Error("owner not stable for the same subject")
	}
	if owner("sub-1", "iss") == owner("sub-2", "iss") {
		t.Error("distinct subjects produced the same owner")
	}
	if owner("sub-1", "iss-a") == owner("sub-1", "iss-b") {
		t.Error("same subject on distinct issuers produced the same owner")
	}
}

func TestDeriveKeyAccountStrategy(t *testing.T) {
	p := Place{Name: "avatars", Prefix: "orbit/user-content/avatars", Strategy: StrategyAccount, RequireIdentity: true}

	key, err := p.DeriveKey("user-1", "iss", false, Request{Filename: "me.png"})
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !strings.HasPrefix(key, "orbit/user-content/avatars/") || !strings.HasSuffix(key, "/me.png") {
		t.Errorf("account key = %q", key)
	}
	// Same identity derives the same key (deterministic, so re-upload overwrites).
	again, _ := p.DeriveKey("user-1", "iss", false, Request{Filename: "me.png"})
	if key != again {
		t.Errorf("account strategy not deterministic: %q != %q", key, again)
	}

	// Anonymous cannot use a per-account key.
	if _, err := p.DeriveKey("", "", true, Request{Filename: "x.png"}); err != ErrIdentityRequired {
		t.Errorf("anonymous account key err = %v, want ErrIdentityRequired", err)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := map[string]string{
		"screenshot.png":   "screenshot.png",
		"../../etc/passwd": "passwd",
		`a\b\c.png`:        "c.png",
		"my file (1).png":  "my_file__1_.png",
		"":                 "file",
		"...":              "file",
		".":                "file",
		"..":               "file",
		"résumé.pdf":       "r_sum_.pdf",
	}
	for in, want := range tests {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUniqueSegmentChronological(t *testing.T) {
	t1 := time.Date(2026, 6, 17, 11, 18, 35, 0, time.UTC)
	t2 := time.Date(2026, 6, 17, 11, 18, 36, 0, time.UTC)

	a, err := uniqueSegment(t1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := uniqueSegment(t2)
	if err != nil {
		t.Fatal(err)
	}
	if a >= b {
		t.Errorf("uniqueSegment not chronological: %q >= %q", a, b)
	}
	if !strings.HasPrefix(a, "20260617T111835.000-") {
		t.Errorf("unexpected unique segment format: %q", a)
	}
}
