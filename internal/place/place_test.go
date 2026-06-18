package place

import "testing"

func TestRegistryResolvesConfiguredPlace(t *testing.T) {
	r, err := New(map[string]Definition{"uploads": {}}, "", 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p, err := r.Resolve("uploads")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Prefix != "uploads" || p.Strategy != StrategyDump || p.MaxSize != 100 {
		t.Errorf("Resolve(uploads) = %+v, want uploads/dump/100", p)
	}
}

func TestRegistryConfiguredPlace(t *testing.T) {
	r, err := New(map[string]Definition{
		"avatars": {
			Prefix:      "orbit/user-content/avatars",
			Strategy:    StrategyAccount,
			MaxSize:     2 << 20,
			AllowedMIME: []string{"image/png"},
		},
	}, "", 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p, err := r.Resolve("avatars")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !p.RequireIdentity {
		t.Error("account strategy did not force RequireIdentity")
	}
	if p.MaxSize != 2<<20 {
		t.Errorf("MaxSize = %d, want %d", p.MaxSize, 2<<20)
	}
	// There is no built-in place: an undeclared name does not exist.
	if _, err := r.Resolve("uploads"); err != ErrUnknownPlace {
		t.Errorf("Resolve(uploads) = %v, want ErrUnknownPlace (no built-in place)", err)
	}
}

func TestRegistryDefaultsPrefixAndSize(t *testing.T) {
	r, _ := New(map[string]Definition{"scratch": {}}, "", 50)
	p, _ := r.Resolve("scratch")
	if p.Prefix != "scratch" { // prefix defaults to the place name
		t.Errorf("Prefix = %q, want scratch", p.Prefix)
	}
	if p.Strategy != StrategyDump { // strategy defaults to dump
		t.Errorf("Strategy = %q, want dump", p.Strategy)
	}
	if p.MaxSize != 50 { // max size falls back to the global default
		t.Errorf("MaxSize = %d, want 50", p.MaxSize)
	}
}

func TestRegistryDefaultPlacePointer(t *testing.T) {
	r, err := New(map[string]Definition{"uploads": {}, "avatars": {Strategy: StrategyAccount}}, "uploads", 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// An empty name resolves to the configured default, with that place's rules.
	p, err := r.Resolve("")
	if err != nil {
		t.Fatalf("Resolve(\"\"): %v", err)
	}
	if p.Name != "uploads" {
		t.Errorf("default resolved to %q, want uploads", p.Name)
	}
}

func TestRegistryNoDefault(t *testing.T) {
	r, _ := New(map[string]Definition{"uploads": {}}, "", 100)
	if _, err := r.Resolve(""); err != ErrNoPlaceSpecified {
		t.Errorf("Resolve(\"\") with no default = %v, want ErrNoPlaceSpecified", err)
	}
}

func TestRegistryRejectsUnknownDefault(t *testing.T) {
	if _, err := New(map[string]Definition{"uploads": {}}, "missing", 100); err == nil {
		t.Error("New with unknown default place = nil error, want error")
	}
}

func TestRegistryRejectsBadStrategy(t *testing.T) {
	if _, err := New(map[string]Definition{"x": {Strategy: "weird"}}, "", 100); err == nil {
		t.Error("New with bad strategy = nil error, want error")
	}
}

func TestRegistryUnknownPlace(t *testing.T) {
	r, _ := New(map[string]Definition{"uploads": {}}, "", 100)
	if _, err := r.Resolve("nope"); err != ErrUnknownPlace {
		t.Errorf("Resolve(nope) = %v, want ErrUnknownPlace", err)
	}
}

func TestValidate(t *testing.T) {
	p := Place{Name: "p", Prefix: "p", Strategy: StrategyDump, MaxSize: 1000, AllowedMIME: []string{"image/png"}}

	if err := p.Validate(Request{Size: 500, ContentType: "image/png"}, false); err != nil {
		t.Errorf("valid request rejected: %v", err)
	}
	if err := p.Validate(Request{Size: 0, ContentType: "image/png"}, false); err != ErrInvalidRequest {
		t.Errorf("zero size err = %v, want ErrInvalidRequest", err)
	}
	if err := p.Validate(Request{Size: 2000, ContentType: "image/png"}, false); err != ErrTooLarge {
		t.Errorf("oversize err = %v, want ErrTooLarge", err)
	}
	if err := p.Validate(Request{Size: 500, ContentType: "text/plain"}, false); err != ErrMIMENotAllowed {
		t.Errorf("bad mime err = %v, want ErrMIMENotAllowed", err)
	}

	ident := Place{Name: "a", Prefix: "a", Strategy: StrategyAccount, RequireIdentity: true, MaxSize: 1000}
	if err := ident.Validate(Request{Size: 500}, true); err != ErrIdentityRequired {
		t.Errorf("anonymous to identity-required place err = %v, want ErrIdentityRequired", err)
	}
}
