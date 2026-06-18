// Package place is the routing layer: it decides where an upload's bytes land
// and on what terms. A place is a named destination with a policy (allowed MIME
// types, size cap, identity requirement) and a key strategy. The client names a
// place; it never names the object key. Depot derives the key from the verified
// identity, so a caller can only ever write within their own owner namespace.
//
// Every place is configured; there is no built-in default. A permissive place
// (dump strategy, no MIME restriction) acts as a catch-all, and an operator may
// name one as the default for requests that omit a place. Restricted places
// (avatars, banners, a bot extension's bucket) are pure config and slot in
// without code changes.
package place

import (
	"errors"
	"fmt"
	"slices"
)

// Strategy selects how an object key is derived for a place.
type Strategy string

const (
	// StrategyDump derives a fresh random key per upload:
	// {prefix}/{owner}/{ts}-{rand}/{filename}. Place-link-forget; no overwrite.
	StrategyDump Strategy = "dump"
	// StrategyAccount derives a deterministic per-account key:
	// {prefix}/{owner}/{filename}. A re-upload overwrites. Requires identity.
	StrategyAccount Strategy = "account"
)

// Errors a place can return when authorizing or deriving a key. Handlers map
// these to HTTP status codes.
var (
	ErrUnknownPlace     = errors.New("unknown place")
	ErrNoPlaceSpecified = errors.New("no place specified and no default place configured")
	ErrIdentityRequired = errors.New("this place requires an authenticated identity")
	ErrTooLarge         = errors.New("file exceeds the size limit for this place")
	ErrMIMENotAllowed   = errors.New("content type is not allowed for this place")
	ErrInvalidRequest   = errors.New("invalid upload request")
)

// Definition is the resolved policy for a place, independent of config wiring.
type Definition struct {
	Prefix          string
	Strategy        Strategy
	MaxSize         int64 // 0 means "use the registry's global default"
	AllowedMIME     []string
	RequireIdentity bool
}

// Place is a registered destination ready to validate and derive keys.
type Place struct {
	Name            string
	Prefix          string
	Strategy        Strategy
	MaxSize         int64
	AllowedMIME     []string
	RequireIdentity bool
}

// Request is the client-supplied description of an upload. The client supplies
// what to call the file and how big it is; it never supplies where it goes.
type Request struct {
	Filename    string
	Size        int64
	ContentType string
}

// Registry holds the configured places and an optional default.
type Registry struct {
	places      map[string]Place
	defaultName string // "" means a request must name a place
}

// New builds a registry from place definitions, the name of the default place
// (empty for none), and the global default size cap. Every place is configured;
// there is no built-in place. The default, when set, must name one of defs.
func New(defs map[string]Definition, defaultName string, globalMaxSize int64) (*Registry, error) {
	places := make(map[string]Place, len(defs))
	for name, d := range defs {
		p, err := build(name, d, globalMaxSize)
		if err != nil {
			return nil, fmt.Errorf("place %q: %w", name, err)
		}
		places[name] = p
	}

	if defaultName != "" {
		if _, ok := places[defaultName]; !ok {
			return nil, fmt.Errorf("default place %q is not configured", defaultName)
		}
	}

	return &Registry{places: places, defaultName: defaultName}, nil
}

func build(name string, d Definition, globalMaxSize int64) (Place, error) {
	prefix := d.Prefix
	if prefix == "" {
		prefix = name
	}

	strategy := d.Strategy
	if strategy == "" {
		strategy = StrategyDump
	}
	if strategy != StrategyDump && strategy != StrategyAccount {
		return Place{}, fmt.Errorf("unknown key strategy %q", strategy)
	}

	maxSize := d.MaxSize
	if maxSize == 0 {
		maxSize = globalMaxSize
	}

	requireIdentity := d.RequireIdentity
	// A deterministic per-account key has no meaning without an account, so the
	// account strategy always requires identity.
	if strategy == StrategyAccount {
		requireIdentity = true
	}

	return Place{
		Name:            name,
		Prefix:          prefix,
		Strategy:        strategy,
		MaxSize:         maxSize,
		AllowedMIME:     d.AllowedMIME,
		RequireIdentity: requireIdentity,
	}, nil
}

// Resolve returns the named place. An empty name resolves to the configured
// default place, or ErrNoPlaceSpecified when no default is set.
func (r *Registry) Resolve(name string) (Place, error) {
	if name == "" {
		if r.defaultName == "" {
			return Place{}, ErrNoPlaceSpecified
		}
		name = r.defaultName
	}
	p, ok := r.places[name]
	if !ok {
		return Place{}, ErrUnknownPlace
	}
	return p, nil
}

// Validate checks an upload request against the place's policy.
func (p Place) Validate(req Request, anonymous bool) error {
	if anonymous && p.RequireIdentity {
		return ErrIdentityRequired
	}
	if req.Size <= 0 {
		return ErrInvalidRequest
	}
	if p.MaxSize > 0 && req.Size > p.MaxSize {
		return ErrTooLarge
	}
	if len(p.AllowedMIME) > 0 && !slices.Contains(p.AllowedMIME, req.ContentType) {
		return ErrMIMENotAllowed
	}
	return nil
}
