package fs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// uploadCap is the capability a presigned fs upload URL carries: which object
// key may be written, under what constraints, until when. It is the fs
// equivalent of the constraints baked into an S3 presigned signature.
type uploadCap struct {
	key         string
	maxSize     int64
	contentType string
	expires     time.Time
}

// mac computes the HMAC over the capability's canonical form. The secret is
// per-process, so signatures do not survive a restart (acceptable: fs is
// single-box and presigned URLs are short-lived).
func (d *Driver) mac(c uploadCap) string {
	h := hmac.New(sha256.New, d.secret)
	fmt.Fprintf(h, "%s\n%d\n%s\n%d", c.key, c.maxSize, c.contentType, c.expires.Unix())
	return hex.EncodeToString(h.Sum(nil))
}

// signUpload returns the query parameters that authorize an upload to key.
func (d *Driver) signUpload(c uploadCap) url.Values {
	v := url.Values{}
	v.Set("exp", strconv.FormatInt(c.expires.Unix(), 10))
	v.Set("size", strconv.FormatInt(c.maxSize, 10))
	v.Set("ct", c.contentType)
	v.Set("sig", d.mac(c))
	return v
}

// verifyUpload reconstructs the capability from the request query and checks
// its signature and expiry. A valid capability means the bearer was authorized
// at presign time to write exactly this key under these constraints.
func (d *Driver) verifyUpload(key string, q url.Values) (uploadCap, error) {
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil {
		return uploadCap{}, errBadCapability
	}
	size, err := strconv.ParseInt(q.Get("size"), 10, 64)
	if err != nil {
		return uploadCap{}, errBadCapability
	}

	c := uploadCap{key: key, maxSize: size, contentType: q.Get("ct"), expires: time.Unix(exp, 0)}

	if !hmac.Equal([]byte(d.mac(c)), []byte(q.Get("sig"))) {
		return uploadCap{}, errBadSignature
	}
	if time.Now().After(c.expires) {
		return uploadCap{}, errExpired
	}
	return c, nil
}
