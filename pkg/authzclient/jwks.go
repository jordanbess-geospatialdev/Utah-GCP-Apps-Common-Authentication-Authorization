package authzclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksCacheTTL is how long a fetched JWKS document is trusted before refresh. Google IAP
// docs recommend caching public keys for at least 5 minutes; our own service publishes
// Cache-Control: max-age=300 on /.well-known/jwks.json.
const jwksCacheTTL = 5 * time.Minute

// jwksMinRefreshInterval throttles forced refreshes triggered by unknown-key lookups so a
// flood of tokens with bogus kids cannot turn the JWKS endpoint into a DoS amplifier.
const jwksMinRefreshInterval = 30 * time.Second

// jwksKey is the wire format of a single JWK, covering both the EC keys our authz service
// publishes and the EC/RSA keys Google publishes for IAP assertions.
type jwksKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

// remoteJWKS fetches and caches a JSON Web Key Set, exposing a jwt.Keyfunc that resolves
// tokens by kid and refreshes (throttled) when an unknown kid appears.
type remoteJWKS struct {
	url     string
	hc      *http.Client
	mu      sync.RWMutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
}

func newRemoteJWKS(url string, hc *http.Client) *remoteJWKS {
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &remoteJWKS{url: url, hc: hc}
}

// keyFunc returns a jwt.Keyfunc bound to this key set. It rejects tokens whose alg is not
// in allowedAlgs before any key lookup, so algorithm confusion (e.g. an RS256 token matched
// against an EC key) cannot reach the signature check.
func (j *remoteJWKS) keyFunc(ctx context.Context, allowedAlgs ...string) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		alg, _ := token.Header["alg"].(string)
		allowed := false
		for _, a := range allowedAlgs {
			if alg == a {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("signing algorithm %q is not accepted", alg)
		}

		kid, _ := token.Header["kid"].(string)
		if key := j.lookup(ctx, kid); key != nil {
			return key, nil
		}
		return nil, fmt.Errorf("no signing key for kid %q", kid)
	}
}

// lookup returns the cached key for kid, refreshing the set when it is stale or the kid is
// unknown. A refresh that hits the throttle window still serves the stale cache if it has
// the key; otherwise it fails closed.
func (j *remoteJWKS) lookup(ctx context.Context, kid string) crypto.PublicKey {
	j.mu.RLock()
	key, have := j.keys[kid]
	fresh := time.Since(j.fetched) < jwksCacheTTL
	j.mu.RUnlock()
	if have && fresh {
		return key
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	// Re-check under write lock: another goroutine may have refreshed while we waited.
	if key, ok := j.keys[kid]; ok && time.Since(j.fetched) < jwksCacheTTL {
		return key
	}
	if j.fetched.IsZero() || time.Since(j.fetched) >= jwksMinRefreshInterval {
		if err := j.fetchLocked(ctx); err == nil {
			return j.keys[kid]
		}
		// Refresh failed: fall through to stale cache (key rotation grace) or fail closed.
	}
	if key, ok := j.keys[kid]; ok {
		return key
	}
	return nil
}

func (j *remoteJWKS) fetchLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return err
	}
	resp, err := j.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&doc); err != nil {
		return err
	}

	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if pub, err := k.publicKey(); err == nil && pub != nil {
			keys[k.Kid] = pub
		}
	}
	if len(keys) == 0 {
		return errors.New("jwks document contained no usable keys")
	}
	j.keys = keys
	j.fetched = time.Now()
	return nil
}

// publicKey materializes the JWK into a crypto.PublicKey for signature verification.
func (k *jwksKey) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		if k.Crv != elliptic.P256().Params().Name {
			return nil, fmt.Errorf("unsupported ec curve %q", k.Crv)
		}
		x, err := decodeBase64BigInt(k.X)
		if err != nil {
			return nil, err
		}
		y, err := decodeBase64BigInt(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case "RSA":
		n, err := decodeBase64BigInt(k.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeBase64BigInt(k.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, errors.New("rsa exponent out of range")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

func decodeBase64BigInt(s string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}
