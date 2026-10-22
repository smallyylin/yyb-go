package httpapi

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// authConfig holds the optional HTTP Basic credentials guarding the API.
// When Token is empty the guard is skipped entirely; NewApp then refuses to
// bind a non-loopback address so the port cannot be exposed anonymously.
type authConfig struct {
	User  string
	Token string
}

func (a authConfig) enabled() bool { return a.Token != "" }

// publicPath reports whether a request path may bypass authentication. Only the
// liveness probe is anonymous; every endpoint able to read or mutate an account
// requires credentials.
func publicPath(path string) bool {
	return path == "/health"
}

// check validates supplied credentials against the configured token. Both
// comparisons are constant time so response timing cannot be used to recover
// the token byte by byte.
func (a authConfig) check(user, token string) bool {
	if !a.enabled() {
		return true
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(a.User)) == 1
	tokenOK := subtle.ConstantTimeCompare([]byte(token), []byte(a.Token)) == 1
	return userOK && tokenOK
}

// middleware enforces Basic auth. Scripted clients may instead send the token
// in X-Auth-Token or an Authorization: Bearer header, which avoids
// percent-encoding trouble with tokens containing '#' or '$'.
func (a authConfig) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.enabled() || publicPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		if user, token, ok := c.Request.BasicAuth(); ok && a.check(user, token) {
			c.Next()
			return
		}
		if raw := bearerToken(c.Request); raw != "" && a.check(a.User, raw) {
			c.Next()
			return
		}
		c.Header("WWW-Authenticate", `Basic realm="YYB Go", charset="UTF-8"`)
		writeError(c.Writer, http.StatusUnauthorized, "authentication required")
		c.Abort()
	}
}

func bearerToken(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Auth-Token")); v != "" {
		return v
	}
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
