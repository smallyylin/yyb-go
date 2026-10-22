package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testToken = "test-token-abc123"

// newTestApp builds an app with auth enabled and a throwaway resource root.
func newTestApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{
		ResourceRoot:   t.TempDir(),
		RequestTimeout: time.Second,
		AvatarTimeout:  time.Second,
		SessionTTL:     time.Minute,
		QRSessionTTL:   time.Minute,
		AuthUser:       "admin",
		AuthToken:      testToken,
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return app
}

// do issues an authenticated request the way a scripted client would.
func do(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.SetBasicAuth("admin", testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandlerServesGinRoutesAndSwaggerDocs(t *testing.T) {
	app := newTestApp(t)
	handler := app.Handler()

	health := do(t, handler, http.MethodGet, "/health")
	if health.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d", health.Code)
	}
	var healthBody struct {
		Code int            `json:"code"`
		Msg  string         `json:"msg"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(health.Body.Bytes(), &healthBody); err != nil {
		t.Fatalf("decode health JSON: %v", err)
	}
	if healthBody.Code != 0 || healthBody.Msg != "success" || healthBody.Data["ok"] != true {
		t.Fatalf("GET /health body = %#v", healthBody)
	}

	openapi := do(t, handler, http.MethodGet, "/openapi.json")
	if openapi.Code != http.StatusOK {
		t.Fatalf("GET /openapi.json status = %d", openapi.Code)
	}
	var spec map[string]any
	if err := json.Unmarshal(openapi.Body.Bytes(), &spec); err != nil {
		t.Fatalf("decode OpenAPI JSON: %v", err)
	}
	if spec["openapi"] != "3.0.3" {
		t.Fatalf("openapi version = %v", spec["openapi"])
	}
	if _, ok := spec["code"]; ok {
		t.Fatalf("OpenAPI JSON should not be wrapped in API envelope")
	}
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI paths missing or invalid")
	}
	for _, path := range []string{"/wxapp/getCode", "/wxapp/getPhoneNumber", "/wxapp/operateWxData", "/accounts/avatar"} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("OpenAPI path %s missing", path)
		}
	}
	for _, path := range []string{"/wxapp/getCode", "/wxapp/getPhoneNumber", "/wxapp/operateWxData"} {
		pathItem := paths[path].(map[string]any)
		post := pathItem["post"].(map[string]any)
		tags := post["tags"].([]any)
		if len(tags) != 1 || tags[0] != "wxapp" {
			t.Fatalf("OpenAPI path %s tags = %#v, want [wxapp]", path, tags)
		}
	}
	for _, path := range []string{"/accounts/{ref}", "/accounts/{ref}/getCode", "/accounts/{ref}/getPhoneNumber", "/accounts/{ref}/operateWxData", "/accounts/getCode", "/accounts/getPhoneNumber", "/accounts/operateWxData"} {
		if _, ok := paths[path]; ok {
			t.Fatalf("OpenAPI still exposes old account feature route %s", path)
		}
	}
	if _, ok := paths["/features"]; ok {
		t.Fatalf("OpenAPI still exposes /features")
	}

	docs := do(t, handler, http.MethodGet, "/docs")
	if docs.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /docs status = %d", docs.Code)
	}
	if got := docs.Header().Get("Location"); got != "/docs/index.html" {
		t.Fatalf("GET /docs Location = %q", got)
	}

	features := do(t, handler, http.MethodGet, "/features")
	if features.Code != http.StatusNotFound {
		t.Fatalf("GET /features status = %d", features.Code)
	}
	var notFoundBody struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data any    `json:"data"`
	}
	if err := json.Unmarshal(features.Body.Bytes(), &notFoundBody); err != nil {
		t.Fatalf("decode /features error JSON: %v", err)
	}
	if notFoundBody.Code == 0 || notFoundBody.Msg == "" || notFoundBody.Data != nil {
		t.Fatalf("GET /features body = %#v", notFoundBody)
	}

	oldPath := do(t, handler, http.MethodPost, "/accounts/getCode")
	if oldPath.Code != http.StatusNotFound {
		t.Fatalf("POST old account feature route status = %d", oldPath.Code)
	}
}

// TestOpenAPIDeclaresAuth documents that the spec advertises the auth scheme and
// that /health is the only operation exempt from it.
func TestOpenAPIDeclaresAuth(t *testing.T) {
	app := newTestApp(t)
	rec := do(t, app.Handler(), http.MethodGet, "/openapi.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var spec map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := spec["security"]; !ok {
		t.Fatalf("document-level security requirement missing")
	}
	comps, ok := spec["components"].(map[string]any)
	if !ok {
		t.Fatalf("components missing")
	}
	schemes, ok := comps["securitySchemes"].(map[string]any)
	if !ok {
		t.Fatalf("securitySchemes missing")
	}
	basic, ok := schemes["basicAuth"].(map[string]any)
	if !ok {
		t.Fatalf("basicAuth scheme missing")
	}
	if basic["type"] != "http" || basic["scheme"] != "basic" {
		t.Fatalf("basicAuth = %#v", basic)
	}

	paths := spec["paths"].(map[string]any)
	health := paths["/health"].(map[string]any)["get"].(map[string]any)
	sec, ok := health["security"].([]any)
	if !ok || len(sec) != 0 {
		t.Fatalf("/health security = %#v, want empty list", health["security"])
	}

	// Every protected operation must document its 401.
	for path, item := range paths {
		if path == "/health" {
			continue
		}
		for method, raw := range item.(map[string]any) {
			op, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			responses, ok := op["responses"].(map[string]any)
			if !ok {
				t.Fatalf("%s %s responses missing", method, path)
			}
			if _, ok := responses["401"]; !ok {
				t.Fatalf("%s %s missing 401 response", method, path)
			}
		}
	}
}

// TestAuthRequiredForAccountEndpoints locks in the core fix: no request may read
// or mutate account state without credentials, while /health stays reachable so
// orchestrators can probe liveness.
func TestAuthRequiredForAccountEndpoints(t *testing.T) {
	app := newTestApp(t)
	handler := app.Handler()

	protected := []struct{ method, path string }{
		{http.MethodGet, "/accounts"},
		{http.MethodDelete, "/accounts?ref=1"},
		{http.MethodGet, "/accounts/avatar?ref=1"},
		{http.MethodPost, "/accounts/refresh"},
		{http.MethodPost, "/accounts/resync"},
		{http.MethodPost, "/wxapp/getCode"},
		{http.MethodPost, "/wxapp/getPhoneNumber"},
		{http.MethodPost, "/wxapp/operateWxData"},
		{http.MethodPost, "/qr"},
		{http.MethodGet, "/qr/abc/poll"},
		{http.MethodPost, "/qr/abc/confirm"},
		{http.MethodGet, "/openapi.json"},
		{http.MethodGet, "/"},
	}
	for _, tc := range protected {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without auth status = %d, want 401", tc.method, tc.path, rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s %s missing WWW-Authenticate", tc.method, tc.path)
		}
	}

	// Wrong credentials must not pass.
	bad := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	req.SetBasicAuth("admin", "wrong")
	handler.ServeHTTP(bad, req)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", bad.Code)
	}

	// /health stays anonymous.
	anon := httptest.NewRecorder()
	handler.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, "/health", nil))
	if anon.Code != http.StatusOK {
		t.Fatalf("anonymous /health status = %d, want 200", anon.Code)
	}
}

// TestBearerTokenAuth covers the scripted-client path, which avoids Basic
// header encoding problems for tokens containing '#' or '$'.
func TestBearerTokenAuth(t *testing.T) {
	app := newTestApp(t)
	handler := app.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	req.Header.Set("X-Auth-Token", testToken)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("X-Auth-Token status = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Bearer status = %d, want 200", rec.Code)
	}
}

// TestNewAppRejectsMissingToken ensures the server fails closed instead of
// silently publishing an unauthenticated account store.
func TestNewAppRejectsMissingToken(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err == nil {
		_ = app.Close()
		t.Fatalf("NewApp() with no token should fail")
	}
}

// TestQRPathValidation rejects session ids that could escape the qr directory.
func TestQRPathValidation(t *testing.T) {
	app := newTestApp(t)
	handler := app.Handler()

	for _, path := range []string{
		"/qr/..%2f..%2fetc%2fpasswd/image",
		"/qr/abcDEF123/image",
		"/qr/a%20b/image",
	} {
		rec := do(t, handler, http.MethodGet, path)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want 404", path, rec.Code)
		}
	}

	// A well-formed but unknown session id must also 404, not 500.
	rec := do(t, handler, http.MethodGet, "/qr/deadbeefdeadbeef/image")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown session image status = %d, want 404", rec.Code)
	}
}

// TestAllowedAvatarURL pins the allowlist that both the redirect and the
// download path rely on.
func TestAllowedAvatarURL(t *testing.T) {
	allowed := []string{
		"https://thirdwx.qlogo.cn/mmopen/vi_32/abc/132",
		"https://wx.qlogo.cn/mmopen/abc",
		"https://mmbiz.qpic.cn/abc",
	}
	for _, u := range allowed {
		if _, ok := allowedAvatarURL(u); !ok {
			t.Fatalf("expected %q to be allowed", u)
		}
	}
	blocked := []string{
		"http://thirdwx.qlogo.cn/abc",         // plain http
		"https://evil.example.com/abc",        // off-list host
		"https://qlogo.cn.evil.example/abc",   // suffix confusion
		"https://user:pass@qlogo.cn/abc",      // embedded credentials
		"//qlogo.cn/abc",                      // scheme-relative
		"file:///etc/passwd",                  // local file
		"https://169.254.169.254/latest/meta", // link-local metadata
		"",                                    // empty
	}
	for _, u := range blocked {
		if got, ok := allowedAvatarURL(u); ok {
			t.Fatalf("expected %q to be blocked, got %q", u, got)
		}
	}
}
