package headers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig_ReturnsNonEmptyValues(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotEmpty(t, cfg.ContentSecurityPolicy)
	assert.NotEmpty(t, cfg.XFrameOptions)
	assert.NotEmpty(t, cfg.XContentTypeOptions)
	assert.NotEmpty(t, cfg.StrictTransportSecurity)
	assert.NotEmpty(t, cfg.ReferrerPolicy)
	assert.NotEmpty(t, cfg.PermissionsPolicy)
	assert.NotEmpty(t, cfg.XSSProtection)
}

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "default-src 'self'", cfg.ContentSecurityPolicy)
	assert.Equal(t, "DENY", cfg.XFrameOptions)
	assert.Equal(t, "nosniff", cfg.XContentTypeOptions)
	assert.Equal(t, "max-age=63072000; includeSubDomains", cfg.StrictTransportSecurity)
	assert.Equal(t, "strict-origin-when-cross-origin", cfg.ReferrerPolicy)
	assert.Equal(t, "geolocation=(), camera=(), microphone=()", cfg.PermissionsPolicy)
	assert.Equal(t, "1; mode=block", cfg.XSSProtection)
}

func TestMiddleware_SetsAllConfiguredHeaders(t *testing.T) {
	cfg := DefaultConfig()
	handler := Middleware(cfg)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rr, req)

	tests := []struct {
		header string
		value  string
	}{
		{"Content-Security-Policy", cfg.ContentSecurityPolicy},
		{"X-Frame-Options", cfg.XFrameOptions},
		{"X-Content-Type-Options", cfg.XContentTypeOptions},
		{"Strict-Transport-Security", cfg.StrictTransportSecurity},
		{"Referrer-Policy", cfg.ReferrerPolicy},
		{"Permissions-Policy", cfg.PermissionsPolicy},
		{"X-XSS-Protection", cfg.XSSProtection},
	}

	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			assert.Equal(t, tc.value, rr.Header().Get(tc.header))
		})
	}
}

func TestMiddleware_SkipsEmptyHeaderValues(t *testing.T) {
	cfg := Config{
		XFrameOptions:       "DENY",
		XContentTypeOptions: "nosniff",
		// All other fields are empty strings.
	}

	handler := Middleware(cfg)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rr, req)

	// Set headers should be present.
	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))

	// Empty config fields should not produce headers.
	assert.Empty(t, rr.Header().Get("Content-Security-Policy"))
	assert.Empty(t, rr.Header().Get("Strict-Transport-Security"))
	assert.Empty(t, rr.Header().Get("Referrer-Policy"))
	assert.Empty(t, rr.Header().Get("Permissions-Policy"))
	assert.Empty(t, rr.Header().Get("X-XSS-Protection"))
}

func TestMiddleware_WrappedHandlerIsCalled(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("X-Custom", "test")
		w.WriteHeader(http.StatusTeapot)
	})

	handler := Middleware(DefaultConfig())(inner)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rr, req)

	require.True(t, called, "wrapped handler must be called")
	assert.Equal(t, http.StatusTeapot, rr.Code)
	assert.Equal(t, "test", rr.Header().Get("X-Custom"))
}

func TestMiddleware_ZeroConfig_NoHeaders(t *testing.T) {
	cfg := Config{}
	handler := Middleware(cfg)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rr, req)

	assert.Empty(t, rr.Header().Get("Content-Security-Policy"))
	assert.Empty(t, rr.Header().Get("X-Frame-Options"))
	assert.Empty(t, rr.Header().Get("X-Content-Type-Options"))
	assert.Empty(t, rr.Header().Get("Strict-Transport-Security"))
	assert.Empty(t, rr.Header().Get("Referrer-Policy"))
	assert.Empty(t, rr.Header().Get("Permissions-Policy"))
	assert.Empty(t, rr.Header().Get("X-XSS-Protection"))
}

func TestMiddleware_CustomConfig(t *testing.T) {
	cfg := Config{
		ContentSecurityPolicy:   "default-src 'none'",
		XFrameOptions:           "SAMEORIGIN",
		XContentTypeOptions:     "nosniff",
		StrictTransportSecurity: "max-age=31536000",
		ReferrerPolicy:          "no-referrer",
		PermissionsPolicy:       "camera=()",
		XSSProtection:           "0",
	}

	handler := Middleware(cfg)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, "default-src 'none'", rr.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "SAMEORIGIN", rr.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "max-age=31536000", rr.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "no-referrer", rr.Header().Get("Referrer-Policy"))
	assert.Equal(t, "camera=()", rr.Header().Get("Permissions-Policy"))
	assert.Equal(t, "0", rr.Header().Get("X-XSS-Protection"))
}
