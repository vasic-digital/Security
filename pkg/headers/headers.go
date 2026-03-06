// Package headers provides security header middleware for HTTP servers.
// It sets common security headers such as Content-Security-Policy,
// X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security,
// Referrer-Policy, Permissions-Policy, and X-XSS-Protection.
package headers

import "net/http"

// Config holds the values for each security header. Any field left
// empty will cause that header to be skipped.
type Config struct {
	ContentSecurityPolicy   string
	XFrameOptions           string
	XContentTypeOptions     string
	StrictTransportSecurity string
	ReferrerPolicy          string
	PermissionsPolicy       string
	XSSProtection           string
}

// DefaultConfig returns a Config with sensible security defaults.
func DefaultConfig() Config {
	return Config{
		ContentSecurityPolicy:   "default-src 'self'",
		XFrameOptions:           "DENY",
		XContentTypeOptions:     "nosniff",
		StrictTransportSecurity: "max-age=63072000; includeSubDomains",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		PermissionsPolicy:       "geolocation=(), camera=(), microphone=()",
		XSSProtection:           "1; mode=block",
	}
}

// Middleware returns an http.Handler middleware that sets security
// headers from the provided Config on every response. Headers whose
// Config value is the empty string are not set.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	// Build the header pairs once so there is no per-request
	// allocation for the configuration lookup.
	type pair struct {
		name  string
		value string
	}

	candidates := []pair{
		{"Content-Security-Policy", cfg.ContentSecurityPolicy},
		{"X-Frame-Options", cfg.XFrameOptions},
		{"X-Content-Type-Options", cfg.XContentTypeOptions},
		{"Strict-Transport-Security", cfg.StrictTransportSecurity},
		{"Referrer-Policy", cfg.ReferrerPolicy},
		{"Permissions-Policy", cfg.PermissionsPolicy},
		{"X-XSS-Protection", cfg.XSSProtection},
	}

	// Keep only non-empty values.
	pairs := make([]pair, 0, len(candidates))
	for _, p := range candidates {
		if p.value != "" {
			pairs = append(pairs, p)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range pairs {
				w.Header().Set(p.name, p.value)
			}
			next.ServeHTTP(w, r)
		})
	}
}
