package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"yyb_go/internal/httpapi"
)

func main() {
	host := flag.String("host", "127.0.0.1", "listen host")
	port := flag.Int("port", 8000, "listen port")
	resourceRoot := flag.String("resource-root", filepath.Join(".", "resource"), "runtime resource directory")
	dbFilename := flag.String("db", httpapi.DefaultDBFilename, "SQLite database filename under <resource-root>/db")
	tcpProxy := flag.String("tcp-proxy", "", "optional TCP proxy: socks5://host:port or http-connect://host:port")
	authUser := flag.String("auth-user", envOr("YYB_AUTH_USER", "admin"), "HTTP Basic auth username")
	authToken := flag.String("auth-token", os.Getenv("YYB_AUTH_TOKEN"), "HTTP Basic auth token; required unless a token is generated")
	sessionTTL := flag.Duration("session-ttl", 30*time.Minute, "cached upstream session TTL")
	requestTimeout := flag.Duration("request-timeout", 8*time.Second, "per-upstream-request timeout")
	flag.Parse()

	// An empty token used to mean "wide open". Instead, mint a strong ephemeral
	// token and log it: the operator still gets in, and a forgotten flag no
	// longer publishes every stored account to the internet.
	token := strings.TrimSpace(*authToken)
	generated := false
	if token == "" {
		var err error
		if token, err = randomToken(); err != nil {
			log.Fatalf("generate auth token: %v", err)
		}
		generated = true
	}

	cfg := httpapi.Config{
		ResourceRoot:   *resourceRoot,
		DBFilename:     *dbFilename,
		TCPProxy:       *tcpProxy,
		SessionTTL:     *sessionTTL,
		RequestTimeout: *requestTimeout,
		AvatarTimeout:  10 * time.Second,
		ScanTimeout:    180 * time.Second,
		QRSessionTTL:   5 * time.Minute,
		AuthUser:       *authUser,
		AuthToken:      token,
	}

	app, err := httpapi.NewApp(cfg)
	if err != nil {
		log.Fatalf("init app: %v", err)
	}
	defer app.Close()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	srv := &http.Server{
		Addr:    addr,
		Handler: app.Handler(),
		// All four timeouts are required. Without Read/Write/Idle a client can
		// hold connections open indefinitely (slowloris) and the process leaks
		// goroutines until it dies.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Nothing else purges the sessions table, so on a long-running host it
	// grows without bound. Run a janitor for the process lifetime.
	stopJanitor := startSessionJanitor(app, 10*time.Minute)

	go func() {
		log.Printf("YYB Go service listening on http://%s (auth=enabled)", addr)
		if err = srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	if generated {
		log.Printf("no -auth-token supplied; generated ephemeral credentials")
		log.Printf("  username: %s", *authUser)
		log.Printf("  token   : %s", token)
		log.Printf("set -auth-token or YYB_AUTH_TOKEN to make this stable across restarts")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")

	stopJanitor()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
		_ = srv.Close()
	}
}

// startSessionJanitor runs the expired-session purge on a ticker and returns a
// function that stops it.
func startSessionJanitor(app *httpapi.App, every time.Duration) func() {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				n, err := app.PurgeExpiredSessions(ctx)
				cancel()
				if err != nil {
					log.Printf("purge expired sessions: %v", err)
				} else if n > 0 {
					log.Printf("purged %d expired session(s)", n)
				}
			}
		}
	}()
	return func() { close(stop) }
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
