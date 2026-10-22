package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	"yyb_go/internal/protocol"
	"yyb_go/internal/qr"
	"yyb_go/internal/store"
)

type Config struct {
	ResourceRoot   string
	DBFilename     string
	TCPProxy       string
	SessionTTL     time.Duration
	RequestTimeout time.Duration
	AvatarTimeout  time.Duration
	ScanTimeout    time.Duration
	QRSessionTTL   time.Duration

	// AuthUser and AuthToken enable HTTP Basic authentication. When AuthToken
	// is empty the API is unauthenticated, so NewApp refuses to construct an
	// app unless the caller also confined the listener to a loopback address.
	AuthUser  string
	AuthToken string

	// AllowUnauthenticated bypasses the loopback safety check above. It exists
	// for local development and tests; a public deployment must supply a token.
	AllowUnauthenticated bool
}

type App struct {
	cfg       Config
	resources resources
	db        *store.DB
	pool      *protocol.Pool
	qr        *qr.Client
	auth      authConfig

	mu         sync.Mutex
	qrSessions map[string]*qr.Session
}

var swaggerDocsHandler = httpSwagger.Handler(
	httpSwagger.URL("/openapi.json"),
	httpSwagger.DocExpansion("list"),
	httpSwagger.DeepLinking(true),
	httpSwagger.DefaultModelsExpandDepth(httpSwagger.ShowModel),
)

func NewApp(cfg Config) (*App, error) {
	if cfg.ResourceRoot == "" {
		cfg.ResourceRoot = filepath.Join(".", "resource")
	}
	if cfg.DBFilename == "" {
		cfg.DBFilename = DefaultDBFilename
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 8 * time.Second
	}
	if cfg.AvatarTimeout == 0 {
		cfg.AvatarTimeout = 10 * time.Second
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 30 * time.Minute
	}
	if cfg.QRSessionTTL == 0 {
		cfg.QRSessionTTL = 5 * time.Minute
	}
	if cfg.AuthUser == "" {
		cfg.AuthUser = "admin"
	}
	// Fail closed: an unauthenticated API can read every stored WeChat account
	// and impersonate them against wxapp endpoints. Refuse to start rather than
	// silently expose that, unless the caller explicitly opted out.
	if cfg.AuthToken == "" && !cfg.AllowUnauthenticated {
		return nil, fmt.Errorf("auth token is required: set -auth-token or pass -allow-unauthenticated for loopback-only use")
	}
	res, err := ensureResources(cfg.ResourceRoot)
	if err != nil {
		return nil, err
	}
	dbPath, err := prepareDBPath(res.DB, cfg.DBFilename)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	poolCfg := protocol.DefaultConfig()
	poolCfg.SessionTTL = cfg.SessionTTL
	poolCfg.ShortlinkTimeout = cfg.RequestTimeout
	poolCfg.TCPProxy = cfg.TCPProxy
	pool := protocol.NewPool(poolCfg, db)
	return &App{
		cfg:        cfg,
		resources:  res,
		db:         db,
		pool:       pool,
		qr:         qr.NewClient(cfg.RequestTimeout),
		auth:       authConfig{User: cfg.AuthUser, Token: cfg.AuthToken},
		qrSessions: map[string]*qr.Session{},
	}, nil
}

func (a *App) Close() error {
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

// PurgeExpiredSessions deletes cached upstream sessions whose TTL has passed.
// Exposed so the binary can run it on a ticker; nothing in the request path
// does, and without it the sessions table only ever grows.
func (a *App) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	if a.db == nil {
		return 0, nil
	}
	return a.db.PurgeExpiredSessions(ctx)
}

func (a *App) Handler() http.Handler {
	if os.Getenv(gin.EnvGinMode) == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	// Authentication wraps every route below; /health is exempt inside the
	// middleware so orchestrators can probe liveness without credentials.
	router.Use(a.auth.middleware())

	router.Any("/", gin.WrapF(a.handleIndex))
	router.Any("/scan", gin.WrapF(a.handleScan))
	router.Any("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/docs/index.html")
	})
	router.Any("/docs/*path", gin.WrapF(a.handleDocs))
	router.Any("/openapi.json", gin.WrapF(a.handleOpenAPI))
	router.Any("/health", func(c *gin.Context) {
		writeJSON(c.Writer, http.StatusOK, gin.H{"ok": true})
	})
	router.StaticFS("/static", http.Dir(a.resources.Static))
	router.Any("/qr", gin.WrapF(a.handleQRRoot))
	router.Any("/qr/*path", gin.WrapF(a.handleQR))
	router.Any("/accounts", gin.WrapF(a.handleAccountsRoot))
	router.Any("/accounts/avatar", gin.WrapF(a.handleAccountAvatar))
	router.Any("/accounts/refresh", gin.WrapF(a.handleAccountRefresh))
	router.Any("/accounts/resync", gin.WrapF(a.handleAccountResync))
	router.Any("/wxapp/getCode", gin.WrapF(a.handleGetCode))
	router.Any("/wxapp/getPhoneNumber", gin.WrapF(a.handleGetPhoneNumber))
	router.Any("/wxapp/operateWxData", gin.WrapF(a.handleOperateWXData))
	router.NoRoute(func(c *gin.Context) {
		writeError(c.Writer, http.StatusNotFound, "not found")
	})

	return router
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	serveFileOrText(w, r, filepath.Join(a.resources.Templates, "index.html"), fallbackIndexHTML)
}

func (a *App) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	serveFileOrText(w, r, filepath.Join(a.resources.Templates, "scan.html"), fallbackScanHTML)
}

func (a *App) handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.URL.Path == "/docs/" {
		http.Redirect(w, r, "/docs/index.html", http.StatusMovedPermanently)
		return
	}
	swaggerDocsHandler.ServeHTTP(w, r)
}

func (a *App) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeRawJSON(w, http.StatusOK, openAPISpec)
}

func (a *App) handleQRRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/qr" {
		writeError(w, http.StatusNotFound, "qr session not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.pruneQR()
	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.RequestTimeout+35*time.Second)
	defer cancel()
	img, err := a.qr.GetQRCodeImage(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	// Write the image before registering the session and take the keep-snapshot
	// under the same lock, so a concurrent request cannot garbage-collect the
	// file in the window between registration and write.
	path := a.resources.qrPath(img.Session.ID)
	if err = os.WriteFile(path, img.ImageBytes, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist QR image: "+err.Error())
		return
	}
	a.mu.Lock()
	a.qrSessions[img.Session.ID] = img.Session
	keep := make(map[string]bool, len(a.qrSessions))
	for sid := range a.qrSessions {
		keep[sid] = true
	}
	a.mu.Unlock()
	a.cleanupQR(keep)
	out := map[string]any{
		"session_id": img.Session.ID,
		"status":     img.Session.State(),
		"image_url":  "/qr/" + img.Session.ID + "/image",
	}
	if r.URL.Query().Get("as_base64") == "true" {
		out["image_base64"] = qr.DataURIJPEG(img.ImageBytes)
	} else {
		out["image_base64"] = nil
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/qr/"), "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "qr session not found")
		return
	}
	sessionID, action := parts[0], parts[1]
	// sessionID becomes a filename under resource/qr. Rejecting anything
	// outside the hex alphabet we generate stops "../" traversal and NUL tricks
	// from reaching arbitrary files.
	if !validSessionID(sessionID) {
		writeError(w, http.StatusNotFound, "qr session not found")
		return
	}
	switch action {
	case "image":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		path := a.resources.qrPath(sessionID)
		if _, err := os.Stat(path); err != nil {
			writeError(w, http.StatusNotFound, "qr session not found")
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		http.ServeFile(w, r, path)
	case "poll":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		sess := a.getQRSession(sessionID)
		if sess == nil {
			writeError(w, http.StatusNotFound, "qr session not found")
			return
		}
		result, err := a.qr.PollQRCode(r.Context(), sess)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		if terminalQR(result.Status) {
			a.dropQRSession(sessionID)
		}
		writeJSON(w, http.StatusOK, result)
	case "confirm":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		sess := a.getQRSession(sessionID)
		if sess == nil {
			writeError(w, http.StatusNotFound, "qr session not found")
			return
		}
		result, err := a.qr.GetLoginBuffer(r.Context(), sess)
		if err != nil {
			writeError(w, http.StatusConflict, "buffer not ready: "+err.Error())
			return
		}
		var userInfo map[string]any
		if ui, uiErr := a.qr.LoginBuffers().FetchUserInfo(r.Context(), result.Credentials); uiErr == nil {
			userInfo = ui
		}
		acc, err := a.storeFromScan(r.Context(), result.LoginBuffer, result.Credentials, userInfo)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Keep the session registered instead of dropping it here. The login
		// buffer is cached on the session, so a retried confirm (browser lost
		// the response, user double-clicked) is idempotent and returns the same
		// account rather than a confusing 404. pruneQR releases it later.
		writeJSON(w, http.StatusOK, acc.Public())
	default:
		writeError(w, http.StatusNotFound, "qr session not found")
	}
}

func (a *App) handleAccountsRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		accounts, err := a.db.ListAccounts(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]store.AccountPublic, 0, len(accounts))
		for _, acc := range accounts {
			out = append(out, acc.Public())
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		acc, ok := a.resolveAccountFromQuery(w, r)
		if !ok {
			return
		}
		if err := a.db.DeleteAccount(r.Context(), acc.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": acc.ID, "openid": acc.OpenID})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAccountAvatar(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts/avatar" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	acc, ok := a.resolveAccountFromQuery(w, r)
	if !ok {
		return
	}
	a.serveAvatar(w, r, acc)
}

func (a *App) handleAccountRefresh(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts/refresh" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body accountRefIn
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		a.refreshAll(w, r)
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	status := a.refreshLiveness(r.Context(), acc)
	writeJSON(w, http.StatusOK, refreshOut(acc, status))
}

func (a *App) handleAccountResync(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts/resync" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body accountRefIn
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		a.resyncAll(w, r)
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	updated, err := a.resyncProfile(r.Context(), acc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated.Public())
}

func (a *App) handleGetCode(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getCode") {
		return
	}
	a.callWXApp(w, r, false, a.invokeGetCode)
}

func (a *App) handleGetPhoneNumber(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getPhoneNumber") {
		return
	}
	a.callWXApp(w, r, false, a.invokeGetPhoneNumber)
}

func (a *App) handleOperateWXData(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/operateWxData") {
		return
	}
	a.callWXApp(w, r, true, a.invokeOperateWXData)
}

func acceptWXAppRoute(w http.ResponseWriter, r *http.Request, path string) bool {
	if r.URL.Path != path {
		writeError(w, http.StatusNotFound, "not found")
		return false
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	return true
}

type accountRefIn struct {
	Ref string `json:"ref"`
}

type wxappRequest struct {
	Ref     string         `json:"ref"`
	AppID   string         `json:"app_id"`
	Payload map[string]any `json:"payload"`
}

type wxappCall func(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any) (map[string]any, error)

func (a *App) callWXApp(w http.ResponseWriter, r *http.Request, requirePayload bool, call wxappCall) {
	var body wxappRequest
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return
	}
	if body.AppID == "" {
		writeError(w, http.StatusBadRequest, "app_id is required")
		return
	}
	if requirePayload && body.Payload == nil {
		writeError(w, http.StatusBadRequest, "payload is required")
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	result, err := a.invokeWXApp(r.Context(), acc, body.AppID, body.Payload, call)
	if err != nil {
		var expired accountExpiredError
		switch {
		case errors.As(err, &expired):
			writeError(w, http.StatusConflict, "account login_buffer expired (refresh failed); re-scan required")
		default:
			writeError(w, http.StatusBadGateway, "call failed: "+err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"openid": acc.OpenID, "result": result})
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	err := json.NewDecoder(r.Body).Decode(dst)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (a *App) resolveAccountFromQuery(w http.ResponseWriter, r *http.Request) (*store.WechatAccount, bool) {
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	if ref == "" {
		writeError(w, http.StatusBadRequest, "ref query param is required")
		return nil, false
	}
	return a.resolveAccountRef(w, r, ref)
}

func (a *App) resolveAccountRef(w http.ResponseWriter, r *http.Request, ref string) (*store.WechatAccount, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return nil, false
	}
	acc, err := a.db.ResolveAccount(r.Context(), ref)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "account not found: "+ref)
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return nil, false
	}
	return acc, true
}

// refreshAll probes every stored account. Failures are reported per account
// rather than aborting the batch: one dead account must not hide the status of
// the others.
func (a *App) refreshAll(w http.ResponseWriter, r *http.Request) {
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Bound the whole batch so a hung upstream cannot hold the request open
	// indefinitely while accounts are probed one by one.
	ctx, cancel := context.WithTimeout(r.Context(), a.batchTimeout(len(accounts)))
	defer cancel()

	out := make([]map[string]any, 0, len(accounts))
	for _, acc := range accounts {
		if err = ctx.Err(); err != nil {
			out = append(out, map[string]any{
				"id": acc.ID, "openid": acc.OpenID, "uin": acc.UIN,
				"nickname": acc.Nickname, "status": "timeout",
			})
			continue
		}
		out = append(out, refreshOut(acc, a.refreshLiveness(ctx, acc)))
	}
	writeJSON(w, http.StatusOK, out)
}

// resyncAll reloads profile data for every account. Per-account failures are
// recorded in the response instead of failing the whole batch.
func (a *App) resyncAll(w http.ResponseWriter, r *http.Request) {
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), a.batchTimeout(len(accounts)))
	defer cancel()

	out := make([]any, 0, len(accounts))
	for _, acc := range accounts {
		if err = ctx.Err(); err != nil {
			out = append(out, map[string]any{
				"id": acc.ID, "openid": acc.OpenID, "error": "batch timeout",
			})
			continue
		}
		updated, rerr := a.resyncProfile(ctx, acc)
		if rerr != nil {
			out = append(out, map[string]any{
				"id": acc.ID, "openid": acc.OpenID, "error": rerr.Error(),
			})
			continue
		}
		out = append(out, updated.Public())
	}
	writeJSON(w, http.StatusOK, out)
}

// batchTimeout scales the per-batch deadline with the number of accounts,
// capped so the total stays within typical proxy timeouts.
func (a *App) batchTimeout(n int) time.Duration {
	per := a.cfg.RequestTimeout
	if per <= 0 {
		per = 8 * time.Second
	}
	if n <= 0 {
		n = 1
	}
	d := time.Duration(n) * per
	if d > 90*time.Second {
		d = 90 * time.Second
	}
	return d
}

func (a *App) serveAvatar(w http.ResponseWriter, r *http.Request, acc *store.WechatAccount) {
	if acc.Avatar != nil && *acc.Avatar != "" {
		// Resolve the stored path and confirm it stays inside the avatar
		// directory. The value round-trips through the database, so trusting
		// it verbatim would let a poisoned row read any file the process can.
		if p, ok := a.confineToAvatars(*acc.Avatar); ok {
			w.Header().Set("Content-Type", "image/jpeg")
			http.ServeFile(w, r, p)
			return
		}
		// Only follow redirects to https hosts we expect avatars from. The
		// value comes from remote user info, so an unconditional 302 here
		// would let a crafted profile turn our endpoint into an open
		// redirect for phishing links.
		if u, ok := allowedAvatarURL(*acc.Avatar); ok {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, u, http.StatusFound)
			return
		}
	}
	writeError(w, http.StatusNotFound, "no avatar")
}

// confineToAvatars returns the cleaned absolute path when it lies inside the
// avatar directory and is a regular file.
func (a *App) confineToAvatars(raw string) (string, bool) {
	base, err := filepath.Abs(a.resources.Avatars)
	if err != nil {
		return "", false
	}
	p, err := filepath.Abs(raw)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", false
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	return p, true
}

// allowedAvatarURL validates that raw is an https URL on an allowlisted WeChat
// media host and returns it unchanged when acceptable.
func allowedAvatarURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", false
	}
	if u.User != nil {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	for _, suffix := range avatarHostSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return u.String(), true
		}
	}
	return "", false
}

// avatarHostSuffixes lists the domains WeChat serves profile images from.
var avatarHostSuffixes = []string{
	"qlogo.cn",
	"weixin.qq.com",
	"wx.qq.com",
	"gtimg.cn",
	"qpic.cn",
}

func (a *App) storeFromScan(ctx context.Context, loginBuffer string, creds protocol.LoginBufferCredentials, userInfo map[string]any) (*store.WechatAccount, error) {
	openid := creds.OpenID
	nick := pickNickname(userInfo, creds.Nickname)
	avatar := a.resolveAvatar(ctx, openid, userInfo)
	status := "alive"
	return a.db.UpsertAccount(ctx, openid, loginBuffer, stringPtrMaybe(nick), stringPtrMaybe(nick), stringPtrMaybe(avatar), userInfo, creds.ToMap(), &status)
}

func (a *App) refreshLiveness(ctx context.Context, acc *store.WechatAccount) string {
	if acc.Credentials == nil {
		_ = a.db.SetAccountStatus(ctx, acc.ID, "unknown")
		return "unknown"
	}
	creds := protocol.CredentialsFromMap(acc.Credentials)
	result, err := a.qr.RefreshLoginBuffer(ctx, creds)
	if err != nil {
		_ = a.db.SetAccountStatus(ctx, acc.ID, "expired")
		// The cached long-link session was derived from the now-dead
		// credentials. Leaving it in place makes every later call retry a
		// session that cannot work, until it expires on its own.
		a.dropCachedSessions(ctx, acc.ID)
		return "expired"
	}
	_ = a.db.SetAccountCredential(ctx, acc.ID, result.LoginBuffer, result.Credentials.ToMap())
	_ = a.db.SetAccountStatus(ctx, acc.ID, "alive")
	// The login buffer changed, so any cached session is stale by definition.
	a.dropCachedSessions(ctx, acc.ID)
	if avatar := a.resolveAvatar(ctx, acc.OpenID, acc.UserInfo); avatar != "" {
		_ = a.db.SetAccountProfile(ctx, acc.ID, acc.Nickname, &avatar, acc.UserInfo)
	}
	return "alive"
}

// dropCachedSessions removes cached long-link sessions for an account so the
// next call performs a fresh manual auth against the current login buffer.
func (a *App) dropCachedSessions(ctx context.Context, accountID int64) {
	for _, proxy := range a.sessionProxyKeys() {
		_ = a.db.InvalidateSession(ctx, accountID, proxy)
	}
}

// sessionProxyKeys returns every tcp_proxy value a session could have been
// stored under for this process configuration.
func (a *App) sessionProxyKeys() []string {
	keys := []string{""}
	if a.cfg.TCPProxy != "" {
		keys = append(keys, a.cfg.TCPProxy)
	}
	return keys
}

func (a *App) resyncProfile(ctx context.Context, acc *store.WechatAccount) (*store.WechatAccount, error) {
	nick := pickNickname(acc.UserInfo, deref(acc.Nickname))
	avatar := a.resolveAvatar(ctx, acc.OpenID, acc.UserInfo)
	if avatar == "" {
		avatar = deref(acc.Avatar)
	}
	if err := a.db.SetAccountProfile(ctx, acc.ID, stringPtrMaybe(nick), stringPtrMaybe(avatar), acc.UserInfo); err != nil {
		return nil, err
	}
	return a.db.GetAccount(ctx, acc.ID)
}

type accountExpiredError struct{ openid string }

func (e accountExpiredError) Error() string { return "account expired: " + e.openid }

// invokeWXApp runs a wxapp call, repairing the account state once when the first
// attempt fails.
//
// The retry ladder is: try with whatever credentials we have; if that fails,
// clear the cached session and refresh the OAuth token; if the account is no
// longer alive, surface a typed expired error so the handler can answer 409
// instead of a generic 502.
func (a *App) invokeWXApp(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, call wxappCall) (map[string]any, error) {
	// First attempt. Pool.run reuses a cached session when one exists and only
	// logs in when it must, so no pre-flight session check is needed here (the
	// old code did one and then raced against it).
	result, firstErr := call(ctx, acc, appID, payload)
	if firstErr == nil {
		return result, nil
	}

	// Second attempt: drop the cached session so the retry cannot reuse the
	// socket state that just failed.
	a.dropCachedSessions(ctx, acc.ID)

	status := a.refreshLiveness(ctx, acc)
	if status != "alive" {
		return nil, accountExpiredError{openid: acc.OpenID}
	}
	// refreshLiveness rewrote login_buffer and credentials in the database; the
	// account value we hold is stale, so reload before retrying.
	fresh, err := a.db.GetAccount(ctx, acc.ID)
	if err != nil || fresh == nil {
		return nil, fmt.Errorf("reload account after refresh: %w", err)
	}
	// The buffer changed, so any session created above is unusable again.
	a.dropCachedSessions(ctx, acc.ID)
	return call(ctx, fresh, appID, payload)
}

func (a *App) invokeGetCode(ctx context.Context, acc *store.WechatAccount, appID string, _ map[string]any) (map[string]any, error) {
	return a.pool.GetCode(ctx, acc.LoginBuffer, appID, acc.ID, a.cfg.TCPProxy)
}

func (a *App) invokeGetPhoneNumber(ctx context.Context, acc *store.WechatAccount, appID string, _ map[string]any) (map[string]any, error) {
	return a.pool.GetPhoneNumber(ctx, acc.LoginBuffer, appID, acc.ID, a.cfg.TCPProxy)
}

func (a *App) invokeOperateWXData(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any) (map[string]any, error) {
	return a.pool.OperateWXData(ctx, acc.LoginBuffer, appID, payload, acc.ID, a.cfg.TCPProxy)
}

func refreshOut(acc *store.WechatAccount, status string) map[string]any {
	return map[string]any{"id": acc.ID, "openid": acc.OpenID, "uin": acc.UIN, "nickname": acc.Nickname, "status": status}
}

func pickNickname(userInfo map[string]any, fallback string) string {
	if s := stringFromAny(userInfo["nick_name"]); s != "" {
		return s
	}
	return fallback
}

func pickAvatarURL(userInfo map[string]any) string {
	for _, k := range []string{"head_img_url", "head_url", "headimgurl", "avatar"} {
		if s := stringFromAny(userInfo[k]); s != "" {
			return s
		}
	}
	return ""
}

func (a *App) resolveAvatar(ctx context.Context, openid string, userInfo map[string]any) string {
	u := pickAvatarURL(userInfo)
	if u == "" {
		return ""
	}
	dest := a.resources.avatarPath(openid)
	if downloadAvatar(ctx, u, dest, a.cfg.AvatarTimeout) {
		return dest
	}
	// Keep the remote URL only if it is on an allowlisted host, so a stored
	// value can never act as an arbitrary redirect target later.
	if safe, ok := allowedAvatarURL(u); ok {
		return safe
	}
	return ""
}

func downloadAvatar(ctx context.Context, url, dest string, timeout time.Duration) bool {
	// Refuse to fetch anything that is not an allowlisted https avatar host.
	// This is the only outbound request driven by remote-supplied data, so it
	// doubles as an SSRF guard against internal addresses.
	if _, ok := allowedAvatarURL(url); !ok {
		return false
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	// Do not follow redirects: the allowlist applies to the URL we chose, and a
	// redirect could point at an internal service.
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil || resp.StatusCode != 200 || !looksLikeImage(data) {
		return false
	}
	if err = os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return false
	}
	return os.WriteFile(dest, data, 0o644) == nil
}

func looksLikeImage(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	magics := [][]byte{{0xff, 0xd8, 0xff}, {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, []byte("GIF87a"), []byte("GIF89a")}
	for _, m := range magics {
		if strings.HasPrefix(string(data), string(m)) {
			return true
		}
	}
	return false
}

func (a *App) getQRSession(id string) *qr.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.qrSessions[id]
}

func (a *App) dropQRSession(id string) {
	a.mu.Lock()
	delete(a.qrSessions, id)
	a.mu.Unlock()
	_ = os.Remove(a.resources.qrPath(id))
}

func (a *App) pruneQR() {
	a.mu.Lock()
	var drop []string
	for sid, sess := range a.qrSessions {
		if sess.Age() > a.cfg.QRSessionTTL {
			drop = append(drop, sid)
		}
	}
	for _, sid := range drop {
		delete(a.qrSessions, sid)
	}
	a.mu.Unlock()
	for _, sid := range drop {
		_ = os.Remove(a.resources.qrPath(sid))
	}
}

func (a *App) cleanupQR(keep map[string]bool) {
	files, _ := filepath.Glob(filepath.Join(a.resources.QR, "*.jpg"))
	for _, f := range files {
		sid := strings.TrimSuffix(filepath.Base(f), ".jpg")
		if !keep[sid] {
			_ = os.Remove(f)
		}
	}
}

// terminalQR reports whether a poll status means the QR session can never make
// progress again, so the in-memory session and its image can be released.
//
// "unknown" is deliberately excluded: it means we could not classify the
// upstream reply, which is frequently transient (a proxy hiccup or a partial
// body). Dropping the session there would turn a recoverable blip into a hard
// 404 for the browser mid-scan.
func terminalQR(status string) bool {
	return status == "expired" || status == "cancelled"
}

type apiEnvelope struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	writeRawJSON(w, status, apiEnvelope{
		Code: 0,
		Msg:  "success",
		Data: v,
	})
}

func writeRawJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeRawJSON(w, status, apiEnvelope{
		Code: status,
		Msg:  detail,
		Data: nil,
	})
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// serveFileOrText serves path when it exists, otherwise writes the embedded
// fallback. The path is always composed by the caller from a fixed template
// name, never from user input.
func serveFileOrText(w http.ResponseWriter, r *http.Request, path, fallback string) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		http.ServeFile(w, r, path)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(fallback))
}

func stringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func stringPtrMaybe(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// validSessionID accepts only the lowercase hex identifiers produced by
// randomHex(16). Anything else cannot name a file we created.
func validSessionID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
