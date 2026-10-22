package qr

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"yyb_go/internal/protocol"
)

const (
	oauthURL = "https://open.weixin.qq.com/connect/qrconnect" +
		"?appid=wxd44977328b36e647" +
		"&redirect_uri=https://yybadaccess.3g.qq.com/pc_yyb/pcyyb_oauth?login_type=WX" +
		"&response_type=code&scope=snsapi_login,snsapi_runtime_pcsdk" +
		"&state=web&fast_login=1&self_redirect=true"
	callbackURL  = "https://yybadaccess.3g.qq.com/pc_yyb/pcyyb_oauth"
	qrBase       = "https://open.weixin.qq.com/connect/qrcode/"
	longPollBase = "https://long.open.weixin.qq.com/connect/l/qrconnect"

	// qrImageLimit bounds how many bytes we buffer for a QR image. The real
	// image is a few KB; a much larger body is an error page or hostile.
	qrImageLimit = 2 << 20
	// pollBodyLimit bounds the long-poll response body.
	pollBodyLimit = 64 << 10
	// pollWindow is the upstream long-poll hang time.
	pollWindow = 35 * time.Second
)

var (
	// Character class restricted to what WeChat actually emits for a QR uuid,
	// so a hostile page cannot smuggle path or query syntax into our URLs.
	uuidRE = regexp.MustCompile(`/connect/qrcode/([A-Za-z0-9_-]+)`)
	errRE  = regexp.MustCompile(`wx_errcode\s*=\s*(\d+)`)
	codeRE = regexp.MustCompile(`wx_code\s*=\s*'([A-Za-z0-9_./+=-]*)'`)
)

type Session struct {
	ID            string
	WXUUID        string
	QRCodeURL     string
	CreatedAt     time.Time
	HTTPClient    *http.Client
	Jar           http.CookieJar
	AuthorizeCode string
	Credentials   *protocol.LoginBufferCredentials
	LoginBuffer   string
	Status        string
	Error         string

	// mu guards the mutable state fields above. It is never held across a
	// network call, so a slow long poll cannot block status readers.
	mu sync.Mutex

	// confirmMu serialises the confirmation flow: two concurrent confirms
	// would both redeem the same authorize code and the loser would error.
	confirmMu sync.Mutex

	// pollCoord collapses concurrent pollers onto one upstream request.
	// Browsers poll every 1.5s while upstream hangs 35s; without this every
	// tab would open its own long-poll connection and sessions pile up.
	pollCoord pollCoordinator
}

type pollCoordinator struct {
	mu       sync.Mutex
	inflight bool
	done     chan struct{}
	result   PollResult
	err      error
}

func (s *Session) Age() time.Duration { return time.Since(s.CreatedAt) }

// Status reports the current status under lock.
func (s *Session) State() (status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Status
}

func (s *Session) setStatus(status, errMsg string) {
	s.mu.Lock()
	s.Status = status
	s.Error = errMsg
	s.mu.Unlock()
}

type ImageResult struct {
	Session    *Session
	ImageBytes []byte
}

type PollResult struct {
	Status  string `json:"status"`
	ErrCode *int   `json:"errcode,omitempty"`
	Code    string `json:"-"`
	Message string `json:"-"`
}

type Client struct {
	timeout      time.Duration
	loginBuffers *protocol.LoginBufferClient
}

func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &Client{
		timeout:      timeout,
		loginBuffers: protocol.NewLoginBufferClient(timeout),
	}
}

func (c *Client) LoginBuffers() *protocol.LoginBufferClient { return c.loginBuffers }

func (c *Client) GetQRCodeImage(ctx context.Context) (ImageResult, error) {
	sess, err := c.CreateSession(ctx)
	if err != nil {
		return ImageResult{}, err
	}
	data, err := c.FetchQRCodeImage(ctx, sess)
	if err != nil {
		return ImageResult{}, err
	}
	return ImageResult{Session: sess, ImageBytes: data}, nil
}

func (c *Client) CreateSession(ctx context.Context) (*Session, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: c.timeout, Jar: jar}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oauthURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	m := uuidRE.FindStringSubmatch(string(body))
	if len(m) < 2 {
		return nil, fmt.Errorf("failed to parse WeChat QR uuid")
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	wxuuid := m[1]
	return &Session{
		ID:         id,
		WXUUID:     wxuuid,
		QRCodeURL:  qrBase + wxuuid,
		CreatedAt:  time.Now(),
		HTTPClient: hc,
		Jar:        jar,
		Status:     "pending",
	}, nil
}

func (c *Client) FetchQRCodeImage(ctx context.Context, sess *Session) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sess.QRCodeURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := sess.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("QR image HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, qrImageLimit))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("QR image is empty")
	}
	return data, nil
}

// PollQRCode performs one long-poll step.
//
// Concurrent callers in the same window share a single upstream request: the
// first becomes the leader, the rest wait on its result. This keeps a fast
// browser poll loop from opening dozens of 35 second connections per session.
func (c *Client) PollQRCode(ctx context.Context, sess *Session) (PollResult, error) {
	// Fast path: resolved states need no network call at all.
	sess.mu.Lock()
	if sess.LoginBuffer != "" {
		sess.mu.Unlock()
		return PollResult{Status: "confirmed"}, nil
	}
	if code := sess.AuthorizeCode; code != "" {
		sess.mu.Unlock()
		errcode := 405
		return PollResult{Status: "authorized", ErrCode: &errcode, Code: code}, nil
	}
	sess.mu.Unlock()

	coord := &sess.pollCoord
	coord.mu.Lock()
	if coord.inflight {
		done := coord.done
		coord.mu.Unlock()
		select {
		case <-done:
			return coord.result, coord.err
		case <-ctx.Done():
			return PollResult{}, ctx.Err()
		}
	}
	coord.inflight = true
	coord.done = make(chan struct{})
	done := coord.done
	coord.mu.Unlock()

	result, err := c.pollUpstream(ctx, sess)

	coord.mu.Lock()
	coord.result, coord.err = result, err
	coord.inflight = false
	coord.mu.Unlock()
	close(done)

	return result, err
}

// pollUpstream issues the actual long poll. No session lock is held while the
// request is in flight.
func (c *Client) pollUpstream(ctx context.Context, sess *Session) (PollResult, error) {
	u := longPollBase + "?" + url.Values{
		"uuid": {sess.WXUUID},
		"_":    {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	}.Encode()
	reqCtx, cancel := context.WithTimeout(ctx, pollWindow)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return PollResult{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := sess.HTTPClient.Do(req)
	if err != nil {
		return PollResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, pollBodyLimit))
	if err != nil {
		return PollResult{}, err
	}
	text := string(body)
	errcode, code := parsePoll(text)

	switch {
	case errcode != nil && *errcode == 408:
		sess.setStatus("pending", "")
		return PollResult{Status: "pending", ErrCode: errcode, Code: code}, nil
	case errcode != nil && *errcode == 404:
		sess.setStatus("scanned", "")
		return PollResult{Status: "scanned", ErrCode: errcode, Code: code}, nil
	case errcode != nil && *errcode == 403:
		sess.setStatus("cancelled", "")
		return PollResult{Status: "cancelled", ErrCode: errcode, Code: code}, nil
	case errcode != nil && *errcode == 402:
		sess.setStatus("expired", "")
		return PollResult{Status: "expired", ErrCode: errcode, Code: code}, nil
	case errcode != nil && *errcode == 405 && code != "":
		sess.mu.Lock()
		sess.AuthorizeCode = code
		sess.Status = "authorized"
		sess.mu.Unlock()
		return PollResult{Status: "authorized", ErrCode: errcode, Code: code}, nil
	default:
		if len(text) > 200 {
			text = text[:200]
		}
		sess.setStatus("unknown", text)
		return PollResult{Status: "unknown", ErrCode: errcode, Code: code, Message: text}, nil
	}
}

func (c *Client) GetLoginBuffer(ctx context.Context, sess *Session) (protocol.LoginBufferResult, error) {
	sess.confirmMu.Lock()
	defer sess.confirmMu.Unlock()

	sess.mu.Lock()
	if sess.LoginBuffer != "" && sess.Credentials != nil {
		lb, creds := sess.LoginBuffer, *sess.Credentials
		sess.mu.Unlock()
		return protocol.LoginBufferResult{LoginBuffer: lb, Credentials: creds}, nil
	}
	code := sess.AuthorizeCode
	sess.mu.Unlock()

	if code == "" {
		return protocol.LoginBufferResult{}, fmt.Errorf("QR session is not authorized yet")
	}
	cb := callbackURL + "?" + url.Values{
		"login_type": {"WX"},
		"code":       {code},
		"state":      {"web"},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cb, nil)
	if err != nil {
		return protocol.LoginBufferResult{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := sess.HTTPClient.Do(req)
	if err != nil {
		return protocol.LoginBufferResult{}, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	creds, err := credentialsFromJar(sess.Jar, cb)
	if err != nil {
		return protocol.LoginBufferResult{}, err
	}
	lb, err := c.loginBuffers.FetchLoginBuffer(ctx, creds)
	if err != nil {
		return protocol.LoginBufferResult{}, err
	}
	sess.mu.Lock()
	sess.Credentials = &creds
	sess.LoginBuffer = lb
	sess.Status = "confirmed"
	sess.mu.Unlock()
	return protocol.LoginBufferResult{LoginBuffer: lb, Credentials: creds}, nil
}

func (c *Client) RefreshLoginBuffer(ctx context.Context, creds protocol.LoginBufferCredentials) (protocol.LoginBufferResult, error) {
	return c.loginBuffers.RefreshLoginBuffer(ctx, creds)
}

func DataURIJPEG(data []byte) string {
	return "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(data)
}

func parsePoll(text string) (*int, string) {
	var out *int
	if m := errRE.FindStringSubmatch(text); len(m) == 2 {
		n, _ := strconv.Atoi(m[1])
		out = &n
	}
	code := ""
	if m := codeRE.FindStringSubmatch(text); len(m) == 2 {
		code = m[1]
	}
	return out, code
}

func credentialsFromJar(jar http.CookieJar, rawURL string) (protocol.LoginBufferCredentials, error) {
	var cookies []*http.Cookie
	if u, err := url.Parse(rawURL); err == nil {
		cookies = append(cookies, jar.Cookies(u)...)
	}
	if hostURL, err := url.Parse("https://yybadaccess.3g.qq.com/"); err == nil {
		cookies = append(cookies, jar.Cookies(hostURL)...)
	}
	values := map[string]string{}
	for _, ck := range cookies {
		values[ck.Name] = ck.Value
	}
	openid := values["openid"]
	accessToken := values["accesstoken"]
	if openid == "" || accessToken == "" {
		return protocol.LoginBufferCredentials{}, fmt.Errorf("OAuth callback did not set required cookies")
	}
	expiresIn := int64(7200)
	if values["expires_in"] != "" {
		if n, err := strconv.ParseInt(values["expires_in"], 10, 64); err == nil && n > 0 {
			expiresIn = n
		}
	}
	return protocol.LoginBufferCredentials{
		OpenID:       openid,
		AccessToken:  accessToken,
		RefreshToken: values["refreshtoken"],
		LoginType:    defaultString(values["logintype"], "WX"),
		Nickname:     values["nickname"],
		ExpiresAt:    time.Now().Unix() + expiresIn,
		ExpiresIn:    expiresIn,
	}, nil
}

func defaultString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
