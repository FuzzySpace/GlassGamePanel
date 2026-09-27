// Package wings is a Wings daemon HTTP client.
// It dials POST /api/servers/{uuid}/power, GET /api/servers/{uuid}/files/list-directory,
// POST /api/servers/{uuid}/files/write, and POST /api/servers/{uuid}/files/delete.
// It is not the Pterodactyl Application API. The daemon token is never placed on
// the URL, never written into errors, and never logged by this package.
package wings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxBody     = 1 << 20
	maxSummary  = 240
	httpTimeout = 10 * time.Second
)

// Request is one allowlisted daemon call. ServerID is the Wings server UUID.
// RequestID is copied onto X-Request-Id when it is a safe token, so a Wings
// access log can be tied to the GGP request. It is never the daemon token.
// File is the volume path for files_write and files_delete. Content is the
// raw archive for files_write. Content is not logged.
type Request struct {
	Op        string
	ServerID  string
	Action    string
	Directory string
	File      string
	Content   []byte
	RequestID string
}

// Result is a completed HTTP round-trip. Status is the Wings status code,
// including 4xx and 5xx. Summary is a truncated, token-redacted body.
type Result struct {
	Status  int
	Summary string
	Body    []byte
}

var (
	// ErrNotConfigured means the daemon origin or token is empty.
	ErrNotConfigured = errors.New("wings daemon is not configured")
	// ErrUnreachable means the dial did not complete an HTTP round-trip.
	ErrUnreachable = errors.New("wings daemon unreachable")
	// ErrRedirect means Wings (or something in front of it) returned a redirect.
	// The client does not follow it.
	ErrRedirect = errors.New("wings daemon redirect rejected")
	// ErrBadTarget means the server id or action was rejected before a dial.
	ErrBadTarget = errors.New("wings server id rejected")
)

// Client dials one Wings daemon origin. The token is the node daemon bearer.
type Client struct {
	origin *url.URL
	token  string
	http   *http.Client
}

// New builds a client for one daemon origin. rawURL is PANEL_WINGS_BASE_URL.
// token is PANEL_WINGS_TOKEN. Neither value is echoed in errors.
func New(rawURL, token string) (*Client, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrNotConfigured
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("wings daemon url is invalid")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("wings daemon url scheme is invalid")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("wings daemon url must be an origin")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("wings daemon url must be an origin")
	}
	origin := &url.URL{Scheme: u.Scheme, Host: u.Host}
	return &Client{
		origin: origin,
		token:  token,
		http: &http.Client{
			Timeout: httpTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return ErrRedirect
			},
			// Do not forward the daemon token through an ambient proxy.
			Transport: &http.Transport{Proxy: nil},
		},
	}, nil
}

// Do performs one daemon call. A nil error means Wings returned an HTTP status.
// Non-2xx statuses are still a completed round-trip. Network errors, redirects,
// and a missing client return a static error that does not contain the token.
func (c *Client) Do(ctx context.Context, req Request) (Result, error) {
	if c == nil || c.origin == nil || c.token == "" || c.http == nil {
		return Result{}, ErrNotConfigured
	}
	id, ok := canonUUID(req.ServerID)
	if !ok {
		return Result{}, ErrBadTarget
	}
	switch req.Op {
	case "power":
		return c.power(ctx, id, req.Action, req.RequestID)
	case "files":
		return c.listDirectory(ctx, id, req.Directory, req.RequestID)
	case "files_write":
		return c.writeFile(ctx, id, req.File, req.Content, req.RequestID)
	case "files_delete":
		return c.deleteFile(ctx, id, req.File, req.RequestID)
	default:
		return Result{}, ErrBadTarget
	}
}

func (c *Client) power(ctx context.Context, serverID, action, requestID string) (Result, error) {
	switch action {
	case "start", "stop", "restart", "kill":
	default:
		return Result{}, ErrBadTarget
	}
	payload, err := json.Marshal(map[string]string{"action": action})
	if err != nil {
		return Result{}, ErrBadTarget
	}
	u := c.origin.ResolveReference(&url.URL{Path: "/api/servers/" + serverID + "/power"})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return Result{}, ErrBadTarget
	}
	httpReq.Header.Set("Content-Type", "application/json")
	return c.roundTrip(httpReq, requestID)
}

func (c *Client) writeFile(ctx context.Context, serverID, file string, content []byte, requestID string) (Result, error) {
	file, err := CleanVolumeFile(file)
	if err != nil || !ModArchive(content) {
		return Result{}, ErrBadTarget
	}
	u := c.origin.ResolveReference(&url.URL{Path: "/api/servers/" + serverID + "/files/write"})
	q := u.Query()
	q.Set("file", file)
	u.RawQuery = q.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(content))
	if err != nil {
		return Result{}, ErrBadTarget
	}
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	return c.roundTrip(httpReq, requestID)
}

func (c *Client) deleteFile(ctx context.Context, serverID, file, requestID string) (Result, error) {
	file, err := CleanVolumeFile(file)
	if err != nil {
		return Result{}, ErrBadTarget
	}
	root, name := splitVolumeFile(file)
	if root == "" || name == "" || strings.Contains(name, "/") {
		return Result{}, ErrBadTarget
	}
	payload, err := json.Marshal(struct {
		Root  string   `json:"root"`
		Files []string `json:"files"`
	}{Root: root, Files: []string{name}})
	if err != nil {
		return Result{}, ErrBadTarget
	}
	u := c.origin.ResolveReference(&url.URL{Path: "/api/servers/" + serverID + "/files/delete"})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return Result{}, ErrBadTarget
	}
	httpReq.Header.Set("Content-Type", "application/json")
	return c.roundTrip(httpReq, requestID)
}

func splitVolumeFile(file string) (root, name string) {
	i := strings.LastIndex(file, "/")
	if i <= 0 || i == len(file)-1 {
		return "", ""
	}
	return file[:i], file[i+1:]
}

func (c *Client) listDirectory(ctx context.Context, serverID, directory, requestID string) (Result, error) {
	if directory == "" {
		directory = "/"
	}
	if strings.Contains(directory, "..") {
		return Result{}, ErrBadTarget
	}
	u := c.origin.ResolveReference(&url.URL{Path: "/api/servers/" + serverID + "/files/list-directory"})
	q := u.Query()
	q.Set("directory", directory)
	u.RawQuery = q.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Result{}, ErrBadTarget
	}
	return c.roundTrip(httpReq, requestID)
}

func (c *Client) roundTrip(req *http.Request, requestID string) (Result, error) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if id, ok := safeRequestID(requestID); ok {
		req.Header.Set("X-Request-Id", id)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return Result{}, ErrRedirect
		}
		return Result{}, ErrUnreachable
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return Result{Status: resp.StatusCode, Summary: "body unreadable"}, nil
	}
	truncated := false
	if len(body) > maxBody {
		body = body[:maxBody]
		truncated = true
	}
	if c.token != "" {
		body = bytes.ReplaceAll(body, []byte(c.token), []byte("[redacted]"))
	}
	summary := summarize(body, truncated)
	return Result{Status: resp.StatusCode, Summary: summary, Body: body}, nil
}

func summarize(body []byte, truncated bool) string {
	s := strings.TrimSpace(string(body))
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if truncated {
		s = strings.TrimSpace(s + " [truncated]")
	}
	if len(s) <= maxSummary {
		return s
	}
	s = s[:maxSummary]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

func safeRequestID(s string) (string, bool) {
	if len(s) < 8 || len(s) > 64 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return "", false
	}
	return s, true
}

func canonUUID(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 36 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "", false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return "", false
			}
		}
	}
	return s, true
}
