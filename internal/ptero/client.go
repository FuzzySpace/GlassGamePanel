// Package ptero is a read-only Pterodactyl Application API client.
// It GETs /api/application/servers only. It does not create, power, or
// write servers, and it has no executor dispatch.
package ptero

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxPages    = 20
	maxServers  = 500
	perPage     = 50
	maxBody     = 4 << 20
	httpTimeout = 10 * time.Second
)

// Server is one source panel server. Nest identifiers are parsed and dropped
// so they cannot be copied into a customer-facing plan.
type Server struct {
	ID          int
	UUID        string
	ExternalID  string
	Name        string
	NodeID      int
	EggID       int
	Allocations []Allocation
}

// Allocation is a source address record copied into the plan only.
type Allocation struct {
	IP      string
	Port    int
	Default bool
}

// Client reads the configured Application API origin. The token is not
// included in errors and is not placed on the URL.
type Client struct {
	origin  *url.URL
	servers string
	token   string
	http    *http.Client
}

// New builds a client for one panel origin. rawURL is PTERO_SOURCE_API_URL.
// token is PTERO_SOURCE_API_TOKEN. Neither value is echoed in errors.
func New(rawURL, token string) (*Client, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("source application api token is empty")
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("source application api url is invalid")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("source application api url scheme is invalid")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("source application api url must be an origin")
	}
	origin := &url.URL{Scheme: u.Scheme, Host: u.Host}
	return &Client{
		origin:  origin,
		servers: serversPath(u),
		token:   token,
		http: &http.Client{
			Timeout: httpTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errors.New("source application api redirect rejected")
			},
			// Do not forward the Application token through an ambient proxy.
			Transport: &http.Transport{Proxy: nil},
		},
	}, nil
}

// Origin is the scheme and host the client is allowed to dial.
func (c *Client) Origin() *url.URL {
	if c == nil || c.origin == nil {
		return nil
	}
	return &url.URL{Scheme: c.origin.Scheme, Host: c.origin.Host}
}

// ListServers pages the Application servers collection. It returns an error
// instead of a partial list when the cap is hit, so a plan cannot silently
// drop a later page.
func (c *Client) ListServers(ctx context.Context) ([]Server, error) {
	if c == nil {
		return nil, errors.New("source application api client is nil")
	}
	var all []Server
	seenPage := map[int]struct{}{}
	for page := 1; page <= maxPages; page++ {
		if _, ok := seenPage[page]; ok {
			return nil, errors.New("source application api page loop")
		}
		seenPage[page] = struct{}{}
		batch, meta, err := c.getPage(ctx, page)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(all) > maxServers {
			return nil, errors.New("source application api inventory exceeds cap")
		}
		if meta.TotalPages <= page || meta.TotalPages == 0 || len(batch) == 0 {
			return all, nil
		}
	}
	return nil, errors.New("source application api inventory exceeds cap")
}

type pageMeta struct {
	CurrentPage int
	TotalPages  int
}

func (c *Client) getPage(ctx context.Context, page int) ([]Server, pageMeta, error) {
	u := c.origin.ResolveReference(&url.URL{Path: c.servers})
	q := u.Query()
	q.Set("include", "allocations")
	q.Set("per_page", strconv.Itoa(perPage))
	q.Set("page", strconv.Itoa(page))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, pageMeta{}, errors.New("source application api request rejected")
	}
	req.Header.Set("Accept", "Application/vnd.pterodactyl.v1+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, pageMeta{}, errors.New("source application api unreachable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, pageMeta{}, errors.New("source application api body rejected")
	}
	if len(body) > maxBody {
		return nil, pageMeta{}, errors.New("source application api body rejected")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, pageMeta{}, errors.New("source application api status rejected")
	}
	return parseServerPage(body)
}

func serversPath(u *url.URL) string {
	p := strings.TrimRight(u.Path, "/")
	switch {
	case p == "" || p == "/":
		return "/api/application/servers"
	case strings.HasSuffix(p, "/api/application/servers"):
		return p
	case strings.HasSuffix(p, "/api/application"):
		return p + "/servers"
	default:
		return p + "/api/application/servers"
	}
}

type listDoc struct {
	Data []serverObj `json:"data"`
	Meta struct {
		Pagination struct {
			CurrentPage int `json:"current_page"`
			TotalPages  int `json:"total_pages"`
		} `json:"pagination"`
	} `json:"meta"`
}

type serverObj struct {
	Attributes serverAttr `json:"attributes"`
}

type serverAttr struct {
	ID            int        `json:"id"`
	ExternalID    flexString `json:"external_id"`
	UUID          string     `json:"uuid"`
	Name          string     `json:"name"`
	Node          int        `json:"node"`
	Nest          int        `json:"nest"`
	Egg           int        `json:"egg"`
	Relationships struct {
		Allocations struct {
			Data []struct {
				Attributes struct {
					IP        string `json:"ip"`
					Port      int    `json:"port"`
					IsDefault bool   `json:"is_default"`
				} `json:"attributes"`
			} `json:"data"`
		} `json:"allocations"`
	} `json:"relationships"`
}

// flexString accepts a JSON string, number, or null. Ptero external_id is
// usually a string and sometimes null.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*f = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexString(strings.TrimSpace(s))
		return nil
	}
	var n json.Number
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&n); err == nil {
		*f = flexString(n.String())
		return nil
	}
	return fmt.Errorf("external_id rejected")
}

func parseServerPage(body []byte) ([]Server, pageMeta, error) {
	var doc listDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, pageMeta{}, errors.New("source application api body rejected")
	}
	out := make([]Server, 0, len(doc.Data))
	for _, item := range doc.Data {
		a := item.Attributes
		if strings.TrimSpace(a.UUID) == "" {
			return nil, pageMeta{}, errors.New("source application api server missing uuid")
		}
		// a.Nest is intentionally not copied onto Server.
		srv := Server{
			ID:         a.ID,
			UUID:       strings.ToLower(strings.TrimSpace(a.UUID)),
			ExternalID: string(a.ExternalID),
			Name:       a.Name,
			NodeID:     a.Node,
			EggID:      a.Egg,
		}
		for _, al := range a.Relationships.Allocations.Data {
			if al.Attributes.IP == "" || al.Attributes.Port <= 0 {
				continue
			}
			srv.Allocations = append(srv.Allocations, Allocation{
				IP:      al.Attributes.IP,
				Port:    al.Attributes.Port,
				Default: al.Attributes.IsDefault,
			})
		}
		out = append(out, srv)
	}
	meta := pageMeta{
		CurrentPage: doc.Meta.Pagination.CurrentPage,
		TotalPages:  doc.Meta.Pagination.TotalPages,
	}
	if meta.CurrentPage == 0 {
		meta.CurrentPage = 1
	}
	return out, meta, nil
}
