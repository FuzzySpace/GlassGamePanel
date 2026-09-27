package wings

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPowerPostsBearerAndDoesNotFollowRedirect(t *testing.T) {
	const token = "test-wings-daemon-token"
	const serverID = "d0c77bd4-0a24-4b2d-8e73-213f2b37dce4"
	var secondHits int
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits++
		http.Error(w, "redirect target "+token, http.StatusOK)
	}))
	t.Cleanup(second.Close)

	var hits int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if r.URL.Path != "/api/servers/"+serverID+"/power" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("query %s", r.URL.RawQuery)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization %q", got)
		}
		if got := r.Header.Get("X-Request-Id"); got != "req-wings-power-0001" {
			t.Errorf("request id %q", got)
		}
		if strings.Contains(r.URL.String(), token) {
			t.Fatal("token leaked onto the url")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"action":"start"}` {
			t.Fatalf("body %s", body)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content-type %s", r.Header.Get("Content-Type"))
		}
		http.Redirect(w, r, second.URL+"/evil", http.StatusFound)
	}))
	t.Cleanup(primary.Close)

	c, err := New(primary.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(context.Background(), Request{Op: "power", ServerID: strings.ToUpper(serverID), Action: "start", RequestID: "req-wings-power-0001"})
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), second.URL) {
		t.Fatalf("error leaked secret or redirect target: %v", err)
	}
	if hits != 1 || secondHits != 0 {
		t.Fatalf("hits primary=%d second=%d", hits, secondHits)
	}
}

func TestPowerNon2xxIsCompletedRoundTrip(t *testing.T) {
	const token = "test-wings-daemon-token"
	const serverID = "abababab-abab-4aba-8aba-abababababab"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"no such server ` + token + `"}`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(context.Background(), Request{Op: "power", ServerID: serverID, Action: "kill"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d", res.Status)
	}
	if strings.Contains(res.Summary, token) || strings.Contains(string(res.Body), token) {
		t.Fatalf("token leaked into result summary=%q body=%s", res.Summary, res.Body)
	}
	if !strings.Contains(res.Summary, "[redacted]") {
		t.Fatalf("summary %q", res.Summary)
	}
}

func TestListDirectoryGet(t *testing.T) {
	const token = "test-wings-daemon-token"
	const serverID = "abababab-abab-4aba-8aba-abababababab"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/servers/"+serverID+"/files/list-directory" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("directory") != "/world" {
			t.Errorf("directory %q", r.URL.Query().Get("directory"))
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"server.properties","file":true}]`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(context.Background(), Request{Op: "files", ServerID: serverID, Directory: "/world"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusOK || !strings.Contains(string(res.Body), "server.properties") {
		t.Fatalf("status %d body %s", res.Status, res.Body)
	}
}

func TestNewRejectsUserinfoAndEmptyToken(t *testing.T) {
	if _, err := New("https://wings.example:8080", ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("empty token %v", err)
	}
	_, err := New("https://user:daemon-token-value@wings.example:8080", "daemon-token-value")
	if err == nil || strings.Contains(err.Error(), "daemon-token-value") {
		t.Fatalf("userinfo err %v", err)
	}
	if _, err := New("https://wings.example:8080/api", "daemon-token-value"); err == nil {
		t.Fatal("path accepted")
	}
}

func TestWriteFilePostsArchive(t *testing.T) {
	const token = "test-wings-daemon-token"
	const serverID = "d0c77bd4-0a24-4b2d-8e73-213f2b37dce4"
	jar := append([]byte{0x50, 0x4b, 0x03, 0x04}, make([]byte, 26)...)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost || r.URL.Path != "/api/servers/"+serverID+"/files/write" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("file") != "/mods/fabric-api.jar" {
			t.Errorf("file %q", r.URL.Query().Get("file"))
		}
		if strings.Contains(r.URL.String(), token) {
			t.Fatal("token on url")
		}
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("X-Request-Id") != "req-d2-wings-write01" {
			t.Errorf("headers auth=%q ctype=%q rid=%q", r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header.Get("X-Request-Id"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != string(jar) {
			t.Fatalf("body len %d", len(body))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(context.Background(), Request{Op: "files_write", ServerID: serverID, File: "mods/fabric-api.jar", Content: jar, RequestID: "req-d2-wings-write01"})
	if err != nil || res.Status != http.StatusNoContent || hits != 1 {
		t.Fatalf("status %d err %v hits %d", res.Status, err, hits)
	}
}

func TestDeleteFilePostsRootAndName(t *testing.T) {
	const token = "test-wings-daemon-token"
	const serverID = "abababab-abab-4aba-8aba-abababababab"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/servers/"+serverID+"/files/delete" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"root":"/plugins","files":["Vault.zip"]}` {
			t.Fatalf("body %s", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(context.Background(), Request{Op: "files_delete", ServerID: serverID, File: "/plugins/Vault.zip"})
	if err != nil || res.Status != http.StatusNoContent {
		t.Fatalf("status %d err %v", res.Status, err)
	}
}

func TestWriteRejectsEscapeAndScriptBeforeDial(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "test-wings-daemon-token")
	if err != nil {
		t.Fatal(err)
	}
	jar := append([]byte{0x50, 0x4b, 0x03, 0x04}, make([]byte, 26)...)
	id := "abababab-abab-4aba-8aba-abababababab"
	for _, file := range []string{"/etc/passwd", "../mods/a.jar", "/lib/systemd/system/x.service", "mods/evil.sh"} {
		_, err = c.Do(context.Background(), Request{Op: "files_write", ServerID: id, File: file, Content: jar})
		if !errors.Is(err, ErrBadTarget) {
			t.Fatalf("file %q err %v", file, err)
		}
	}
	_, err = c.Do(context.Background(), Request{Op: "files_write", ServerID: id, File: "mods/fabric-api.jar", Content: []byte("#!/bin/bash\n")})
	if !errors.Is(err, ErrBadTarget) {
		t.Fatalf("script %v", err)
	}
	_, err = c.Do(context.Background(), Request{Op: "files_delete", ServerID: id, File: "/etc/systemd/system/x.service"})
	if !errors.Is(err, ErrBadTarget) {
		t.Fatalf("delete %v", err)
	}
	if hits != 0 {
		t.Fatalf("hits %d", hits)
	}
}

func TestDoRejectsPathEscapeBeforeDial(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "test-wings-daemon-token")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(context.Background(), Request{Op: "files", ServerID: "abababab-abab-4aba-8aba-abababababab", Directory: "/../etc"})
	if !errors.Is(err, ErrBadTarget) {
		t.Fatalf("err %v", err)
	}
	_, err = c.Do(context.Background(), Request{Op: "power", ServerID: "../evil", Action: "start"})
	if !errors.Is(err, ErrBadTarget) {
		t.Fatalf("bad id %v", err)
	}
	if hits != 0 {
		t.Fatalf("hits %d", hits)
	}
}
