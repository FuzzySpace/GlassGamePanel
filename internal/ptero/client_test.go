package ptero

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseDropsNestAndPages(t *testing.T) {
	const page = `{
	  "data": [{
	    "object": "server",
	    "attributes": {
	      "id": 19,
	      "external_id": "19",
	      "uuid": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
	      "name": "Commercial",
	      "node": 5,
	      "nest": 11,
	      "egg": 15,
	      "relationships": {
	        "allocations": {
	          "data": [
	            {"object": "allocation", "attributes": {"ip": "203.0.113.10", "port": 25565, "is_default": true}},
	            {"object": "allocation", "attributes": {"ip": "2001:db8::10", "port": 25565, "is_default": false}}
	          ]
	        }
	      }
	    }
	  }],
	  "meta": {"pagination": {"current_page": 1, "total_pages": 1}}
	}`
	rows, meta, err := parseServerPage([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	if meta.TotalPages != 1 || len(rows) != 1 {
		t.Fatalf("meta %+v rows %d", meta, len(rows))
	}
	if rows[0].UUID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || rows[0].EggID != 15 || rows[0].NodeID != 5 {
		t.Fatalf("row %+v", rows[0])
	}
	if len(rows[0].Allocations) != 2 || rows[0].Allocations[1].IP != "2001:db8::10" {
		t.Fatalf("alloc %+v", rows[0].Allocations)
	}
	b, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(b)), "nest") {
		t.Fatalf("nest leaked into encoded server: %s", b)
	}
}

func TestListUsesEnvTokenAndRejectsRedirect(t *testing.T) {
	const envToken = "test-ro-application-token"
	const bodyToken = "body-token-must-not-be-sent"
	var secondHits int
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits++
		http.Error(w, "redirect target", http.StatusOK)
	}))
	t.Cleanup(second.Close)

	var pages int
	var sawAuth []string
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		if strings.Contains(r.Header.Get("Authorization"), bodyToken) {
			t.Fatal("body token was sent")
		}
		if strings.Contains(r.URL.RawQuery, "token") || strings.Contains(r.URL.RawQuery, envToken) {
			t.Fatal("token leaked onto the url")
		}
		http.Redirect(w, r, second.URL+"/api/application/servers", http.StatusFound)
	}))
	t.Cleanup(primary.Close)

	c, err := New(primary.URL, envToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListServers(context.Background()); err == nil {
		t.Fatal("redirect was followed")
	}
	if secondHits != 0 {
		t.Fatalf("redirect target hits %d", secondHits)
	}
	if pages != 1 || len(sawAuth) != 1 || sawAuth[0] != "Bearer "+envToken {
		t.Fatalf("pages %d auth %v", pages, sawAuth)
	}
}

func TestListPaginates(t *testing.T) {
	const token = "test-ro-application-token"
	var gotPages []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		page := r.URL.Query().Get("page")
		gotPages = append(gotPages, page)
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "1":
			_, _ = w.Write([]byte(`{"data":[{"attributes":{"id":19,"external_id":"19","uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","name":"A","node":5,"nest":11,"egg":15}}],"meta":{"pagination":{"current_page":1,"total_pages":2}}}`))
		case "2":
			_, _ = w.Write([]byte(`{"data":[{"attributes":{"id":20,"external_id":null,"uuid":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","name":"B","node":5,"nest":11,"egg":16}}],"meta":{"pagination":{"current_page":2,"total_pages":2}}}`))
		default:
			http.Error(w, "page", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.ListServers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1].ExternalID != "" || rows[0].EggID != 15 {
		t.Fatalf("rows %+v", rows)
	}
	if strings.Join(gotPages, ",") != "1,2" {
		t.Fatalf("pages %v", gotPages)
	}
}

func TestNewRejectsUserinfo(t *testing.T) {
	if _, err := New("https://user:secret@panel.example", "test-ro-application-token"); err == nil {
		t.Fatal("userinfo accepted")
	}
}
