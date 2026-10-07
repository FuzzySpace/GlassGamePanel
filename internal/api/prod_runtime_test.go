package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FuzzySpace/GlassGamePanel/internal/config"
)

func TestRuntimeHeaderByPlane(t *testing.T) {
	testSrv, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got := headerRuntime(testSrv); got != "panel-api-test" {
		t.Fatalf("test runtime %s", got)
	}

	prod := config.Config{
		Env:           "prod",
		ListenAddr:    config.DefaultListenAddr,
		JWTSecret:     []byte("day1-prod-hmac-secret-value"),
		JWTIss:        config.ProdJWTIss,
		JWTAud:        config.ProdJWTAud,
		JWTJWKSURL:    config.ProdJWTJWKSURL,
		JWTKID:        config.ProdJWTKID,
		PublicBaseURL: config.ProdPublicBase,
		MutateRPM:     config.MaxMutateRPM,
		ReadRPM:       config.MaxReadRPM,
		WingsExecutor: config.WingsExecutorNoop,
	}
	prodSrv, err := New(prod)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	prodSrv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("health %d", rr.Code)
	}
	if got := rr.Header().Get("X-Glass-Runtime"); got != "panel-api" {
		t.Fatalf("prod runtime %s", got)
	}
	if got := rr.Header().Get("X-Glass-Executor"); got != "noop" {
		t.Fatalf("executor %s", got)
	}
	if got := rr.Header().Get("X-Glass-Wings-Dispatch"); got != "0" {
		t.Fatalf("dispatch %s", got)
	}
	if prodSrv.DenySHA256() != "a511e974bb08f6f19f612f19e1bb9cb2693489eeb8d4869351e42e0279824097" {
		t.Fatalf("deny sha %s", prodSrv.DenySHA256())
	}
}

func headerRuntime(srv *Server) string {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.Handler().ServeHTTP(rr, req)
	return rr.Header().Get("X-Glass-Runtime")
}
