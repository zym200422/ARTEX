package server

// 流量重放单测：验证原样发送、响应解析与目标解析。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPerformReplayEchoesRequest(t *testing.T) {
	var gotMethod, gotURI, gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotURI = r.URL.RequestURI()
		gotHeader = r.Header.Get("X-Test")
		w.Header().Set("X-Probe", "ok")
		w.WriteHeader(234)
		_, _ = w.Write([]byte("replay-body"))
	}))
	defer srv.Close()

	target := strings.TrimPrefix(srv.URL, "http://")
	raw := "POST /pikachu/x HTTP/1.1\nHost: target.example\nX-Test: v1\nContent-Type: text/plain\n\nbody=1"

	resp, err := performReplay(raw, target, false, false, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 234 {
		t.Fatalf("status = %d, want 234", resp.Status)
	}
	if resp.Body != "replay-body" {
		t.Fatalf("body = %q", resp.Body)
	}
	if gotMethod != "POST" || gotURI != "/pikachu/x" || gotHeader != "v1" {
		t.Fatalf("server received method=%q uri=%q x-test=%q", gotMethod, gotURI, gotHeader)
	}
	if resp.Target != target {
		t.Fatalf("target = %q, want %q", resp.Target, target)
	}
	if resp.Headers["X-Probe"] != "ok" {
		t.Fatalf("X-Probe = %q", resp.Headers["X-Probe"])
	}
}

func TestPerformReplayGzipRewrite(t *testing.T) {
	var gotAE string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	raw := "GET / HTTP/1.1\nHost: t.example\nAccept-Encoding: gzip, br\n\n"
	if _, err := performReplay(raw, target, false, true, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if gotAE != "identity" {
		t.Fatalf("Accept-Encoding = %q, want identity", gotAE)
	}
}

func TestReplayTargetParsing(t *testing.T) {
	host, port, err := replayTarget("", "GET /x HTTP/1.1\nHost: api.acme.com:8443\n\n", false)
	if err != nil || host != "api.acme.com" || port != "8443" {
		t.Fatalf("host=%q port=%q err=%v", host, port, err)
	}
	host, port, err = replayTarget("10.0.0.5", "GET / HTTP/1.1\n\n", true)
	if err != nil || host != "10.0.0.5" || port != "443" {
		t.Fatalf("host=%q port=%q err=%v", host, port, err)
	}
	if _, _, err := replayTarget("", "GET / HTTP/1.1\n\n", false); err == nil {
		t.Fatal("no host should error")
	}
	if _, _, err := replayTarget("http://bad.example", "GET / HTTP/1.1\n\n", false); err == nil {
		t.Fatal("scheme in host should error")
	}
}

func TestRewriteAcceptEncoding(t *testing.T) {
	wire := "GET / HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\n\r\n"
	out := rewriteAcceptEncoding(wire)
	if !strings.Contains(out, "Accept-Encoding: identity") {
		t.Fatalf("rewrite failed: %q", out)
	}
	if strings.Contains(out, "gzip") {
		t.Fatalf("gzip still present: %q", out)
	}
}
