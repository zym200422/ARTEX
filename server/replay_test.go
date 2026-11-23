package server

// 数据重放解析器单测：Burp 原始报文 / curl 命令 / 目标与 body 归一。

import (
	"strings"
	"testing"
)

func TestParseBurpRaw(t *testing.T) {
	input := "POST /pikachu/vul/sqli/sqli_str.php?name=kobe HTTP/1.1\n" +
		"Host: 10.113.76.85\n" +
		"Content-Type: application/x-www-form-urlencoded\n" +
		"Cookie: PHPSESSID=abc\n" +
		"\n" +
		"name=kobe&submit=查询"

	p, err := parseReplayInput("auto", input, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != "burp" {
		t.Fatalf("format = %q", p.Format)
	}
	if p.Method != "POST" || p.Scheme != "http" {
		t.Fatalf("method=%q scheme=%q", p.Method, p.Scheme)
	}
	if p.URL != "http://10.113.76.85/pikachu/vul/sqli/sqli_str.php?name=kobe" {
		t.Fatalf("url = %q", p.URL)
	}
	if p.Host != "10.113.76.85" {
		t.Fatalf("host = %q", p.Host)
	}
	if p.Body != "name=kobe&submit=查询" {
		t.Fatalf("body = %q", p.Body)
	}
	if p.Headers["Cookie"] != "PHPSESSID=abc" {
		t.Fatalf("cookie = %q", p.Headers["Cookie"])
	}
}

func TestParseBurpHTTPSAndPort(t *testing.T) {
	input := "GET /x HTTP/1.1\nHost: api.example.com:8443\n\n"
	p, err := parseReplayInput("burp", input, "https")
	if err != nil {
		t.Fatal(err)
	}
	if p.Scheme != "https" || p.URL != "https://api.example.com:8443/x" {
		t.Fatalf("scheme=%q url=%q", p.Scheme, p.URL)
	}
	if p.Host != "api.example.com" {
		t.Fatalf("host = %q", p.Host)
	}
}

func TestParseBurpMissingHost(t *testing.T) {
	if _, err := parseReplayInput("burp", "GET / HTTP/1.1\n\n", ""); err == nil {
		t.Fatal("missing Host should error")
	}
}

func TestParseCurlCommand(t *testing.T) {
	input := `curl -X POST 'http://10.113.76.85/pikachu/vul/xss/xsspost/post_login.php' ` +
		`-H 'Content-Type: application/x-www-form-urlencoded' ` +
		`-H 'Cookie: PHPSESSID=abc' ` +
		`-d 'username=lucy&password=123456'`
	p, err := parseReplayInput("auto", input, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != "curl" {
		t.Fatalf("format = %q", p.Format)
	}
	if p.Method != "POST" {
		t.Fatalf("method = %q", p.Method)
	}
	if p.URL != "http://10.113.76.85/pikachu/vul/xss/xsspost/post_login.php" {
		t.Fatalf("url = %q", p.URL)
	}
	if p.Body != "username=lucy&password=123456" {
		t.Fatalf("body = %q", p.Body)
	}
	if p.Host != "10.113.76.85" {
		t.Fatalf("host = %q", p.Host)
	}
}

func TestParseCurlDefaultsToPostWithBody(t *testing.T) {
	p, err := parseReplayInput("curl", `curl https://example.com/api -d 'a=1'`, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != "POST" || p.Scheme != "https" {
		t.Fatalf("method=%q scheme=%q", p.Method, p.Scheme)
	}
	if !strings.Contains(p.Headers["Content-Type"], "x-www-form-urlencoded") {
		t.Fatalf("content-type = %q", p.Headers["Content-Type"])
	}
}

func TestParseCurlNoURL(t *testing.T) {
	if _, err := parseReplayInput("curl", `curl -X GET`, ""); err == nil {
		t.Fatal("missing URL should error")
	}
}

func TestParseUnknownFormat(t *testing.T) {
	if _, err := parseReplayInput("postman", "whatever", ""); err == nil {
		t.Fatal("unknown format should error")
	}
}

// 回归：多段 --data-urlencode 必须按 & 连接，且值内空格不能被改写。
func TestParseCurlMultiDataUrlencode(t *testing.T) {
	input := `curl -s -X POST http://192.168.1.147/pikachu/vul/xxe/xxe_1.php \
--data-urlencode 'xml=<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "file:///C:/Windows/win.ini">]><a>&e;</a>' \
--data-urlencode 'submit=提交'`
	p, err := parseReplayInput("", input, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != "curl" {
		t.Fatalf("format = %q, want curl", p.Format)
	}
	want := `xml=<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "file:///C:/Windows/win.ini">]><a>&e;</a>&submit=提交`
	if p.Body != want {
		t.Fatalf("body = %q\nwant    %q", p.Body, want)
	}
	if p.Method != "POST" || p.URL != "http://192.168.1.147/pikachu/vul/xxe/xxe_1.php" {
		t.Fatalf("method=%q url=%q", p.Method, p.URL)
	}
	if strings.Contains(p.Body, "&version=") {
		t.Fatal("space inside data value was rewritten to &")
	}
}

// 回归：curl 命令即使在报文中间出现也必须识别为 curl。
func TestDetectReplayFormatCurl(t *testing.T) {
	if got := detectReplayFormat("curl -X GET http://a.com/x"); got != "curl" {
		t.Fatalf("plain curl -> %q", got)
	}
	if got := detectReplayFormat("$ curl -s http://a.com/x -d 'a=1'"); got != "curl" {
		t.Fatalf("$ curl -> %q", got)
	}
	if got := detectReplayFormat("sudo curl https://a.com/x"); got != "curl" {
		t.Fatalf("sudo curl -> %q", got)
	}
	if got := detectReplayFormat("POST /x HTTP/1.1\nHost: a.com\n\nbody"); got != "burp" {
		t.Fatalf("burp -> %q", got)
	}
	// 请求行优先：报文里含 curl 字样也不能误判
	if got := detectReplayFormat("GET /curl?id=1 HTTP/1.1\nHost: a.com\n\n"); got != "burp" {
		t.Fatalf("burp with curl in path -> %q", got)
	}
}
