package server

// 流量重放：把录制的原始请求原样（或改参后）重新发给目标，回显真实响应。
// 相当于内置一个 Burp Repeater——录什么发什么，所见即所发。
//
// 红线：重放目标必须通过「资产拦截规则」校验，命中拦截规则的主机一律 403。
// 报文语义：原样发送用户编辑后的字节（不经过 Go 客户端规范化），
// 仅在勾选「自动去 gzip」时把 Accept-Encoding 改写为 identity。

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// replayMaxBody 响应正文回显上限 512KB，超出截断（完整抓包仍在流量树里）。
const replayMaxBody = 512 * 1024

const (
	replayDefaultTimeout = 15 * time.Second
	replayMaxTimeout     = 60 * time.Second
)

type trafficReplayReq struct {
	Raw       string `json:"raw"`        // 完整原始请求（请求行/头/体）
	Host      string `json:"host"`       // 实际拨号目标 host[:port]；空 = 从 Host 头解析
	TLS       bool   `json:"tls"`        // 是否走 TLS
	TimeoutMs int    `json:"timeout_ms"` // 超时；0 = 默认 15s，上限 60s
	NoGzip    bool   `json:"no_gzip"`    // true = 把 Accept-Encoding 改写为 identity，响应可读
}

type trafficReplayResp struct {
	Status     int               `json:"status"`
	StatusLine string            `json:"status_line"`
	Proto      string            `json:"proto"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	BodyTrunc  bool              `json:"body_truncated"`
	DurationMs int64             `json:"duration_ms"`
	Target     string            `json:"target"`
}

// trafficReplay POST /api/traffic/replay
func (s *Server) trafficReplay(w http.ResponseWriter, r *http.Request) {
	var req trafficReplayReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	raw := strings.ReplaceAll(req.Raw, "\r\n", "\n")
	if strings.TrimSpace(raw) == "" {
		writeErr(w, 400, "missing raw request")
		return
	}

	host, port, err := replayTarget(req.Host, raw, req.TLS)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	if reason, blocked := s.replayBlockedByRule(host); blocked {
		writeErr(w, 403, "重放目标被资产拦截规则命中（"+reason+"），禁止重放")
		return
	}

	timeout := replayDefaultTimeout
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
		if timeout > replayMaxTimeout {
			timeout = replayMaxTimeout
		}
	}

	result, err := performReplay(raw, host+":"+port, req.TLS, req.NoGzip, timeout)
	if err != nil {
		writeErr(w, 502, "重放失败："+err.Error())
		return
	}
	writeJSON(w, 200, result)
}

// replayTarget 解析拨号目标：显式 Host[:port] 优先，其次请求头里的 Host:。
func replayTarget(hostOverride, raw string, useTLS bool) (host, port string, err error) {
	h := strings.TrimSpace(hostOverride)
	if h == "" {
		sc := bufio.NewScanner(strings.NewReader(raw))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				break
			}
			if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
				h = strings.TrimSpace(line[5:])
				break
			}
		}
	}
	if h == "" {
		return "", "", fmt.Errorf("无法确定目标主机：请在「目标主机」填写 host[:port]，或让请求自带 Host 头")
	}
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i:], "]") {
		host, port = h[:i], h[i+1:]
	} else {
		host = strings.Trim(h, "[]")
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", "", fmt.Errorf("目标主机为空")
	}
	if strings.Contains(host, "://") {
		return "", "", fmt.Errorf("目标主机不要带 http:// 协议前缀，TLS 用开关控制")
	}
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", "", fmt.Errorf("端口不合法：%s", port)
	}
	return host, port, nil
}

// replayBlockedByRule 用「资产拦截规则」校验重放目标：命中任意启用的拦截规则即禁止。
func (s *Server) replayBlockedByRule(host string) (string, bool) {
	pg := s.m.pg
	if pg == nil {
		return "", false
	}
	rules, err := pg.ListAssetInterceptRules()
	if err != nil {
		return "", false
	}
	host = strings.ToLower(strings.Trim(host, "."))
	ip := net.ParseIP(host)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		pattern := strings.ToLower(strings.TrimSpace(rule.Pattern))
		if pattern == "" {
			continue
		}
		matched := false
		switch rule.Kind {
		case "exact_domain", "exact_ip":
			matched = host == pattern
		case "fuzzy_domain":
			matched = strings.HasSuffix(host, pattern) || strings.HasSuffix(host, "."+strings.TrimPrefix(pattern, "."))
		case "fuzzy_ip":
			matched = strings.HasPrefix(host, pattern)
		case "cidr":
			if _, cidrNet, cErr := net.ParseCIDR(pattern); cErr == nil && ip != nil {
				matched = cidrNet.Contains(ip)
			}
		}
		if matched {
			reason := pattern
			if rule.Note != "" {
				reason = fmt.Sprintf("%s（%s）", pattern, rule.Note)
			}
			return reason, true
		}
	}
	return "", false
}

// performReplay 原样发送编辑后的请求字节（不做 Go 客户端规范化），解析真实响应。
func performReplay(raw, hostOverride string, useTLS, noGzip bool, timeout time.Duration) (*trafficReplayResp, error) {
	host, port, err := replayTarget(hostOverride, raw, useTLS)
	if err != nil {
		return nil, err
	}

	wire := strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\n", "\r\n")
	if noGzip {
		wire = rewriteAcceptEncoding(wire)
	}
	if !strings.Contains(wire, "\r\n\r\n") {
		// 请求头与体之间保证一个空行，部分编辑器会把它弄丢。
		wire = strings.TrimRight(wire, "\r\n") + "\r\n\r\n"
	}

	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout, Deadline: time.Now().Add(timeout)}
	var conn net.Conn
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.DialContext(context.Background(), "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败：%w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, wErr := conn.Write([]byte(wire)); wErr != nil {
		return nil, fmt.Errorf("发送请求失败：%w", wErr)
	}

	start := time.Now()
	httpReq, pErr := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
	if pErr != nil {
		return nil, fmt.Errorf("解析请求失败：%w", pErr)
	}
	resp, rErr := http.ReadResponse(bufio.NewReader(conn), httpReq)
	if rErr != nil {
		return nil, fmt.Errorf("读取响应失败：%w", rErr)
	}
	defer resp.Body.Close()

	body, truncated, bErr := readReplayBody(resp.Body)
	if bErr != nil && body == "" {
		return nil, fmt.Errorf("读取响应正文失败：%w", bErr)
	}

	headers := make(map[string]string, len(resp.Header))
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	duration := time.Since(start).Milliseconds()
	return &trafficReplayResp{
		Status:     resp.StatusCode,
		StatusLine: resp.Proto + " " + resp.Status,
		Proto:      resp.Proto,
		Headers:    headers,
		Body:       string(body),
		BodyTrunc:  truncated,
		DurationMs: duration,
		Target:     host + ":" + port,
	}, nil
}

func readReplayBody(r io.Reader) (string, bool, error) {
	limited := io.LimitReader(r, replayMaxBody+1)
	raw, err := io.ReadAll(limited)
	if err != nil && len(raw) == 0 {
		return "", false, err
	}
	truncated := len(raw) > replayMaxBody
	if truncated {
		raw = raw[:replayMaxBody]
	}
	return string(raw), truncated, nil
}

// rewriteAcceptEncoding 把 Accept-Encoding 改写为 identity（没有则跳过），让回显正文可读。
func rewriteAcceptEncoding(wire string) string {
	lines := strings.Split(wire, "\r\n")
	for i, line := range lines {
		if i == 0 {
			continue // 请求行
		}
		if line == "" {
			break // 头结束
		}
		if strings.HasPrefix(strings.ToLower(line), "accept-encoding:") {
			lines[i] = "Accept-Encoding: identity"
			break
		}
	}
	return strings.Join(lines, "\r\n")
}
