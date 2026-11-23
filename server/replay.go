package server

// 数据重放（对齐 Docker 版 /function/replay）。
//
// 与「流量页重放」的区别：这里是独立入口，输入是**任意粘贴过来的报文**——
// Burp「Copy as raw」原文或 curl 命令，解析成结构化请求后发送，
// 并把每一次发送（请求 + 响应 + 归属任务）持久化，可反复复制/重发/删除。
//
// 接口：
//   POST   /api/replay/parse  解析（不发包）          → 结构化请求
//   POST   /api/replay        解析 + 发送 + 落库       → 完整记录
//   GET    /api/replay        记录列表（按 task_id 过滤）
//   GET    /api/replay/{id}   单条记录
//   DELETE /api/replay/{id}   删除记录
//
// 红线：发送前目标主机必须通过「资产拦截规则」；命中即拒绝并落一条 error 记录。

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"

	"github.com/Autumn-27/artex/db"
)

const (
	replayBodyLimit    = 512 * 1024
	replayDefaultSec   = 30
	replayMaxSec       = 300
	replayMaxInputSize = 2 << 20
	replayListLimit    = 50
)

// ReplayParsed 是解析后的结构化请求（parse 与 send 共用）。
type ReplayParsed struct {
	Format      string            `json:"format"` // burp|curl
	Scheme      string            `json:"scheme"` // http|https
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type,omitempty"`
}

type replayParseReq struct {
	Format string `json:"format"` // ""/"auto" = 自动识别
	Input  string `json:"input"`
	Scheme string `json:"scheme"` // ""/"auto" = 按报文推断
}

type replaySendReq struct {
	TaskID          string `json:"task_id"`
	Format          string `json:"format"`
	Input           string `json:"input"`
	Scheme          string `json:"scheme"`
	TimeoutSec      int    `json:"timeout_sec"`
	FollowRedirects bool   `json:"follow_redirects"`
	InsecureTLS     bool   `json:"insecure_tls"`
}

// replayParse POST /api/replay/parse —— 只解析，不发包。
func (s *Server) replayParse(w http.ResponseWriter, r *http.Request) {
	var req replayParseReq
	if err := json.NewDecoder(io.LimitReader(r.Body, replayMaxInputSize)).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	parsed, err := parseReplayInput(req.Format, req.Input, req.Scheme)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, parsed)
}

// replaySend POST /api/replay —— 解析 + 发送 + 落库。
func (s *Server) replaySend(w http.ResponseWriter, r *http.Request) {
	var req replaySendReq
	if err := json.NewDecoder(io.LimitReader(r.Body, replayMaxInputSize)).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Input) == "" {
		writeErr(w, 400, "先粘贴 Burp 原始报文或 curl 命令")
		return
	}
	parsed, err := parseReplayInput(req.Format, req.Input, req.Scheme)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	timeoutSec := req.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = replayDefaultSec
	}
	if timeoutSec > replayMaxSec {
		timeoutSec = replayMaxSec
	}

	rec := db.ReplayRecord{
		TaskID:     strings.TrimSpace(req.TaskID),
		Format:     parsed.Format,
		Scheme:     parsed.Scheme,
		Method:     parsed.Method,
		URL:        parsed.URL,
		ReqHeaders: parsed.Headers,
		ReqBody:    parsed.Body,
	}

	// 红线：目标必须通过资产拦截规则。
	if reason, blocked := s.replayBlockedByRule(parsed.Host); blocked {
		rec.Error = "重放目标被资产拦截规则命中（" + reason + "），禁止重放"
		saved, saveErr := s.saveReplay(rec)
		if saveErr != nil {
			writeErr(w, 500, saveErr.Error())
			return
		}
		writeJSON(w, 403, replayDTO(saved))
		return
	}

	result, sendErr := performReplayRequest(parsed, time.Duration(timeoutSec)*time.Second, req.FollowRedirects, req.InsecureTLS)
	if sendErr != nil {
		rec.Error = sendErr.Error()
		saved, saveErr := s.saveReplay(rec)
		if saveErr != nil {
			writeErr(w, 502, sendErr.Error())
			return
		}
		writeJSON(w, 502, replayDTO(saved))
		return
	}

	rec.Status = result.Status
	rec.StatusText = result.StatusText
	rec.RespHeaders = result.Headers
	rec.RespBody = result.Body
	rec.RespBodyTruncated = result.Truncated
	rec.DurationMs = result.DurationMs
	rec.RespLen = result.RespLen

	saved, saveErr := s.saveReplay(rec)
	if saveErr != nil {
		// 记录落库失败不应吞掉响应本身：返回未持久化的结果。
		writeJSON(w, 200, replayDTO(rec))
		return
	}
	writeJSON(w, 200, replayDTO(saved))
}

func (s *Server) saveReplay(rec db.ReplayRecord) (db.ReplayRecord, error) {
	if s.m.pg == nil {
		return rec, nil
	}
	saved, err := s.m.pg.CreateReplay(rec)
	if err != nil {
		return rec, err
	}
	return saved, nil
}

// replayDTO 收敛返回体：前端读 id/task_id/method/url/status/req_*/resp_*。
func replayDTO(rec db.ReplayRecord) map[string]any {
	return map[string]any{
		"id":                  rec.ID,
		"task_id":             rec.TaskID,
		"format":              rec.Format,
		"scheme":              rec.Scheme,
		"method":              rec.Method,
		"url":                 rec.URL,
		"req_headers":         rec.ReqHeaders,
		"req_body":            rec.ReqBody,
		"status":              rec.Status,
		"status_text":         rec.StatusText,
		"resp_headers":        rec.RespHeaders,
		"resp_body":           rec.RespBody,
		"resp_body_truncated": rec.RespBodyTruncated,
		"duration_ms":         rec.DurationMs,
		"resp_len":            rec.RespLen,
		"error":               rec.Error,
		"created_at":          rec.CreatedAt,
	}
}

// replayList GET /api/replay?task_id=&limit=&offset=
func (s *Server) replayList(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeJSON(w, 200, map[string]any{"items": []any{}, "total": 0})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	idRange, rangeErr := db.ParseReplayIDRange(q.Get("ids"))
	if rangeErr != nil {
		writeErr(w, 400, rangeErr.Error())
		return
	}
	records, total, err := s.m.pg.ListReplays(strings.TrimSpace(q.Get("task_id")), limit, offset, idRange)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		items = append(items, replayDTO(rec))
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
}

// replayGet GET /api/replay/{id}
func (s *Server) replayGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	if s.m.pg == nil {
		writeErr(w, 404, "replay record not found")
		return
	}
	rec, err := s.m.pg.GetReplay(id)
	if errors.Is(err, db.ErrReplayNotFound) {
		writeErr(w, 404, "重放记录不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, replayDTO(rec))
}

// replayBatchDelete POST /api/replay/delete
//
// 批量删除重放记录，支持三种范围（优先级从高到低）：
//   ids: [12,13]        按勾选的重放编号
//   ids_range: "12-19"  按编号区间
//   两者都空            清空全部
// 返回 { deleted: n }。
func (s *Server) replayBatchDelete(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeJSON(w, 200, map[string]any{"deleted": 0})
		return
	}
	var req struct {
		IDs      []int64 `json:"ids"`
		IDsRange string  `json:"ids_range"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	idRange, rangeErr := db.ParseReplayIDRange(req.IDsRange)
	if rangeErr != nil {
		writeErr(w, 400, rangeErr.Error())
		return
	}
	deleted, err := s.m.pg.DeleteReplays(req.IDs, idRange)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": deleted})
}

// replayDelete DELETE /api/replay/{id}
func (s *Server) replayDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	if s.m.pg == nil {
		writeErr(w, 404, "replay record not found")
		return
	}
	if err := s.m.pg.DeleteReplay(id); err != nil {
		if errors.Is(err, db.ErrReplayNotFound) {
			writeErr(w, 404, "重放记录不存在")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ── 输入解析 ────────────────────────────────────────────────────────────────

// Go 的 regexp 不支持反向引用，引号参数用「双引号段 | 单引号段」两个分支匹配。
var curlHeaderRe = regexp.MustCompile(`(?:^|\s)-{1,2}(?:header|H)\s+(?:"([^"]*)"|'([^']*)')`)
var curlAllDataRe = regexp.MustCompile(`(?:^|\s)(?:-{1,2}data(?:-raw|-binary|-urlencode)?|-d)\s+(?:"([\s\S]*?)"|'([\s\S]*?)')`)
var curlMethodRe = regexp.MustCompile(`(?:^|\s)(?:-X|--request)\s+([A-Za-z]+)`)
var curlURLRe = regexp.MustCompile(`(?:^|\s)(?:"(https?://[^"]+)"|'(https?://[^']+)'|(https?://[^\s'"]+))`)

// detectReplayFormat 自动识别输入格式。
//
// 判据（按可靠性排序）：
//  1. 首行是 `METHOD /path HTTP/1.x` → Burp 原始报文
//  2. 首行/首个非空 token 是 curl 且不含请求行 → curl 命令
//  3. 出现 `-X` / `--data` / `-H` 等 curl 参数 → curl
//  默认按 Burp 处理（用户粘贴最多的就是报文）。
func detectReplayFormat(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "burp"
	}
	firstLine := trimmed
	if idx := strings.IndexByte(firstLine, '\n'); idx >= 0 {
		firstLine = firstLine[:idx]
	}
	// 1) 明确的 HTTP 请求行优先
	if requestLineRe.MatchString(strings.TrimSpace(firstLine)) {
		return "burp"
	}
	// 2) 以 curl 开头（允许 `$ curl`、`sudo curl`、换行续行）
	lowered := strings.ToLower(trimmed)
	head := lowered
	if len(head) > 200 {
		head = head[:200]
	}
	if regexp.MustCompile(`(^|[\s$])(sudo\s+)?curl(\.exe)?\s`).MatchString(head) {
		return "curl"
	}
	// 3) 只有 curl 参数、没有请求行
	if !strings.Contains(lowered, "http/") &&
		regexp.MustCompile(`(?m)(^|\s)(-X|--request|-H|--header|-d|--data[a-z-]*)\s`).MatchString(trimmed) {
		return "curl"
	}
	return "burp"
}

var requestLineRe = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+(\s+HTTP/[\d.]+)?\s*$`)

// parseReplayInput 自动识别 Burp 原始报文 / curl 命令并解析为结构化请求。
func parseReplayInput(format, input, scheme string) (ReplayParsed, error) {
	text := strings.ReplaceAll(input, "\r\n", "\n")
	if strings.TrimSpace(text) == "" {
		return ReplayParsed{}, fmt.Errorf("输入为空")
	}
	f := strings.ToLower(strings.TrimSpace(format))
	if f == "" || f == "auto" {
		f = detectReplayFormat(text)
	}
	switch f {
	case "curl":
		return parseCurl(text, scheme)
	case "burp":
		return parseBurp(text, scheme)
	default:
		return ReplayParsed{}, fmt.Errorf("不支持的格式：%s（可选 burp / curl / auto）", format)
	}
}

// parseBurp 解析 Burp「Copy as raw」报文：
//
//	POST /path HTTP/1.1
//	Host: example.com
//	Header: value
//
//	body
func parseBurp(text, scheme string) (ReplayParsed, error) {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return ReplayParsed{}, fmt.Errorf("报文为空")
	}
	requestLine := strings.TrimSpace(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return ReplayParsed{}, fmt.Errorf("请求行无法解析（应为 METHOD /path HTTP/1.1）：%s", requestLine)
	}
	method := strings.ToUpper(parts[0])
	target := parts[1]

	headers := map[string]string{}
	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			bodyStart = i + 1
			break
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue // 折行头部忽略
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key != "" {
			headers[key] = val
		}
	}
	var body string
	if bodyStart >= 0 && bodyStart <= len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}

	host := ""
	for key, value := range headers {
		if strings.EqualFold(key, "host") {
			host = value
			break
		}
	}
	if host == "" {
		return ReplayParsed{}, fmt.Errorf("缺少 Host 头，无法确定目标")
	}

	sch := normalizeScheme(scheme)
	if sch == "" {
		if strings.HasPrefix(strings.ToLower(target), "https://") {
			sch = "https"
		} else {
			sch = "http"
		}
	}
	fullURL, err := buildReplayURL(sch, host, target)
	if err != nil {
		return ReplayParsed{}, err
	}
	return ReplayParsed{
		Format:      "burp",
		Scheme:      sch,
		Method:      method,
		URL:         fullURL,
		Host:        hostOnly(host),
		Headers:     headers,
		Body:        body,
		ContentType: headerValue(headers, "content-type"),
	}, nil
}

// parseCurl 解析 curl 命令（支持 -X/-H/-d/--data-raw/--data-binary/--data-urlencode）。
//
// --data-urlencode 的语义是「这条 data 做 URL 编码后作为表单字段」，多个 data 段
// 用 & 连接（curl 就是这么拼的）。它**不会**把已有值里的空格换成 &，那是我之前的错误实现。
func parseCurl(text, scheme string) (ReplayParsed, error) {
	// 先按出现顺序收集所有 data 段（-d / --data-* / --data-urlencode）。
	dataParts := curlAllDataRe.FindAllStringSubmatch(text, -1)
	bodies := make([]string, 0, len(dataParts))
	for _, m := range dataParts {
		if len(m) < 2 {
			continue
		}
		raw := unescapeShell(firstGroup(m[1:]))
		if raw != "" {
			bodies = append(bodies, raw)
		}
	}
	// 多段 data 以 & 连接（-F 表单、--data-urlencode 都遵循这个规则）。
	body := strings.Join(bodies, "&")

	headers := map[string]string{}
	for _, m := range curlHeaderRe.FindAllStringSubmatch(text, -1) {
		if len(m) < 2 {
			continue
		}
		raw := unescapeShell(firstGroup(m[1:]))
		if idx := strings.Index(raw, ":"); idx > 0 {
			headers[strings.TrimSpace(raw[:idx])] = strings.TrimSpace(raw[idx+1:])
		}
	}

	method := ""
	if m := curlMethodRe.FindStringSubmatch(text); len(m) > 1 {
		method = strings.ToUpper(m[1])
	}

	var rawURL string
	if m := curlURLRe.FindStringSubmatch(text); len(m) > 1 {
		rawURL = firstGroup(m[1:])
	}
	if rawURL == "" {
		return ReplayParsed{}, fmt.Errorf("未找到 URL（curl 命令需包含完整 http(s):// 地址）")
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Host == "" {
		return ReplayParsed{}, fmt.Errorf("URL 无法解析：%s", rawURL)
	}
	sch := normalizeScheme(scheme)
	if sch == "" {
		sch = parsedURL.Scheme
	}
	if sch != "http" && sch != "https" {
		return ReplayParsed{}, fmt.Errorf("不支持的协议：%s", parsedURL.Scheme)
	}
	if method == "" {
		if body != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	if body != "" && headerValue(headers, "content-type") == "" && !strings.Contains(text, "--data-urlencode") {
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}
	if headerValue(headers, "host") == "" {
		headers["Host"] = parsedURL.Host
	}
	if !strings.HasPrefix(strings.ToLower(rawURL), sch+"://") {
		rawURL = sch + "://" + parsedURL.Host + parsedURL.RequestURI()
	}
	return ReplayParsed{
		Format:      "curl",
		Scheme:      sch,
		Method:      method,
		URL:         rawURL,
		Host:        parsedURL.Hostname(),
		Headers:     headers,
		Body:        body,
		ContentType: headerValue(headers, "content-type"),
	}, nil
}

// firstGroup 取第一个非空捕获组（多引号分支匹配后只有一个分支命中）。
func firstGroup(groups []string) string {
	for _, g := range groups {
		if g != "" {
			return g
		}
	}
	return ""
}

func unescapeShell(s string) string {
	replacer := strings.NewReplacer(`\\n`, "\n", `\\r`, "\r", `\\t`, "\t", `\\"`, `"`, `\\'`, `'`, `\\`, `\`)
	return replacer.Replace(s)
}

func normalizeScheme(scheme string) string {
	s := strings.ToLower(strings.TrimSpace(scheme))
	if s == "auto" {
		return ""
	}
	if s == "http" || s == "https" {
		return s
	}
	return ""
}

func hostOnly(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		return strings.Trim(host[:i], "[]")
	}
	return strings.Trim(host, "[]")
}

func headerValue(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func buildReplayURL(scheme, host, target string) (string, error) {
	if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
		return target, nil
	}
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	return scheme + "://" + host + target, nil
}

// ── 发送 ────────────────────────────────────────────────────────────────────

type replaySendResult struct {
	Status     int
	StatusText string
	Headers    map[string]string
	Body       string
	Truncated  bool
	RespLen    int64
	DurationMs int64
}

func performReplayRequest(p ReplayParsed, timeout time.Duration, followRedirects, insecureTLS bool) (replaySendResult, error) {
	var out replaySendResult

	req, err := http.NewRequestWithContext(context.Background(), p.Method, p.URL, strings.NewReader(p.Body))
	if err != nil {
		return out, fmt.Errorf("构造请求失败：%w", err)
	}
	for key, value := range p.Headers {
		if strings.EqualFold(key, "host") || strings.EqualFold(key, "content-length") {
			continue // 交给 Transport 处理，避免签名/长度不一致
		}
		req.Header.Set(key, value)
	}
	if p.Body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecureTLS}, //nolint:gosec // 靶场自签证书场景
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	if !followRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return out, fmt.Errorf("发送失败：%w", err)
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, replayBodyLimit+1))
	if readErr != nil && len(raw) == 0 {
		return out, fmt.Errorf("读取响应失败：%w", readErr)
	}
	truncated := len(raw) > replayBodyLimit
	if truncated {
		raw = raw[:replayBodyLimit]
	}

	headers := make(map[string]string, len(resp.Header))
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}
	statusText := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))

	return replaySendResult{
		Status:     resp.StatusCode,
		StatusText: statusText,
		Headers:    headers,
		Body:       decodeReplayBody(raw, headerValue(headers, "content-encoding")),
		Truncated:  truncated,
		RespLen:    int64(len(raw)),
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

// decodeReplayBody 尽量给出可读正文：gzip/deflate 解压，二进制退化为占位说明。
func decodeReplayBody(raw []byte, contentEncoding string) string {
	if len(raw) == 0 {
		return ""
	}
	decoded := raw
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "gzip":
		if r, err := newGzipReader(bytes.NewReader(raw)); err == nil {
			defer r.Close()
			if b, err := io.ReadAll(io.LimitReader(r, replayBodyLimit)); err == nil {
				decoded = b
			}
		}
	case "deflate":
		if r, err := newZlibReader(bytes.NewReader(raw)); err == nil {
			defer r.Close()
			if b, err := io.ReadAll(io.LimitReader(r, replayBodyLimit)); err == nil {
				decoded = b
			}
		}
	}
	if !utf8.Valid(decoded) {
		// GBK/GB18030 等非 UTF-8 文本（国内站点常见）不能被当成二进制丢弃：
		// 只有含 NUL 字节或替换率极高的才按二进制处理。
		if converted, ok := decodeGBKLoose(decoded); ok {
			return converted
		}
		return fmt.Sprintf("（二进制正文 %d 字节，已省略）", len(raw))
	}
	return string(decoded)
}

// decodeGBKLoose 用 GB18030 宽松解码：能解出可读文本就返回，否则 ok=false。
// 目标：pikachu/phpstudy 这类 GBK 页面在重放留痕里必须能看到命令回显原文。
func decodeGBKLoose(raw []byte) (string, bool) {
	if bytes.IndexByte(raw, 0) >= 0 {
		return "", false // 含 NUL，判定为真二进制
	}
	converted, err := simplifiedchinese.GB18030.NewDecoder().Bytes(raw)
	if err != nil || len(converted) == 0 {
		return "", false
	}
	bad := bytes.Count(converted, []byte("\uFFFD"))
	// 替换字符占比超过 2% 视为解码失败，避免把二进制解成乱码。
	if bad*50 > len([]rune(string(converted))) {
		return "", false
	}
	return string(converted), true
}

func newGzipReader(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) }

func newZlibReader(r io.Reader) (io.ReadCloser, error) { return zlib.NewReader(r) }
