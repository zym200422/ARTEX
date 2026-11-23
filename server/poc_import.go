package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/text/encoding/simplifiedchinese"
	"gopkg.in/yaml.v3"
)

// PoC 导入解析：把用户上传/指定目录里的素材翻译成 db.PocInput。
//
// 支持四类格式，按内容自动识别，不看扩展名也尽量能猜对：
//   1. nuclei 模板（YAML，含 id + info + http/requests/...）→ 抽取 CVE/severity/
//      tags/reference，content 存模板原文（agent 可直接照着改请求）。
//   2. 通用 YAML/JSON（单对象、数组、或 {pocs:[...]}）→ 按常见字段名映射。
//   3. Markdown（可带 YAML frontmatter）→ 标题/正文/CVE。
//   4. 其它文本/脚本（.py/.sh/.txt/...）→ 文件名作标题、全文作 content，
//      正则抽 CVE、按关键词猜漏洞类型。
//
// 解析失败只跳过该文件，不中断整批导入。

const pocImportMaxFiles = 5000

type pocFileResult struct {
	Inputs []db.PocInput
	Format string
}

var cveRE = regexp.MustCompile(`(?i)CVE-[0-9]{4}-[0-9]{4,}`)

// vulnTypeKeywords 决定从标题/tags/正文里猜出的漏洞类型（按优先级）。
var vulnTypeKeywords = []struct {
	typ  string
	keys []string
}{
	{"rce", []string{"rce", "remote code execution", "command injection", "cmdi", "命令执行", "代码执行"}},
	{"sqli", []string{"sqli", "sql injection", "sql注", "sql注入"}},
	{"deserialization", []string{"deserialization", "deserialize", "反序列化"}},
	{"ssrf", []string{"ssrf", "server-side request forgery", "服务端请求伪造"}},
	{"xxe", []string{"xxe", "xml external entity"}},
	{"lfi", []string{"lfi", "path traversal", "directory traversal", "file inclusion", "任意文件读", "目录穿越", "路径穿越"}},
	{"upload", []string{"arbitrary file upload", "file upload", "upload", "文件上传", "上传漏洞"}},
	{"auth-bypass", []string{"auth bypass", "authentication bypass", "authorization bypass", "认证绕过", "越权", "权限绕过"}},
	{"default-login", []string{"default login", "default password", "weak password", "默认口令", "弱口令", "默认密码"}},
	{"xss", []string{"xss", "cross site scripting", "跨站脚本"}},
	{"csrf", []string{"csrf", "cross-site request forgery", "跨站请求伪造"}},
	{"info-disclosure", []string{"info disclosure", "information disclosure", "info leak", "信息泄露", "敏感信息"}},
}

func inferVulnType(parts ...string) string {
	hay := strings.ToLower(strings.Join(parts, " "))
	for _, vt := range vulnTypeKeywords {
		for _, k := range vt.keys {
			if strings.Contains(hay, k) {
				return vt.typ
			}
		}
	}
	return ""
}

func extractCVEs(parts ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range parts {
		for _, m := range cveRE.FindAllString(p, -1) {
			u := strings.ToUpper(strings.TrimSpace(m))
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

func pocFileKey(kind string, data []byte) string {
	sum := sha256.Sum256(data)
	return kind + ":" + hex.EncodeToString(sum[:])
}

func pocEntryKey(name, product, vulnType, content string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(strings.Join(strings.Fields(name), " "))))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(strings.TrimSpace(product))))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(strings.TrimSpace(vulnType))))
	h.Write([]byte{0})
	h.Write([]byte(content))
	return "entry:" + hex.EncodeToString(h.Sum(nil))
}

func pocTitleFromFilename(filename string) string {
	base := filepath.Base(strings.TrimSpace(filename))
	if base == "" {
		return "untitled"
	}
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.ReplaceAll(base, "_", " ")
	base = strings.ReplaceAll(base, "-", " ")
	base = strings.Join(strings.Fields(base), " ")
	if base == "" {
		return "untitled"
	}
	return base
}

// anyToStrings accepts the many shapes YAML/JSON give us: scalar (possibly a
// comma/semicolon/newline separated list) or a sequence.
func anyToStrings(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		fields := strings.FieldsFunc(t, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n'
		})
		out := make([]string, 0, len(fields))
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if f != "" {
				out = append(out, f)
			}
		}
		return out
	case []string:
		return t
	case []any:
		out := []string{}
		for _, e := range t {
			out = append(out, anyToStrings(e)...)
		}
		return out
	case int, int64, float64:
		return []string{fmt.Sprintf("%v", t)}
	default:
		return nil
	}
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}

func normalizedMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		nk := strings.ToLower(k)
		nk = strings.ReplaceAll(nk, "-", "")
		nk = strings.ReplaceAll(nk, "_", "")
		out[nk] = v
	}
	return out
}

func pickString(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	nm := normalizedMap(m)
	for _, k := range keys {
		nk := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, "-", ""), "_", ""))
		if v, ok := nm[nk]; ok {
			if s := strings.TrimSpace(stringify(v)); s != "" {
				return s
			}
		}
	}
	return ""
}

func pickStrings(m map[string]any, keys ...string) []string {
	if m == nil {
		return nil
	}
	nm := normalizedMap(m)
	for _, k := range keys {
		nk := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, "-", ""), "_", ""))
		if v, ok := nm[nk]; ok {
			if out := anyToStrings(v); len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

// genericPocInput maps a loose JSON/YAML object to a PoC. Unknown structures are
// still kept whole in content so nothing is silently lost.
func genericPocInput(m map[string]any, fallbackName string) db.PocInput {
	// Many PoC collections wrap metadata one level down: nuclei/afrog use
	// info.*, xray uses detail.* / detail.vulnerability.*.
	info, _ := m["info"].(map[string]any)
	detail, _ := m["detail"].(map[string]any)
	vulnMeta, _ := detail["vulnerability"].(map[string]any)
	classification, _ := info["classification"].(map[string]any)

	name := pickString(m, "name", "title")
	if name == "" {
		name = pickString(info, "name", "title")
	}
	if name == "" {
		name = pickString(m, "id")
	}
	if name == "" {
		name = fallbackName
	}
	content := pickString(m, "content", "poc", "code", "payload", "exploit", "template", "body", "request", "requests")
	if content == "" {
		// Keep the raw entry as the material rather than dropping it.
		if b, err := json.MarshalIndent(m, "", "  "); err == nil {
			content = string(b)
		}
	}
	desc := pickString(m, "description", "summary", "details", "overview")
	if desc == "" {
		desc = pickString(info, "description", "details", "summary")
	}
	if desc == "" {
		desc = pickString(detail, "description", "summary")
	}
	if desc == "" {
		desc = pickString(vulnMeta, "description", "summary")
	}
	tags := pickStrings(m, "tags", "tag", "keywords")
	if len(tags) == 0 {
		tags = pickStrings(info, "tags", "tag")
	}
	vuln := pickString(m, "vuln_type", "vulntype", "vulnerability_type", "type", "category", "vulnclass", "class")
	if vuln == "" {
		vuln = inferVulnType(name, desc, strings.Join(tags, " "), content)
	}
	cves := pickStrings(m, "cve", "cves", "cve_id", "cveid", "cve-id", "cvelist")
	if len(cves) == 0 {
		cves = pickStrings(info, "cve-id", "cveid", "cve")
	}
	if len(cves) == 0 {
		cves = pickStrings(classification, "cve-id", "cveid", "cve")
	}
	if len(cves) == 0 {
		cves = extractCVEs(name, desc, content)
	}
	product := pickString(m, "product", "app", "affected", "vendor")
	if product == "" {
		product = pickString(classification, "cpe", "product", "vendor")
	}
	if strings.HasPrefix(product, "cpe:") {
		parts := strings.Split(product, ":")
		if len(parts) >= 4 {
			product = parts[3]
		}
	}
	severity := pickString(m, "severity", "risk", "level")
	if severity == "" {
		severity = pickString(info, "severity", "risk", "level")
	}
	if severity == "" {
		severity = pickString(vulnMeta, "level", "severity", "risk")
	}
	if severity == "" {
		severity = pickString(detail, "level", "severity", "risk")
	}
	refs := pickStrings(m, "refs", "references", "reference", "urls", "links", "url")
	if len(refs) == 0 {
		refs = pickStrings(info, "reference", "references", "refs", "links")
	}
	if len(refs) == 0 {
		refs = pickStrings(detail, "links", "reference", "references", "urls")
	}
	if len(refs) == 0 {
		refs = pickStrings(vulnMeta, "links", "reference", "references", "urls")
	}
	return db.PocInput{
		NKey:        pocEntryKey(name, product, vuln, content),
		Name:        name,
		CVE:         cves,
		Product:     product,
		VulnType:    vuln,
		Severity:    severity,
		Tags:        tags,
		Description: desc,
		Content:     content,
		Refs:        refs,
		Source:      pickString(m, "source", "origin"),
	}
}

func parseJSONPocs(raw []byte, fallbackName string) ([]db.PocInput, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	entries, err := pocEntriesFromAny(v)
	if err != nil {
		return nil, err
	}
	out := make([]db.PocInput, 0, len(entries))
	for _, e := range entries {
		out = append(out, genericPocInput(e, fallbackName))
	}
	return out, nil
}

// pocEntriesFromAny unwraps the shapes people actually store PoCs in.
func pocEntriesFromAny(v any) ([]map[string]any, error) {
	switch t := v.(type) {
	case []any:
		out := []map[string]any{}
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("数组里没有对象条目")
		}
		return out, nil
	case map[string]any:
		for _, k := range []string{"pocs", "items", "data", "results"} {
			if arr, ok := t[k].([]any); ok {
				out := []map[string]any{}
				for _, e := range arr {
					if m, ok := e.(map[string]any); ok {
						out = append(out, m)
					}
				}
				if len(out) > 0 {
					return out, nil
				}
			}
		}
		return []map[string]any{t}, nil
	default:
		return nil, fmt.Errorf("顶层既不是对象也不是数组")
	}
}

func parseGenericYAML(raw []byte, fallbackName string) ([]db.PocInput, error) {
	var v any
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	entries, err := pocEntriesFromAny(v)
	if err != nil {
		return nil, err
	}
	out := make([]db.PocInput, 0, len(entries))
	for _, e := range entries {
		out = append(out, genericPocInput(e, fallbackName))
	}
	return out, nil
}

// isTemplateYAML reports whether the parsed YAML looks like a runnable PoC
// template: nuclei (id + info + http/requests/…), afrog (id + info + rules),
// or xray (name + detail + rules).
func isTemplateYAML(m map[string]any) bool {
	id := strings.TrimSpace(stringify(m["id"]))
	name := strings.TrimSpace(stringify(m["name"]))
	if id == "" && name == "" {
		return false
	}
	_, hasInfo := m["info"]
	_, hasDetail := m["detail"]
	if !hasInfo && !hasDetail {
		return false
	}
	for _, k := range []string{"http", "requests", "rules", "network", "dns", "tcp", "headless", "file", "javascript", "code", "ssl", "websocket"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// parseTemplateYAML keeps the whole raw template as content (agents need the
// actual requests/rules), while lifting metadata from the format's wrapper:
//   - nuclei: info.name/severity/tags/reference + classification.cve-id
//   - afrog:  info.name/severity/tags/reference
//   - xray:   name + detail.vulnerability.level + detail.links
func parseTemplateYAML(raw []byte, m map[string]any, fallbackName string) []db.PocInput {
	info, _ := m["info"].(map[string]any)
	detail, _ := m["detail"].(map[string]any)
	vulnMeta, _ := detail["vulnerability"].(map[string]any)
	classification, _ := info["classification"].(map[string]any)

	id := strings.TrimSpace(stringify(m["id"]))
	name := pickString(info, "name", "title")
	if name == "" {
		name = pickString(m, "name", "title")
	}
	if name == "" {
		name = id
	}
	if name == "" {
		name = fallbackName
	}

	severity := pickString(info, "severity")
	if severity == "" {
		severity = pickString(vulnMeta, "level", "severity", "risk")
	}
	if severity == "" {
		severity = pickString(detail, "level", "severity", "risk")
	}
	tags := pickStrings(info, "tags", "tag")
	desc := pickString(info, "description", "details")
	if desc == "" {
		desc = pickString(detail, "description", "summary")
	}
	if desc == "" {
		desc = pickString(vulnMeta, "description", "summary")
	}
	refs := pickStrings(info, "reference", "references", "refs")
	if len(refs) == 0 {
		refs = pickStrings(detail, "links", "reference", "references", "urls")
	}
	if len(refs) == 0 {
		refs = pickStrings(vulnMeta, "links", "reference", "references", "urls")
	}
	cves := pickStrings(info, "cve-id", "cveid", "cve")
	if len(cves) == 0 {
		cves = pickStrings(classification, "cve-id", "cveid", "cve")
	}
	product := pickString(classification, "cpe", "product", "vendor")
	if strings.HasPrefix(product, "cpe:") {
		parts := strings.Split(product, ":")
		if len(parts) >= 4 {
			product = parts[3]
		}
	}
	vuln := inferVulnType(name, desc, strings.Join(tags, " "), id)
	if vuln == "" {
		vuln = inferVulnType(string(raw))
	}
	if len(cves) == 0 {
		cves = extractCVEs(name, strings.Join(tags, " "), string(raw))
	}
	if len(refs) == 0 {
		for _, c := range cves {
			refs = append(refs, "https://nvd.nist.gov/vuln/detail/"+strings.ToUpper(c))
		}
	}

	source := "nuclei"
	switch {
	case detail != nil:
		source = "xray"
	case info != nil:
		if _, hasRules := m["rules"]; hasRules {
			source = "afrog"
		}
	}
	key := pocFileKey(source, raw)
	if id != "" {
		key = source + ":" + strings.ToLower(id)
	}
	return []db.PocInput{{
		NKey:        key,
		Name:        name,
		CVE:         cves,
		Product:     product,
		VulnType:    vuln,
		Severity:    severity,
		Tags:        tags,
		Description: desc,
		Content:     string(raw),
		Refs:        refs,
		Source:      source,
	}}
}

// parseMarkdownPocs handles optional YAML frontmatter plus heading/body.
func parseMarkdownPocs(raw []byte, filename string) []db.PocInput {
	text := strings.TrimPrefix(string(raw), "\ufeff")
	meta := map[string]any{}
	body := text
	if strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "---") {
		trimmed := strings.TrimLeft(text, " \t\r\n")
		if idx := strings.Index(trimmed[3:], "\n---"); idx >= 0 {
			fm := trimmed[3 : 3+idx]
			rest := trimmed[3+idx+4:]
			if err := yaml.Unmarshal([]byte(fm), &meta); err == nil {
				body = strings.TrimLeft(rest, "\r\n")
			}
		}
	}
	name := pickString(meta, "name", "title")
	if name == "" {
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "# ") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "# "))
				break
			}
		}
	}
	if name == "" {
		name = pocTitleFromFilename(filename)
	}
	cves := pickStrings(meta, "cve", "cves", "cve_id", "cveid")
	if len(cves) == 0 {
		cves = extractCVEs(name, body)
	}
	tags := pickStrings(meta, "tags", "tag")
	vuln := pickString(meta, "vuln_type", "vulnerability_type", "type", "category")
	if vuln == "" {
		vuln = inferVulnType(name, strings.Join(tags, " "), body)
	}
	content := body
	if strings.TrimSpace(content) == "" {
		content = string(raw)
	}
	return []db.PocInput{{
		NKey:        pocFileKey("file", raw),
		Name:        name,
		CVE:         cves,
		Product:     pickString(meta, "product", "app", "affected"),
		VulnType:    vuln,
		Severity:    pickString(meta, "severity", "risk"),
		Tags:        tags,
		Description: pickString(meta, "description", "summary"),
		Content:     content,
		Refs:        pickStrings(meta, "refs", "references", "reference"),
		Source:      "markdown",
	}}
}

func parseTextPoc(raw []byte, filename string) []db.PocInput {
	text := strings.TrimPrefix(string(raw), "\ufeff")
	name := pocTitleFromFilename(filename)
	return []db.PocInput{{
		NKey:     pocFileKey("file", raw),
		Name:     name,
		CVE:      extractCVEs(name, text),
		VulnType: inferVulnType(name, text),
		Content:  text,
		Source:   "upload",
	}}
}

// ensureTextBytes normalizes PoC source bytes to UTF-8. Collections scraped from
// Chinese sources are often GBK/GB18030; decode those instead of skipping them.
func ensureTextBytes(raw []byte) ([]byte, error) {
	if utf8.Valid(raw) {
		return raw, nil
	}
	if out, err := simplifiedchinese.GB18030.NewDecoder().Bytes(raw); err == nil && utf8.Valid(out) && !strings.Contains(string(out), "\uFFFD") {
		return out, nil
	}
	// x/text's decoder replaces malformed bytes with U+FFFD instead of erroring;
	// a replacement char means this was binary/data, not GBK text.
	return nil, fmt.Errorf("不是 UTF-8/GB18030 文本")
}

// parsePocFile dispatches on content first, extension second, so a .yaml that is
// actually a JSON PoC still imports.
func parsePocFile(filename string, raw []byte) (pocFileResult, error) {
	if len(raw) == 0 {
		return pocFileResult{}, fmt.Errorf("空文件")
	}
	if len(raw) > db.MaxPocContentBytes {
		return pocFileResult{}, fmt.Errorf("文件超过 %d 字节", db.MaxPocContentBytes)
	}
	decoded, err := ensureTextBytes(raw)
	if err != nil {
		return pocFileResult{}, err
	}
	raw = decoded
	ext := strings.ToLower(filepath.Ext(filename))
	trimmed := strings.TrimLeft(string(raw), " \t\r\n\ufeff")
	fallbackName := pocTitleFromFilename(filename)

	// JSON first when it clearly is JSON.
	if ext == ".json" || (!strings.HasPrefix(trimmed, "id:") && (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) && json.Valid([]byte(trimmed))) {
		inputs, err := parseJSONPocs([]byte(trimmed), fallbackName)
		if err != nil {
			return pocFileResult{}, err
		}
		return pocFileResult{Inputs: inputs, Format: "json"}, nil
	}

	// YAML: nuclei/afrog/xray template detection, else generic.
	if ext == ".yaml" || ext == ".yml" || strings.HasPrefix(trimmed, "id:") || strings.HasPrefix(trimmed, "info:") || strings.HasPrefix(trimmed, "name:") {
		var m map[string]any
		if err := yaml.Unmarshal(raw, &m); err == nil && m != nil {
			if isTemplateYAML(m) {
				inputs := parseTemplateYAML(raw, m, fallbackName)
				format := "template"
				if len(inputs) > 0 {
					format = inputs[0].Source
				}
				return pocFileResult{Inputs: inputs, Format: format}, nil
			}
		}
		inputs, err := parseGenericYAML(raw, fallbackName)
		if err == nil {
			return pocFileResult{Inputs: inputs, Format: "yaml"}, nil
		}
		// Fall through to text for malformed YAML — keep the material.
	}

	// Markdown (frontmatter or headings).
	if ext == ".md" || ext == ".markdown" || strings.HasPrefix(trimmed, "# ") || strings.HasPrefix(trimmed, "---") {
		return pocFileResult{Inputs: parseMarkdownPocs(raw, filename), Format: "markdown"}, nil
	}

	return pocFileResult{Inputs: parseTextPoc(raw, filename), Format: "text"}, nil
}
