package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// search_poc 是「本地 PoC 库优先」的入口：agent 在动手构造/验证利用前先查本库，
// 命中就直接改造返回的原文；只有 found=false 时才被引导去调 web_search。
//
// 这里刻意把「本地优先、联网兜底」写进工具描述和零命中返回：这两个位置模型每次
// 都会读到，不依赖用户在 DB 里怎么改提示词。
const pocToolName = "search_poc"
const pocAddToolName = "add_poc"

func (s *Server) pocTools() []actool.CoreTool {
	return []actool.CoreTool{s.searchPocTool(), s.addPocTool()}
}

func (s *Server) searchPocTool() actool.CoreTool {
	return roTool(pocToolName, pocToolDescription, objSchema(map[string]any{
		"query":     strParam("自由关键词：产品/组件/版本、CVE、漏洞类型、指纹、中文描述均可。多个词用空格分隔（AND 语义）。"),
		"cve":       strParam("按 CVE 编号过滤，如 CVE-2021-44228（大小写不敏感、支持部分匹配）。"),
		"product":   strParam("按受影响产品过滤，如 apache、weblogic、thinkphp。"),
		"vuln_type": strParam("按漏洞类型过滤，如 rce / sqli / xss / ssrf / upload / deserialization / auth-bypass。"),
		"severity":  strParam("按严重等级过滤：info / low / medium / high / critical。"),
		"tag":       strParam("按标签过滤，如 log4j、oa、中间件。"),
		"id":        map[string]any{"type": "integer", "description": "直接按 PoC id 取一条（返回完整原文，忽略其它检索条件）。"},
		"limit":     map[string]any{"type": "integer", "description": "最多返回条数（1-20，默认 5）。", "minimum": 1, "maximum": 20},
		"full":      map[string]any{"type": "boolean", "description": "true=每条返回尽量完整的 content（默认每条截断到 4000 字符；截断时用 id 再取全文）。"},
	}), s.runSearchPoc)
}

const pocToolDescription = `检索【本地 PoC 知识库】——这是你构造/验证漏洞利用时的第一站，优先级高于联网搜索。

工作流（必须按顺序）：
1. 先调用 search_poc：用目标的产品/组件/版本/指纹、CVE 编号、漏洞类型或标签检索本库。
2. 命中 → 基于返回的 PoC 原文（请求报文/脚本/命令/利用链）改造成针对当前目标可执行的验证，并实际触发验证。
3. **只有本工具返回 found=false（本地无命中）时，才调用 web_search 到互联网检索**；不要跳过本地库直接联网，也不要因为一次没搜到换个措辞反复空搜。
4. 本地 PoC 只是参考素材：版本、路径、参数、依赖可能不同；必须按实际响应调整并独立验证，不能因为"库里有"就当成已确认漏洞。

提示：query 支持中英文和空格 AND；已知 CVE 直接传 cve；只按类型找就传 vuln_type。返回的 content 可能被截断，需要全文时用 id 再取一次。`

func (s *Server) runSearchPoc(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	pg := s.m.PG()
	if pg == nil {
		return actool.Errorf("PoC 知识库不可用：PostgreSQL 未连接"), nil
	}
	var args struct {
		Query    string `json:"query"`
		CVE      string `json:"cve"`
		Product  string `json:"product"`
		VulnType string `json:"vuln_type"`
		Severity string `json:"severity"`
		Tag      string `json:"tag"`
		ID       int64  `json:"id"`
		Limit    int    `json:"limit"`
		Full     bool   `json:"full"`
	}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &args); err != nil {
			return actool.Errorf("参数解析失败: " + err.Error()), nil
		}
	}

	// Direct id lookup always returns the full text — no truncation, no guessing.
	if args.ID > 0 {
		p, err := pg.GetPOC(args.ID)
		if err != nil {
			return actool.Errorf("读取 PoC 失败: " + err.Error()), nil
		}
		if p == nil {
			return jsonResult(map[string]any{
				"source": "local_poc_db", "found": false, "id": args.ID,
				"hint": "本地 PoC 库里没有这个 id；可改用 query/cve/product/vuln_type 检索，仍无命中再调用 web_search 到互联网检索。",
			})
		}
		if !p.Enabled {
			return jsonResult(map[string]any{
				"source": "local_poc_db", "found": false, "id": args.ID, "name": p.Name,
				"hint": "该 PoC 已被停用；如需使用请先在 PoC 库页面启用它，或改用其它条目/联网检索。",
			})
		}
		// Even "full" is capped: a multi-MB file would blow the model's context.
		// 60k runes is enough for any realistic template/script.
		full := p.Content
		truncated := false
		if len([]rune(full)) > 60000 {
			full = truncatePocContent(full, 60000)
			truncated = true
		}
		return jsonResult(map[string]any{
			"source": "local_poc_db", "found": true, "count": 1,
			"items": []map[string]any{pocToolItem(p, full, truncated)},
		})
	}

	if strings.TrimSpace(args.Query) == "" && strings.TrimSpace(args.CVE) == "" &&
		strings.TrimSpace(args.Product) == "" && strings.TrimSpace(args.VulnType) == "" &&
		strings.TrimSpace(args.Severity) == "" && strings.TrimSpace(args.Tag) == "" {
		return actool.Errorf("至少提供 query / cve / product / vuln_type / severity / tag / id 之一"), nil
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 5
	}
	if limit > 20 {
		limit = 20
	}
	enabled := true
	f := db.PocFilter{
		Query: args.Query, CVE: args.CVE, Product: args.Product, VulnType: args.VulnType,
		Severity: args.Severity, Tag: args.Tag, Enabled: &enabled,
		Limit: limit, WithContent: true,
	}
	pocs, total, err := pg.SearchPOCs(f)
	if err != nil {
		return actool.Errorf("检索 PoC 库失败: " + err.Error()), nil
	}

	queryForWeb := strings.Join(strings.Fields(strings.Join([]string{args.Query, args.CVE, args.Product, args.VulnType, args.Tag}, " ")), " ")
	if len(pocs) == 0 {
		hint := "本地 PoC 库无命中。下一步请调用 web_search 到互联网检索"
		if queryForWeb != "" {
			hint += "（建议查询词：" + queryForWeb + "）"
		}
		hint += "；本地库没有条目时不要在这里空转，直接联网。"
		return jsonResult(map[string]any{
			"source": "local_poc_db", "found": false, "count": 0, "total": 0,
			"query": queryForWeb, "hint": hint,
		})
	}

	items := make([]map[string]any, 0, len(pocs))
	totalChars := 0
	for _, p := range pocs {
		content := p.Content
		if !args.Full && len(content) > 4000 {
			content = truncatePocContent(content, 4000)
		}
		if totalChars+len(content) > 60000 {
			content = truncatePocContent(content, max(0, 60000-totalChars))
			if content == "" {
				break
			}
		}
		totalChars += len(content)
		items = append(items, pocToolItem(p, content, content != p.Content))
	}
	return jsonResult(map[string]any{
		"source": "local_poc_db", "found": true, "count": len(items), "total": total,
		"query": queryForWeb,
		"note":  "本地命中。基于 content 改造并对当前目标实测；需要某条完整原文时用 search_poc(id=<id>)。",
		"items": items,
	})
}

func pocToolItem(p *db.Poc, content string, truncated bool) map[string]any {
	item := map[string]any{
		"id":          p.ID,
		"name":        p.Name,
		"cve":         p.CVE,
		"product":     p.Product,
		"vuln_type":   p.VulnType,
		"severity":    p.Severity,
		"tags":        p.Tags,
		"description": p.Description,
		"refs":        p.Refs,
		"source":      p.Source,
		"content":     content,
	}
	if truncated {
		item["content_truncated"] = true
		item["full_hint"] = fmt.Sprintf("内容已截断；需要全文请调用 search_poc(id=%d)。", p.ID)
	}
	return item
}

// truncatePocContent clips by runes so multi-byte Chinese/examples never split
// into invalid UTF-8 (which would corrupt the JSON tool result).
func truncatePocContent(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "\n…（已截断）"
}

// add_poc 是对话式入库入口：用户在「主 agent / Auto / 渗透」的对话里把一段
// PoC 原文交给 agent，agent 调它落库；之后渗透时 search_poc 会优先命中。
// 同一 name+content 重复保存按手动身份幂等更新，不会产生重复条目。
const pocAddToolDescription = `把一份 PoC 存入【本地 PoC 知识库】，之后渗透时 search_poc 会优先命中本库。

何时调用：
- 用户明确说"把这段 PoC / 利用代码 / 请求报文 / 复现步骤加入 PoC 库 / 存起来"；
- 对话中产出/整理出一份值得复用的完整 PoC（含请求、脚本、命令或模板），用户同意保存时。
- 用户要求"以后遇到 X 先查这个"时，也应把这份素材存进来。

参数要求：
- name、content 必填。content 是以后 agent 直接拿到并改造的原文，务必完整，不要只写摘要。
- cve/tags/refs 可传数组（也接受逗号分隔字符串）；product/vuln_type/severity 用于检索过滤。
- 同一 name + content 重复保存会更新原条目（幂等）。

不要存：只有猜测、没有原文的"疑似漏洞"；与 PoC 无关的对话内容；未经用户同意的目标敏感凭据明文。`

func (s *Server) addPocTool() actool.CoreTool {
	return wrTool(pocAddToolName, pocAddToolDescription, objSchema(map[string]any{
		"name":        strParam("PoC 名称（必填），如 Apache Log4j2 JNDI RCE。"),
		"content":     strParam("PoC 原文（必填）：请求报文、curl 命令、脚本、nuclei 模板或可照做的复现步骤。"),
		"cve":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "关联 CVE 编号，如 [\"CVE-2021-44228\"]。"},
		"product":     strParam("受影响产品 / 组件，如 apache、log4j、weblogic。"),
		"vuln_type":   strParam("漏洞类型：rce / sqli / xss / ssrf / upload / deserialization / auth-bypass 等。"),
		"severity":    strParam("严重等级：info / low / medium / high / critical。"),
		"tags":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "检索标签，如 [\"log4j\",\"rce\",\"java\"]。"},
		"description": strParam("适用条件 / 指纹 / 影响版本 / 验证要点等说明。"),
		"refs":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "参考链接。"},
		"enabled":     map[string]any{"type": "boolean", "description": "是否启用（默认 true；停用的条目 search_poc 检索不到）。"},
		"source":      strParam("来源标记，默认 conversation；可填 manual / nuclei / 外部仓库名。"),
	}, "name", "content"), s.runAddPoc)
}

func (s *Server) runAddPoc(_ context.Context, in json.RawMessage) (actool.Result, error) {
	pg := s.m.PG()
	if pg == nil {
		return actool.Errorf("PoC 知识库不可用：PostgreSQL 未连接"), nil
	}
	var args struct {
		Name        string      `json:"name"`
		Content     string      `json:"content"`
		CVE         flexStrings `json:"cve"`
		Product     string      `json:"product"`
		VulnType    string      `json:"vuln_type"`
		Severity    string      `json:"severity"`
		Tags        flexStrings `json:"tags"`
		Description string      `json:"description"`
		Refs        flexStrings `json:"refs"`
		Enabled     *bool       `json:"enabled"`
		Source      string      `json:"source"`
	}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &args); err != nil {
			return actool.Errorf("参数解析失败: " + err.Error()), nil
		}
	}
	name := strings.TrimSpace(args.Name)
	content := args.Content
	if name == "" {
		return actool.Errorf("name 必填：给这份 PoC 一个可检索的名称"), nil
	}
	if strings.TrimSpace(content) == "" {
		return actool.Errorf("content 必填：把 PoC 原文（请求报文/脚本/命令/模板/复现步骤）放进 content，不要只写摘要"), nil
	}
	source := strings.TrimSpace(args.Source)
	if source == "" {
		source = "conversation"
	}
	id, inserted, err := pg.UpsertPOC(db.PocInput{
		Name:        name,
		CVE:         []string(args.CVE),
		Product:     args.Product,
		VulnType:    args.VulnType,
		Severity:    args.Severity,
		Tags:        []string(args.Tags),
		Description: args.Description,
		Content:     content,
		Refs:        []string(args.Refs),
		Source:      source,
		Enabled:     args.Enabled,
	})
	if err != nil {
		return actool.Errorf("存入 PoC 库失败: " + err.Error()), nil
	}
	action := "已新增"
	if !inserted {
		action = "已更新同名同内容的已有条目"
	}
	return jsonResult(map[string]any{
		"ok":       true,
		"id":       id,
		"inserted": inserted,
		"updated":  !inserted,
		"name":     name,
		"source":   source,
		"action":   action,
		"hint":     "已存入本地 PoC 库，之后渗透时 search_poc 可命中。需要修改/停用/删除可在「PoC 库」页面按该 id 操作。",
	})
}
