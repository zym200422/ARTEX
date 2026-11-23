package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestModeHardConstraints(t *testing.T) {
	desc := "前言\n\n【作战模式】SRC 漏洞挖掘（黑盒）\n\n【硬约束】\n- 禁止跨 URL 批量扫描\n- 严格单 URL 串行\n- 单 URL 限速：并发 4–9\n\n【交付物】报告\n- 不该被收录"
	got := modeHardConstraints(desc)
	want := []string{"禁止跨 URL 批量扫描", "严格单 URL 串行", "单 URL 限速：并发 4–9"}
	if len(got) != len(want) {
		t.Fatalf("got %d rules %q, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rule[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestModeHardConstraintsBulletAndAbsent(t *testing.T) {
	if got := modeHardConstraints("没有硬约束段的任务"); got != nil {
		t.Fatalf("expected nil, got %q", got)
	}
	got := modeHardConstraints("【硬约束】\n• 不得写入 webshell")
	if len(got) != 1 || got[0] != "不得写入 webshell" {
		t.Fatalf("bullet parse got %q", got)
	}
}

func TestEngagementWorkerCount(t *testing.T) {
	src := "【作战模式】SRC 漏洞挖掘（黑盒 → 白加黑）"
	if got := engagementWorkerCount(src, 4); got != 6 {
		t.Fatalf("src workers=%d, want at least 6", got)
	}
	if got := engagementWorkerCount(src, 8); got != 8 {
		t.Fatalf("src workers=%d, want configured 8", got)
	}
	if got := engagementWorkerCount(src, 0); got != 6 {
		t.Fatalf("src fallback 0 workers=%d, want 6", got)
	}
	if got := engagementWorkerCount("【作战模式】众测冲刺（黑盒 → 白加黑）", 4); got != 4 {
		t.Fatalf("crowdtest workers=%d, want 4", got)
	}
	if got := engagementWorkerCount("普通任务", 0); got != 1 {
		t.Fatalf("fallback 0 workers=%d, want 1", got)
	}
}

func TestModeSeedIntentIsFirstStageStep(t *testing.T) {
	cases := []struct {
		desc string
		want string
	}{
		{"【作战模式】SRC 漏洞挖掘", "url.txt"},
		{"【作战模式】众测冲刺", "矩阵"},
		{"【作战模式】源码审计", "依赖"},
		{"【作战模式】白加黑联动", "版本"},
		{"普通任务", ""},
	}
	for _, c := range cases {
		got := modeSeedIntent(c.desc)
		if c.want == "" {
			if got != "" {
				t.Fatalf("%q: expected empty seed, got %q", c.desc, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Fatalf("%q: seed=%q, want substring %q", c.desc, got, c.want)
		}
	}
}

func TestNormalizeURLKey(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/admin/":   "example.com/admin",
		"http://example.com:80/a?id=1": "example.com/a?id=1",
		"https://example.com:443/":     "example.com/",
		"http://example.com:8080/x/":   "example.com:8080/x",
		"not a url":                    "",
	}
	for raw, want := range cases {
		if got := normalizeURLKey(raw); got != want {
			t.Fatalf("%q: got %q, want %q", raw, got, want)
		}
	}
}

func TestIntentURLKeys(t *testing.T) {
	node := func(summary string) *db.Node {
		payload, _ := json.Marshal(map[string]any{"summary": summary})
		return &db.Node{Payload: payload}
	}
	e := new(Engine)
	got := e.intentURLKeys(nil, node("测试 https://a.com/admin 的 SQLi"))
	if len(got) != 1 || got[0] != "a.com/admin" {
		t.Fatalf("single URL keys=%q", got)
	}
	got = e.intentURLKeys(nil, node("【分诊】逐 URL 做轻量指纹并排序"))
	if len(got) != 1 || got[0] != "triage:*" {
		t.Fatalf("triage keys=%q, want triage:*", got)
	}
	if got := e.intentURLKeys(nil, node("普通的探索方向")); len(got) != 0 {
		t.Fatalf("plain intent keys=%q, want none", got)
	}
	got = e.intentURLKeys(nil, node("测试 https://a.com/1 与 https://b.com/2"))
	if len(got) != 2 || got[0] != "a.com/1" || got[1] != "b.com/2" {
		t.Fatalf("multi-URL keys=%q", got)
	}
}

func TestDetectModeFromDescription(t *testing.T) {
	cases := map[string]string{
		"【作战模式】SRC 漏洞挖掘": "src",
		"【作战模式】众测冲刺":     "crowdtest",
		"【作战模式】源码审计":     "code-audit",
		"【作战模式】白加黑联动":    "greybox",
	}
	for desc, want := range cases {
		if got := detectModeFromDescription(desc); got != want {
			t.Fatalf("%q: got %q, want %q", desc, got, want)
		}
	}
}
