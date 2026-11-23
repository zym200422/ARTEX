package db

import (
	"strings"
	"testing"
)

func TestPocQueryTokens(t *testing.T) {
	got := pocQueryTokens("  apache   RCE apache sql注入 ")
	want := []string{"apache", "RCE", "sql注入"}
	if len(got) != len(want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got=%v want=%v", got, want)
		}
	}
	long := pocQueryTokens("a b c d e f g h i j")
	if len(long) != 8 {
		t.Fatalf("token cap=%d want 8", len(long))
	}
}

func TestLikeContainsEscapesWildcards(t *testing.T) {
	got := likeContains(`50%_off\path`)
	if !strings.HasPrefix(got, "%") || !strings.HasSuffix(got, "%") {
		t.Fatalf("pattern=%q", got)
	}
	if strings.Contains(strings.Trim(got, "%"), `\%`) == false {
		t.Fatalf("percent not escaped: %q", got)
	}
	if !strings.Contains(got, `\_`) {
		t.Fatalf("underscore not escaped: %q", got)
	}
	if !strings.Contains(got, `\`) {
		t.Fatalf("backslash not escaped: %q", got)
	}
}

func TestNormalizePocInput(t *testing.T) {
	enabled := false
	in, err := normalizePocInput(PocInput{
		Name:     "  Apache   Log4j RCE ",
		CVE:      []string{" cve-2021-44228 ", "CVE-2021-44228", ""},
		Tags:     []string{"Log4j", "RCE", "log4j"},
		VulnType: " RCE ",
		Severity: " Critical ",
		Content:  "line1\r\nline2",
		Enabled:  &enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if in.Name != "Apache Log4j RCE" {
		t.Errorf("name=%q", in.Name)
	}
	if len(in.CVE) != 1 || in.CVE[0] != "cve-2021-44228" {
		t.Errorf("cve=%v (case-insensitive dedupe expected)", in.CVE)
	}
	if len(in.Tags) != 2 || in.Tags[0] != "log4j" || in.Tags[1] != "rce" {
		t.Errorf("tags=%v", in.Tags)
	}
	if in.VulnType != "rce" || in.Severity != "critical" {
		t.Errorf("vuln=%q severity=%q", in.VulnType, in.Severity)
	}
	if in.Content != "line1\nline2" {
		t.Errorf("content=%q (CRLF should normalize)", in.Content)
	}
	if in.Source != "manual" {
		t.Errorf("source=%q", in.Source)
	}
	if in.NKey == "" || !strings.HasPrefix(in.NKey, "manual:") {
		t.Errorf("nkey=%q", in.NKey)
	}
	if pocEnabled(in) {
		t.Error("enabled=false not honored")
	}

	if _, err := normalizePocInput(PocInput{Name: "  "}); err == nil {
		t.Error("blank name must fail")
	}
}

func TestParsePGTextArray(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"{}", []string{}},
		{`{a,b}`, []string{"a", "b"}},
		{`{"a,b",c}`, []string{"a,b", "c"}},
		{`{"he said \"hi\"",x}`, []string{`he said "hi"`, "x"}},
		{`{CVE-2021-44228}`, []string{"CVE-2021-44228"}},
	}
	for _, c := range cases {
		got := parsePGTextArray(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("%s: got=%v want=%v", c.in, got, c.want)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("%s: got=%v want=%v", c.in, got, c.want)
			}
		}
	}
	// PG escapes a literal backslash as two backslashes inside the array
	// literal. Build that input from bytes to keep the source free of escaping
	// layers: both the input and the expected value contain one backslash.
	bs := string([]byte{92})
	if got := parsePGTextArray(`{"back` + bs + bs + `slash"}`); len(got) != 1 || got[0] != `back`+bs+`slash` {
		t.Fatalf("escaped backslash: got=%v", got)
	}
}

func TestNormalizePocInputStripsNUL(t *testing.T) {
	in, err := normalizePocInput(PocInput{
		Name: "nul\x00name", Description: "desc\x00ription", Content: "GET /\x00 HTTP/1.1",
		Tags: []string{"a\x00b"}, Refs: []string{"https://x\x00y"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(in.Name, 0) || strings.ContainsRune(in.Description, 0) || strings.ContainsRune(in.Content, 0) {
		t.Fatalf("NUL survived: %+v", in)
	}
	if in.Tags[0] != "ab" || in.Refs[0] != "https://xy" {
		t.Fatalf("list NUL survived: tags=%v refs=%v", in.Tags, in.Refs)
	}
}
