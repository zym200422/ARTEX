package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePocFileNuclei(t *testing.T) {
	raw := `id: CVE-2021-44228
info:
  name: Apache Log4j2 JNDI RCE
  severity: critical
  description: Log4j2 JNDI lookup remote code execution
  tags: log4j,rce,java
  classification:
    cve-id: CVE-2021-44228
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
`
	res, err := parsePocFile("CVE-2021-44228.yaml", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "nuclei" {
		t.Fatalf("format=%q want nuclei", res.Format)
	}
	if len(res.Inputs) != 1 {
		t.Fatalf("inputs=%d want 1", len(res.Inputs))
	}
	in := res.Inputs[0]
	if in.Name != "Apache Log4j2 JNDI RCE" {
		t.Errorf("name=%q", in.Name)
	}
	if len(in.CVE) != 1 || in.CVE[0] != "CVE-2021-44228" {
		t.Errorf("cve=%v", in.CVE)
	}
	if in.Severity != "critical" || in.VulnType != "rce" || in.Source != "nuclei" {
		t.Errorf("severity=%q vuln=%q source=%q", in.Severity, in.VulnType, in.Source)
	}
	if !strings.Contains(in.Content, "GET / HTTP/1.1") {
		t.Errorf("content lost the template body")
	}
	if len(in.Refs) == 0 {
		t.Errorf("expected references")
	}
	if !strings.HasPrefix(in.NKey, "nuclei:cve-2021-44228") {
		t.Errorf("nkey=%q", in.NKey)
	}
}

func TestParsePocFileMarkdownFrontmatter(t *testing.T) {
	raw := `---
name: ThinkPHP 5.x RCE
cve: CVE-2018-20062
severity: critical
tags: [thinkphp, rce]
---
# ThinkPHP 5.x 远程命令执行

POST /index.php?s=index/\think\app/invokefunction
`
	res, err := parsePocFile("thinkphp.md", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "markdown" {
		t.Fatalf("format=%q", res.Format)
	}
	in := res.Inputs[0]
	if in.Name != "ThinkPHP 5.x RCE" || in.Severity != "critical" {
		t.Errorf("name=%q severity=%q", in.Name, in.Severity)
	}
	if len(in.CVE) != 1 || in.CVE[0] != "CVE-2018-20062" {
		t.Errorf("cve=%v", in.CVE)
	}
	if !strings.Contains(in.Content, "invokefunction") {
		t.Errorf("content missing body")
	}
	if in.NKey == "" {
		t.Error("nkey empty")
	}
}

func TestParsePocFileJSONArray(t *testing.T) {
	raw := `[{"name":"Demo SQLi","cve":"CVE-2022-0001","product":"demo","vuln_type":"sqli","content":"' OR 1=1--","tags":["sqli"]}]`
	res, err := parsePocFile("pocs.json", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "json" || len(res.Inputs) != 1 {
		t.Fatalf("format=%q inputs=%d", res.Format, len(res.Inputs))
	}
	in := res.Inputs[0]
	if in.Name != "Demo SQLi" || in.VulnType != "sqli" || in.Product != "demo" {
		t.Errorf("unexpected input: %+v", in)
	}
	if len(in.CVE) != 1 || in.CVE[0] != "CVE-2022-0001" {
		t.Errorf("cve=%v", in.CVE)
	}
}

func TestParsePocFileTextInfersCVEAndType(t *testing.T) {
	raw := "command injection PoC for CVE-2024-1234\ncurl http://target/exec?cmd=id"
	res, err := parsePocFile("cve_2024_1234.txt", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "text" || len(res.Inputs) != 1 {
		t.Fatalf("format=%q inputs=%d", res.Format, len(res.Inputs))
	}
	in := res.Inputs[0]
	if len(in.CVE) != 1 || in.CVE[0] != "CVE-2024-1234" {
		t.Errorf("cve=%v", in.CVE)
	}
	if in.VulnType != "rce" {
		t.Errorf("vuln_type=%q want rce (command injection)", in.VulnType)
	}
	if !strings.Contains(in.Content, "curl") {
		t.Errorf("content missing")
	}
}

func TestParsePocFileRejectsEmptyAndBinary(t *testing.T) {
	if _, err := parsePocFile("empty.txt", nil); err == nil {
		t.Error("empty file must fail")
	}
	if _, err := parsePocFile("bin.dat", []byte{0xff, 0xfe, 0xfd}); err == nil {
		t.Error("non-UTF8 file must fail")
	}
}

func TestFlexStringsAcceptsScalarAndArray(t *testing.T) {
	var f flexStrings
	if err := json.Unmarshal([]byte(`"CVE-2021-44228, CVE-2021-45046"`), &f); err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 || f[1] != "CVE-2021-45046" {
		t.Fatalf("scalar form: %v", f)
	}
	if err := json.Unmarshal([]byte(`["log4j","rce"]`), &f); err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 || f[0] != "log4j" {
		t.Fatalf("array form: %v", f)
	}
	if err := json.Unmarshal([]byte(`null`), &f); err != nil || len(f) != 0 {
		t.Fatalf("null form: %v err=%v", f, err)
	}
}

func TestParsePocFileAfrog(t *testing.T) {
	raw := `id: CNVD-2017-03561

info:
  name: 泛微 E-Mobile 表达式注入
  author: tester
  severity: high
  description: login.do 页面存在表达式注入漏洞
  reference:
    - https://www.cnvd.org.cn/flaw/show/CNVD-2017-03561
  tags: emobile,ssti,cnvd
rules:
  r0:
    request:
      method: GET
      path: "/login.do?message=1"
    expression: response.status == 200
expression: r0()
`
	res, err := parsePocFile("CNVD-2017-03561.yaml", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "afrog" {
		t.Fatalf("format=%q want afrog", res.Format)
	}
	in := res.Inputs[0]
	if in.Name != "泛微 E-Mobile 表达式注入" || in.Severity != "high" || in.Source != "afrog" {
		t.Errorf("name=%q severity=%q source=%q", in.Name, in.Severity, in.Source)
	}
	if !strings.HasPrefix(in.NKey, "afrog:cnvd-2017-03561") {
		t.Errorf("nkey=%q", in.NKey)
	}
	if !strings.Contains(in.Content, "rules:") || len(in.Refs) == 0 {
		t.Errorf("raw rules or refs lost")
	}
}

func TestParsePocFileXray(t *testing.T) {
	raw := `name: poc-yaml-hadoop-yarn-rpc-rce
detail:
    author: tester
    links:
        - https://example.com/yarn
    vulnerability:
        id: CT-416480
        level: critical
        description: hadoop-yarn-rpc-rce
transport: http
rules:
    r0:
        request:
            method: POST
            path: /ws/v1/cluster/apps/new-application
        expression: response.status == 200
expression: r0()
`
	res, err := parsePocFile("apache-hadoop-yarn-unauth-rce.yml", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "xray" {
		t.Fatalf("format=%q want xray", res.Format)
	}
	in := res.Inputs[0]
	if in.Name != "poc-yaml-hadoop-yarn-rpc-rce" || in.Severity != "critical" || in.Source != "xray" {
		t.Errorf("name=%q severity=%q source=%q", in.Name, in.Severity, in.Source)
	}
	if len(in.Refs) != 1 || in.Refs[0] != "https://example.com/yarn" {
		t.Errorf("refs=%v", in.Refs)
	}
	if !strings.HasPrefix(in.NKey, "xray:") || !strings.Contains(in.Content, "transport: http") {
		t.Errorf("nkey=%q content lost", in.NKey)
	}
}

func TestEnsureTextBytesGB18030(t *testing.T) {
	// "中文" encoded as GBK/GB18030 (Chinese PoC collections are commonly GBK).
	raw := []byte{0xD6, 0xD0, 0xCE, 0xC4}
	out, err := ensureTextBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "中文" {
		t.Fatalf("decoded=%q", out)
	}
	if _, err := ensureTextBytes([]byte{0xff, 0xfe, 0xfd, 0x00, 0x81}); err == nil {
		t.Fatal("binary bytes must not decode")
	}
}
