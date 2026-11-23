// 已知开源靶场 / 开源应用指纹 → 源码获取指引。
//
// 解决的问题：任务里常出现「黑盒打一个知名靶场/开源系统」的情况。这类目标
// 的源码是公开的，本可以立刻转白加黑（定位到行、构造精确 payload），但 agent
// 往往只在黑盒里盲猜参数，命中率低、报告也写不出根因。
//
// 本文件维护「指纹 → 源码位置」的映射，供 SRC / 众测等模式在侦察阶段直接引用：
// 一旦识别出目标属于下列项目，就应当获取源码，并按白加黑推进。

export interface SourceHint {
  /** 指纹 key：出现在页面标题/路径/静态资源/响应头里即可判定。 */
  fingerprints: string[];
  name: string;
  /** 开源仓库地址（公开）。 */
  repo: string;
  /** 源码里值得优先定位的目录/文件。 */
  focus: string[];
  /** 转到哪个作战模式。 */
  mode: "code-audit" | "greybox";
}

export const SOURCE_HINTS: SourceHint[] = [
  {
    fingerprints: ["pikachu", "Get the pikachu", "pkxss", "/vul/sqli/", "/vul/xss/"],
    name: "Pikachu 漏洞练习平台",
    repo: "https://github.com/zhuifengshaonianhanlu/pikachu",
    focus: [
      "vul/ 目录按漏洞类型分文件夹，每个 .php 就是一个独立靶点",
      "vul/sqli/：字符型/数字型/搜索型/盲注/宽字节，源码里可直接看到拼接方式",
      "vul/xss/：反射/存储/DOM/盲打，注意 xssblind 有后台查看页",
      "vul/rce/：rce_ping.php 的 shell_exec 拼接、rce_eval.php 的 eval",
      "vul/ssrf/：ssrf_curl.php（curl_exec）、ssrf_fgc.php（file_get_contents）",
      "vul/fileinclude/、vul/unsafedownload/、vul/unsafeupload/：文件类漏洞",
      "vul/sqli/sqli_id.php 等页面会直接 echo 执行的 SQL —— 黑盒就能确认",
      "inc/config.inc.php：数据库连接配置（常配合任意文件读取泄露）",
    ],
    mode: "greybox",
  },
  {
    fingerprints: ["dvwa", "Damn Vulnerable Web Application", "DVWA"],
    name: "DVWA",
    repo: "https://github.com/digininja/DVWA",
    focus: [
      "vulnerabilities/ 下每个模块分 low/medium/high/impossible 四档实现",
      "对比 security level 的实现差异可直接看出过滤绕过点",
      "vulnerabilities/sqli、xss_*、exec、fi、upload、csrf、brute",
    ],
    mode: "greybox",
  },
  {
    fingerprints: ["bWAPP", "bWAPP - Herd of Bugs"],
    name: "bWAPP",
    repo: "https://github.com/raesen/bWAPP",
    focus: ["漏洞按 A1-A10 / 主题分文件，源码含漏洞级别注释", "admin/settings.php 配置项"],
    mode: "greybox",
  },
  {
    fingerprints: ["WebGoat", "OWASP WebGoat"],
    name: "OWASP WebGoat",
    repo: "https://github.com/WebGoat/WebGoat",
    focus: ["Java 实现，lessons 按 OWASP Top10 分包", "关注 Controller → Service 的鉴权与参数处理"],
    mode: "greybox",
  },
  {
    fingerprints: ["juice-shop", "OWASP Juice Shop", "juice shop"],
    name: "OWASP Juice Shop",
    repo: "https://github.com/juice-shop/juice-shop",
    focus: ["Node.js/Express，routes/ 与 data/ 目录", "挑战清单在 data/static/challenges.yml，可直接对照"],
    mode: "greybox",
  },
  {
    fingerprints: ["vulhub", "/vulhub/"],
    name: "Vulhub 靶场集合",
    repo: "https://github.com/vulhub/vulhub",
    focus: ["每个 CVE 一个目录，含 docker-compose 与 README 复现步骤", "按组件名检索对应 CVE 目录"],
    mode: "greybox",
  },
];

/** 按响应/URL 特征匹配已知靶场；返回首个命中。 */
export function detectSourceHint(signals: string[]): SourceHint | null {
  const haystack = signals.join(" ").toLowerCase();
  if (!haystack.trim()) return null;
  for (const hint of SOURCE_HINTS) {
    if (hint.fingerprints.some((fp) => haystack.includes(fp.toLowerCase()))) {
      return hint;
    }
  }
  return null;
}

/** 生成给 agent 的源码获取指引（写进任务简报/演进规则时使用）。 */
export function sourceHintBrief(hint: SourceHint): string {
  return [
    `识别到目标为开源项目「${hint.name}」，源码公开：${hint.repo}`,
    "应立刻获取源码转白加黑（不必继续在黑盒里盲猜）：",
    ...hint.focus.map((item) => `- ${item}`),
    `获取源码的常见途径：GitHub 克隆、目标泄露的 .git / 备份包、容器镜像内源码。`,
  ].join("\n");
}
