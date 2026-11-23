// Burp 原始报文规范化。
//
// 复现过程里展示/复制/重放的数据包统一成 Burp「Copy as raw」形态：
//   请求行 METHOD /path HTTP/1.1
//   头部: 值
//   <空行>
//   body
//
// 常见来源问题（历史报告、agent 摘要、手工粘贴）：
//   - 头部后缺空行，body 直接贴着最后一行头
//   - 少了 HTTP/1.1 版本号
//   - 少了 Host 头
//   - 混用 \r\n 与 \n
// 这里统一收敛成 LF + 固定空行结构，保证「看到的报文」和「贴进 Burp/重放」一致。

const REQUEST_LINE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)(?:\s+HTTP\/[\d.]+)?\s*$/i;
const STATUS_LINE = /^HTTP\/[\d.]+\s+\d{3}/i;

function normalizeNewlines(raw: string): string {
  return raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

function isHeaderLine(line: string): boolean {
  // 头部行：`Name: value`，且 name 不含空格（避免把 `submit=ping&...` 误判成头）
  const idx = line.indexOf(":");
  if (idx <= 0) return false;
  const name = line.slice(0, idx).trim();
  return /^[A-Za-z][A-Za-z0-9-]*$/.test(name);
}

/** 把一段请求文本规范成 Burp 原始报文格式。 */
export function normalizeBurpRequest(raw: string, fallbackHost?: string): string {
  const text = normalizeNewlines(raw).trim();
  if (!text) return "";
  const lines = text.split("\n");

  // 1) 请求行：补 HTTP/1.1
  const first = lines[0].trim();
  const m = REQUEST_LINE.exec(first);
  let head: string;
  let rest: string[];
  if (m) {
    head = `${m[1].toUpperCase()} ${m[2]} HTTP/1.1`;
    rest = lines.slice(1);
  } else {
    // 没有请求行：原样返回（避免破坏非 HTTP 内容，例如命令行 PoC）
    return text;
  }

  // 2) 切出头部与 body：第一个空行即分隔；没有空行时，按「头部行连续段」判定
  let headerLines: string[] = [];
  let bodyLines: string[] = [];
  const blank = rest.findIndex((line) => line.trim() === "");
  if (blank >= 0) {
    headerLines = rest.slice(0, blank);
    bodyLines = rest.slice(blank + 1);
  } else {
    let cut = rest.length;
    for (let i = 0; i < rest.length; i++) {
      if (!isHeaderLine(rest[i])) {
        cut = i;
        break;
      }
    }
    headerLines = rest.slice(0, cut);
    bodyLines = rest.slice(cut);
  }

  headerLines = headerLines.map((line) => line.trimEnd()).filter((line) => line !== "");

  // 3) 补 Host（Burp 的 Host 是头部的第一行语义，缺失时补到最后一行头之前的位置也可）
  const hasHost = headerLines.some((line) => /^host\s*:/i.test(line));
  if (!hasHost && fallbackHost) {
    headerLines.unshift(`Host: ${fallbackHost}`);
  }

  // 4) body 去掉首尾空行
  while (bodyLines.length > 0 && bodyLines[0].trim() === "") bodyLines.shift();
  while (bodyLines.length > 0 && bodyLines[bodyLines.length - 1].trim() === "") bodyLines.pop();

  const out = [head, ...headerLines, ""];
  if (bodyLines.length > 0) out.push(...bodyLines);
  return out.join("\n");
}

/** 把一段响应文本规范成 Burp 原始报文格式（状态行 + 头部 + 空行 + body）。 */
export function normalizeBurpResponse(raw: string): string {
  const text = normalizeNewlines(raw).trim();
  if (!text) return "";
  const lines = text.split("\n");
  const first = lines[0].trim();
  if (!STATUS_LINE.test(first)) {
    // 不是状态行：当作纯 body 展示，前面补一个空状态行更易读也可以，但这里保持原样。
    return text;
  }

  const rest = lines.slice(1);
  let headerLines: string[] = [];
  let bodyLines: string[] = [];
  const blank = rest.findIndex((line) => line.trim() === "");
  if (blank >= 0) {
    headerLines = rest.slice(0, blank);
    bodyLines = rest.slice(blank + 1);
  } else {
    let cut = rest.length;
    for (let i = 0; i < rest.length; i++) {
      if (!isHeaderLine(rest[i])) {
        cut = i;
        break;
      }
    }
    headerLines = rest.slice(0, cut);
    bodyLines = rest.slice(cut);
  }

  headerLines = headerLines.map((line) => line.trimEnd()).filter((line) => line !== "");
  while (bodyLines.length > 0 && bodyLines[0].trim() === "") bodyLines.shift();
  while (bodyLines.length > 0 && bodyLines[bodyLines.length - 1].trim() === "") bodyLines.pop();

  const out = [first, ...headerLines, ""];
  if (bodyLines.length > 0) out.push(...bodyLines);
  return out.join("\n");
}

/** 判断一段文本是否已经是标准 Burp 形态（供 UI 提示用）。 */
export function isBurpReady(raw: string): boolean {
  const text = normalizeNewlines(raw);
  const lines = text.split("\n");
  if (!REQUEST_LINE.test(lines[0]?.trim() ?? "")) return false;
  if (!/HTTP\/[\d.]+\s*$/i.test(lines[0]?.trim() ?? "")) return false;
  return lines.some((line) => line.trim() === "");
}
