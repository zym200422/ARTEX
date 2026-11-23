"use client";

import * as React from "react";

import { EraserIcon, Loader2Icon, PlayIcon, RefreshCwIcon, SendIcon, Trash2Icon, WandSparklesIcon } from "lucide-react";
import { toast } from "sonner";

import { HttpCodeBlock } from "@/components/http-code-block";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ReplayParsed, ReplayRecord } from "@/lib/types";
import { cn } from "@/lib/utils";

const FORMAT_OPTIONS = [
  { value: "auto", label: "自动识别" },
  { value: "burp", label: "Burp 原始报文" },
  { value: "curl", label: "curl 命令" },
];

const SCHEME_OPTIONS = [
  { value: "auto", label: "自动 (按报文)" },
  { value: "https", label: "HTTPS" },
  { value: "http", label: "HTTP" },
];

const POLL_MS = 5000;
// 记录列表默认只拉最新一批，避免历史记录过多拖慢首屏。
const RECORD_LIMIT = 50;

function statusTone(status: number): string {
  if (status >= 500) return "text-red-500";
  if (status >= 400) return "text-amber-500";
  if (status >= 300) return "text-blue-500";
  if (status >= 200) return "text-emerald-500";
  return "text-muted-foreground";
}

function shortURL(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.host + parsed.pathname + parsed.search;
  } catch {
    return url;
  }
}

function fmtSize(bytes: number): string {
  if (bytes <= 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function fmtTime(iso: string): string {
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return "—";
  const diff = Date.now() - ts;
  if (diff < 60_000) return "刚刚";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  return new Date(ts).toLocaleString("zh-CN", { hour12: false });
}

/** 把一条记录还原成可直接再次发送的输入文本（Burp 原始报文）。 */
// originForm 返回 Burp 原始报文里的请求目标：/path?query（origin-form）。
// 代理抓到的原始报文永远是这个形态，带 host 的是 URL 栏里的 absolute-form，
// 贴进 Burp Repeater 会被当成非法请求行——这就是「重发后请求行丢了 /」的原因。
function originForm(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.pathname || "/"}${parsed.search}`;
  } catch {
    return url.startsWith("/") ? url : `/${url}`;
  }
}

// parsedToBurp 把结构化解析结果还原成 Burp 原始报文，用于预览与复用。
function parsedToBurp(parsed: ReplayParsed): string {
  const head = `${parsed.method} ${originForm(parsed.url)} HTTP/1.1`;
  const headers = { ...parsed.headers };
  if (!Object.keys(headers).some((key) => key.toLowerCase() === "host") && parsed.host) {
    headers.Host = parsed.host;
  }
  const lines = [head, ...Object.entries(headers).map(([key, value]) => `${key}: ${value}`), ""];
  if (parsed.body) lines.push(parsed.body);
  return lines.join("\n");
}

function recordToInput(rec: ReplayRecord): string {
  const lines = [`${rec.method} ${originForm(rec.url)} HTTP/1.1`];
  const headers = { ...rec.req_headers };
  if (!Object.keys(headers).some((key) => key.toLowerCase() === "host")) {
    try {
      headers.Host = new URL(rec.url).host;
    } catch {
      // 忽略解析失败
    }
  }
  for (const [key, value] of Object.entries(headers)) lines.push(`${key}: ${value}`);
  lines.push("");
  if (rec.req_body) lines.push(rec.req_body);
  return lines.join("\n");
}

function respRaw(rec: ReplayRecord): string {
  const lines = [`HTTP/1.1 ${rec.status}${rec.status_text ? ` ${rec.status_text}` : ""}`];
  for (const [key, value] of Object.entries(rec.resp_headers ?? {})) lines.push(`${key}: ${value}`);
  if (rec.resp_body) lines.push("", rec.resp_body);
  return lines.join("\n");
}

function reqRaw(rec: ReplayRecord): string {
  const lines = [`${rec.method} ${originForm(rec.url)} HTTP/1.1`];
  for (const [key, value] of Object.entries(rec.req_headers ?? {})) lines.push(`${key}: ${value}`);
  if (rec.req_body) lines.push("", rec.req_body);
  return lines.join("\n");
}

export default function ReplayPage() {
  // 新建重放表单
  const [input, setInput] = React.useState("");
  const [format, setFormat] = React.useState("auto");
  const [scheme, setScheme] = React.useState("auto");
  const [taskId, setTaskId] = React.useState("");
  const [timeoutSec, setTimeoutSec] = React.useState("30");
  const [followRedirects, setFollowRedirects] = React.useState(false);
  const [insecureTls, setInsecureTls] = React.useState(false);
  const [parsed, setParsed] = React.useState<ReplayParsed | null>(null);
  const [parsing, setParsing] = React.useState(false);
  const [sending, setSending] = React.useState(false);

  // 记录列表
  const [records, setRecords] = React.useState<ReplayRecord[]>([]);
  const [total, setTotal] = React.useState(0);
  const [listLoading, setListLoading] = React.useState(false);
  const [filterTask, setFilterTask] = React.useState("");
  const [idFilter, setIdFilter] = React.useState("");
  // 勾选的重放编号 + 批量删除范围对话框
  const [checkedIds, setCheckedIds] = React.useState<Set<number>>(() => new Set());
  const [bulkOpen, setBulkOpen] = React.useState(false);
  const [bulkScope, setBulkScope] = React.useState<"selected" | "filtered" | "all">("selected");
  const [bulkBusy, setBulkBusy] = React.useState(false);
  const [selected, setSelected] = React.useState<ReplayRecord | null>(null);
  const [pendingDelete, setPendingDelete] = React.useState<ReplayRecord | null>(null);
  const [deleting, setDeleting] = React.useState(false);
  const [tick, setTick] = React.useState(0);
  const formRef = React.useRef<HTMLDivElement>(null);
  const detailRef = React.useRef<HTMLDivElement>(null);

  const loadRecords = React.useCallback(async () => {
    setListLoading(true);
    try {
      const result = await api.replayList(filterTask.trim(), RECORD_LIMIT, 0, idFilter.trim());
      setRecords(result.items);
      setTotal(result.total);
    } catch (error) {
      toast.error(`加载重放记录失败：${(error as Error).message}`);
    } finally {
      setListLoading(false);
    }
  }, [filterTask, idFilter]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: tick 仅用于触发重新拉取
  React.useEffect(() => {
    void loadRecords();
  }, [loadRecords, tick]);

  // 每 5 秒自动刷新（AI 生成的新记录也会自动出现）。
  React.useEffect(() => {
    const timer = window.setInterval(() => setTick((value) => value + 1), POLL_MS);
    return () => window.clearInterval(timer);
  }, []);

  // 深链：报告里的「重放 #N」直接带 ?ids=N 打开，自动过滤到该编号。
  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const ids = new URLSearchParams(window.location.search).get("ids");
    if (!ids) return;
    setIdFilter(ids);
    window.history.replaceState(null, "", window.location.pathname);
  }, []);

  async function parseOnly() {
    if (!input.trim()) {
      toast.error("先粘贴 Burp 原始报文或 curl 命令");
      return;
    }
    setParsing(true);
    try {
      const result = await api.replayParse(format === "auto" ? "" : format, input, scheme === "auto" ? "" : scheme);
      setParsed(result);
    } catch (error) {
      setParsed(null);
      toast.error(`解析失败：${(error as Error).message}`);
    } finally {
      setParsing(false);
    }
  }

  async function send() {
    if (!input.trim()) {
      toast.error("先粘贴 Burp 原始报文或 curl 命令");
      return;
    }
    const seconds = Math.min(300, Math.max(1, Number(timeoutSec) || 30));
    setSending(true);
    try {
      const record = await api.replaySend({
        taskId: taskId.trim() || undefined,
        format: format === "auto" ? "" : format,
        input,
        scheme: scheme === "auto" ? "" : scheme,
        timeoutSec: seconds,
        followRedirects,
        insecureTls,
      });
      setSelected(record);
      setParsed({
        format: record.format as ReplayParsed["format"],
        scheme: record.scheme as ReplayParsed["scheme"],
        method: record.method,
        url: record.url,
        host: "",
        headers: record.req_headers,
        body: record.req_body,
      });
      if (record.error) {
        toast.warning(`请求已发送，但存在问题：${record.error}`);
      } else {
        toast.success(`已发送：${record.method} ${record.url} → ${record.status}`);
      }
      setTick((value) => value + 1);
    } catch (error) {
      toast.error(`发送失败：${(error as Error).message}`);
    } finally {
      setSending(false);
    }
  }

  function reuse(record: ReplayRecord) {
    setSelected(record); // 点记录即展示左右分栏详情
    setInput(recordToInput(record));
    setTaskId(record.task_id ?? "");
    setScheme(record.scheme === "https" || record.scheme === "http" ? record.scheme : "auto");
    setFormat("burp");
    setParsed(null);
    detailRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // 批量删除：按选择的范围（勾选 / 当前筛选结果 / 全部）调用后端。
  async function runBulkDelete() {
    setBulkBusy(true);
    try {
      let result: { deleted: number };
      if (bulkScope === "selected") {
        if (checkedIds.size === 0) {
          toast.error("先勾选要删除的记录");
          return;
        }
        result = await api.replayBatchDelete({ ids: [...checkedIds] });
      } else if (bulkScope === "filtered") {
        // 当前筛选条件（任务 + 编号范围）作为删除范围
        result = await api.replayBatchDelete({ idsRange: idFilter.trim() });
      } else {
        result = await api.replayBatchDelete({});
      }
      toast.success(`已删除 ${result.deleted} 条重放记录`);
      setCheckedIds(new Set());
      setBulkOpen(false);
      setSelected(null);
      setTick((value) => value + 1);
    } catch (error) {
      toast.error(`批量删除失败：${(error as Error).message}`);
    } finally {
      setBulkBusy(false);
    }
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await api.replayDelete(pendingDelete.id);
      if (selected?.id === pendingDelete.id) setSelected(null);
      setPendingDelete(null);
      toast.success("重放记录已删除");
      setTick((value) => value + 1);
    } catch (error) {
      toast.error(`删除失败：${(error as Error).message}`);
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="flex flex-1 flex-col gap-4 p-4 lg:p-6">
      <header className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold tracking-tight">数据重放</h1>
        <p className="text-muted-foreground text-sm">
          粘贴 Burp 原始报文或 curl 命令，修改后发送一次。每次重放都会留存请求、响应与归属任务，可从这里反复复制、重发。
        </p>
      </header>

      <div className="grid items-start gap-4 2xl:grid-cols-[minmax(0,1fr)_minmax(18rem,22rem)]">
        {/* 左：新建重放 */}
        <div className="flex min-w-0 flex-col gap-4">
          <Card ref={formRef}>
            <CardHeader>
              <CardTitle>新建重放</CardTitle>
              <CardDescription>
                支持 Burp「Copy as raw」报文与 curl 命令；解析失败时检查请求行或 Host 头。
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="flex flex-wrap items-end gap-3">
                <div className="flex flex-col gap-1">
                  <Label htmlFor="replay-format" className="text-xs text-muted-foreground">
                    输入格式
                  </Label>
                  <NativeSelect
                    id="replay-format"
                    className="w-40"
                    value={format}
                    onChange={(event) => {
                      setFormat(event.target.value);
                      setParsed(null);
                    }}
                  >
                    {FORMAT_OPTIONS.map((option) => (
                      <NativeSelectOption key={option.value} value={option.value}>
                        {option.label}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="replay-scheme" className="text-xs text-muted-foreground">
                    协议
                  </Label>
                  <NativeSelect
                    id="replay-scheme"
                    className="w-36"
                    value={scheme}
                    onChange={(event) => {
                      setScheme(event.target.value);
                      setParsed(null);
                    }}
                  >
                    {SCHEME_OPTIONS.map((option) => (
                      <NativeSelectOption key={option.value} value={option.value}>
                        {option.label}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="replay-task" className="text-xs text-muted-foreground">
                    关联任务 ID（可选）
                  </Label>
                  <Input
                    id="replay-task"
                    value={taskId}
                    onChange={(event) => setTaskId(event.target.value)}
                    placeholder="例如 18"
                    className="w-36 font-mono"
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="replay-timeout" className="text-xs text-muted-foreground">
                    超时（秒）
                  </Label>
                  <Input
                    id="replay-timeout"
                    type="number"
                    min={1}
                    max={300}
                    value={timeoutSec}
                    onChange={(event) => setTimeoutSec(event.target.value)}
                    className="w-24"
                  />
                </div>
                <label htmlFor="replay-follow" className="flex h-8 items-center gap-2 text-sm">
                  <Checkbox
                    id="replay-follow"
                    checked={followRedirects}
                    onCheckedChange={(value) => setFollowRedirects(value === true)}
                  />
                  跟随重定向
                </label>
                <label htmlFor="replay-insecure" className="flex h-8 items-center gap-2 text-sm">
                  <Checkbox
                    id="replay-insecure"
                    checked={insecureTls}
                    onCheckedChange={(value) => setInsecureTls(value === true)}
                  />
                  忽略证书
                </label>
              </div>

              <Textarea
                value={input}
                onChange={(event) => {
                  setInput(event.target.value);
                  setParsed(null);
                }}
                placeholder={`POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\nCookie: PHPSESSID=...\n\n{"user":"admin"}\n\n—— 或者 ——\ncurl -X POST 'https://example.com/api/login' -H 'Content-Type: application/json' -d '{"user":"admin"}'`}
                className="min-h-56 font-mono text-xs leading-relaxed"
                spellCheck={false}
              />

              <div className="flex flex-wrap items-center gap-2">
                <Button type="button" size="sm" variant="outline" onClick={() => void parseOnly()} disabled={parsing}>
                  {parsing ? <Loader2Icon className="animate-spin" /> : <WandSparklesIcon className="size-3.5" />}
                  仅解析预览
                </Button>
                <Button type="button" size="sm" onClick={() => void send()} disabled={sending}>
                  {sending ? <Loader2Icon className="animate-spin" /> : <SendIcon className="size-3.5" />}
                  发送
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={!input && !parsed}
                  onClick={() => {
                    setInput("");
                    setParsed(null);
                    setSelected(null);
                  }}
                >
                  <EraserIcon className="size-3.5" />
                  清空
                </Button>
                <span className="text-muted-foreground ml-auto text-xs">发送后自动写入重放记录</span>
              </div>

              {parsed && (
                <div className="flex flex-col gap-2 rounded-lg border bg-muted/20 p-3">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <Badge variant="secondary" className="font-mono">
                      {parsed.method}
                    </Badge>
                    <span className="break-all font-mono">{parsed.url}</span>
                    <Badge variant="outline" className="ml-auto">
                      {parsed.format} · {parsed.scheme}
                    </Badge>
                  </div>
                  <div className="text-muted-foreground flex flex-wrap gap-x-3 gap-y-1 text-[11px]">
                    <span>Headers {Object.keys(parsed.headers).length}</span>
                    <span>Body {parsed.body ? fmtSize(new Blob([parsed.body]).size) : "空"}</span>
                    {parsed.content_type && <span className="font-mono">{parsed.content_type}</span>}
                  </div>
                  {/* 解析结果按 Burp 原始报文展示：可直接核对/复制进 Repeater */}
                  <div className="min-w-0">
                    <div className="text-muted-foreground mb-1 text-[11px] font-medium">
                      Burp 原始报文预览（发送前可再改）
                    </div>
                    <HttpCodeBlock raw={parsedToBurp(parsed)} />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* 选中记录详情：请求 / 响应左右分栏 */}
          {selected && (
            <div ref={detailRef}>
              <Card>
                <CardHeader>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] font-semibold tabular-nums">
                      #{selected.id}
                    </span>
                    <Badge variant="secondary" className="font-mono">
                      {selected.method}
                    </Badge>
                    <span className={cn("font-mono text-xs font-semibold tabular-nums", statusTone(selected.status))}>
                      {selected.status || "ERR"}
                    </span>
                    {selected.task_id && (
                      <Badge variant="outline" className="font-mono text-[10px]">
                        任务 #{selected.task_id}
                      </Badge>
                    )}
                    <span className="text-muted-foreground ml-auto text-xs tabular-nums">
                      {selected.duration_ms} ms · {fmtSize(selected.resp_len)}
                    </span>
                  </div>
                  <CardTitle className="break-all font-mono text-sm">{shortURL(selected.url)}</CardTitle>
                  {selected.error && <CardDescription className="text-amber-600">{selected.error}</CardDescription>}
                </CardHeader>
                <CardContent>
                  <div className="grid items-start gap-3 xl:grid-cols-2">
                    <section className="flex min-w-0 flex-col gap-1.5">
                      <div className="text-muted-foreground flex items-center justify-between px-1 text-xs font-medium">
                        <span>请求 Request</span>
                        <span className="font-mono tabular-nums">{fmtSize(new Blob([reqRaw(selected)]).size)}</span>
                      </div>
                      <div className="min-w-0 overflow-hidden">
                        <HttpCodeBlock raw={reqRaw(selected)} />
                      </div>
                    </section>
                    <section className="flex min-w-0 flex-col gap-1.5">
                      <div className="text-muted-foreground flex items-center justify-between px-1 text-xs font-medium">
                        <span>响应 Response</span>
                        <span className={cn("font-mono font-semibold tabular-nums", statusTone(selected.status))}>
                          {selected.status || "ERR"}
                          {selected.resp_body_truncated ? " · 截断" : ""}
                        </span>
                      </div>
                      <div className="min-w-0 overflow-hidden">
                        <HttpCodeBlock raw={respRaw(selected)} />
                      </div>
                    </section>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </div>

        {/* 右：重放记录 */}
        <Card className="xl:sticky xl:top-4">
          <CardHeader>
            <div className="flex items-center gap-2">
              <CardTitle>重放记录{records.length > 0 ? ` · ${total}` : ""}</CardTitle>
              <Button
                variant="ghost"
                size="icon"
                className="ml-auto size-7"
                aria-label="刷新重放记录"
                onClick={() => setTick((value) => value + 1)}
                disabled={listLoading}
              >
                <RefreshCwIcon className={cn("size-3.5", listLoading && "animate-spin")} />
              </Button>
            </div>
            <CardDescription>
              默认显示最新 {RECORD_LIMIT} 条；每 5 秒自动刷新（AI 调用 replay 生成的新记录也会自动出现）。
            </CardDescription>
            <div className="mt-2 flex gap-2">
              <Input
                value={filterTask}
                onChange={(event) => setFilterTask(event.target.value)}
                placeholder="任务 ID，例如 18"
                className="h-8 font-mono text-xs"
              />
              <Input
                value={idFilter}
                onChange={(event) => setIdFilter(event.target.value)}
                placeholder="重放编号 12 或 12-19"
                className="h-8 font-mono text-xs"
              />
            </div>
            {/* 选择与删除工具条 */}
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
              <label htmlFor="replay-select-all" className="flex items-center gap-1.5">
                <Checkbox
                  id="replay-select-all"
                  checked={records.length > 0 && records.every((record) => checkedIds.has(record.id))}
                  onCheckedChange={(value) =>
                    setCheckedIds(value === true ? new Set(records.map((record) => record.id)) : new Set())
                  }
                  aria-label="全选当前列表"
                />
                全选
              </label>
              <span className="text-muted-foreground tabular-nums">
                {checkedIds.size > 0 ? `已选 ${checkedIds.size} 条` : ""}
              </span>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="ml-auto h-7"
                disabled={records.length === 0}
                onClick={() => {
                  setBulkScope(checkedIds.size > 0 ? "selected" : idFilter.trim() ? "filtered" : "all");
                  setBulkOpen(true);
                }}
              >
                <Trash2Icon className="size-3.5" />
                删除…
              </Button>
            </div>
          </CardHeader>
          <CardContent className="px-0">
            {listLoading && records.length === 0 ? (
              <div className="text-muted-foreground flex items-center justify-center gap-2 px-4 py-8 text-xs">
                <Loader2Icon className="size-3.5 animate-spin" />
                加载中…
              </div>
            ) : records.length === 0 ? (
              <div className="text-muted-foreground px-4 py-6 text-center text-xs">暂无重放记录。</div>
            ) : (
              records.map((record, index) => (
                <React.Fragment key={record.id}>
                  {index > 0 ? <Separator /> : null}
                  <div className={cn("group flex items-start", selected?.id === record.id && "bg-accent")}>
                    <Checkbox
                      checked={checkedIds.has(record.id)}
                      onCheckedChange={(value) =>
                        setCheckedIds((prev) => {
                          const next = new Set(prev);
                          if (value === true) next.add(record.id);
                          else next.delete(record.id);
                          return next;
                        })
                      }
                      className="mt-3 ml-3 shrink-0"
                      aria-label={`选择重放记录 ${record.id}`}
                    />
                    <button
                      type="button"
                      className="min-w-0 flex-1 px-2 py-2.5 text-left transition-colors hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
                      onClick={() => reuse(record)}
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="rounded bg-muted px-1 font-mono text-[10px] font-semibold tabular-nums">
                          #{record.id}
                        </span>
                        <span className="font-mono text-[10px] font-semibold">{record.method}</span>
                        <span className={cn("font-mono text-xs font-semibold tabular-nums", statusTone(record.status))}>
                          {record.status || "ERR"}
                        </span>
                        {record.task_id ? (
                          <Badge variant="secondary" className="font-mono text-[10px]">
                            #{record.task_id}
                          </Badge>
                        ) : null}
                        <span className="text-muted-foreground ml-auto shrink-0 text-[10px] tabular-nums">
                          {fmtTime(record.created_at)}
                        </span>
                      </div>
                      <span className="mt-0.5 block break-all font-mono text-xs leading-4">{shortURL(record.url)}</span>
                      {record.error ? (
                        <span className="mt-0.5 block truncate text-[10px] text-amber-600">{record.error}</span>
                      ) : null}
                    </button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="mt-1.5 mr-1 size-7 shrink-0 text-muted-foreground opacity-0 group-hover:opacity-100"
                      aria-label={`删除重放记录 ${record.id}`}
                      onClick={() => setPendingDelete(record)}
                    >
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </div>
                </React.Fragment>
              ))
            )}
          </CardContent>
          {total > 20 && (
            <CardFooter className="justify-between gap-2">
              <span className="text-muted-foreground text-xs">
                显示最近 {records.length} / {total} 条
              </span>
            </CardFooter>
          )}
        </Card>
      </div>

      {/* 批量删除：可选范围 */}
      <Dialog open={bulkOpen} onOpenChange={(next) => !next && !bulkBusy && setBulkOpen(false)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>删除重放记录</DialogTitle>
            <DialogDescription>选择删除范围，删除后不可恢复；请求与响应原文会一并移除。</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <label className="flex cursor-pointer items-start gap-2 rounded-lg border p-3 hover:bg-muted/40">
              <input
                type="radio"
                name="replay-bulk-scope"
                className="mt-1"
                checked={bulkScope === "selected"}
                disabled={checkedIds.size === 0}
                onChange={() => setBulkScope("selected")}
              />
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium">仅删除已勾选的 {checkedIds.size} 条</span>
                <span className="text-muted-foreground block text-xs">
                  编号：{[...checkedIds].sort((a, b) => a - b).join("、") || "（未勾选）"}
                </span>
              </span>
            </label>
            <label className="flex cursor-pointer items-start gap-2 rounded-lg border p-3 hover:bg-muted/40">
              <input
                type="radio"
                name="replay-bulk-scope"
                className="mt-1"
                checked={bulkScope === "filtered"}
                disabled={!idFilter.trim() && !filterTask.trim()}
                onChange={() => setBulkScope("filtered")}
              />
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium">删除当前筛选范围</span>
                <span className="text-muted-foreground block text-xs">
                  {[
                    filterTask.trim() ? `任务 ${filterTask.trim()}` : "",
                    idFilter.trim() ? `编号 ${idFilter.trim()}` : "",
                  ]
                    .filter(Boolean)
                    .join(" · ") || "（请先在上方填写任务 ID 或编号范围）"}
                </span>
              </span>
            </label>
            <label className="flex cursor-pointer items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-3">
              <input
                type="radio"
                name="replay-bulk-scope"
                className="mt-1"
                checked={bulkScope === "all"}
                onChange={() => setBulkScope("all")}
              />
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium text-red-600 dark:text-red-400">清空全部重放记录</span>
                <span className="text-muted-foreground block text-xs">
                  共 {total} 条（含其他任务的记录），此操作不可撤销。
                </span>
              </span>
            </label>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={bulkBusy} onClick={() => setBulkOpen(false)}>
              取消
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={bulkBusy || (bulkScope === "selected" && checkedIds.size === 0)}
              onClick={() => void runBulkDelete()}
            >
              {bulkBusy ? <Loader2Icon className="animate-spin" /> : <Trash2Icon className="size-3.5" />}
              {bulkBusy ? "删除中" : "确认删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={pendingDelete !== null} onOpenChange={(next) => !next && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除这条重放记录？</AlertDialogTitle>
            <AlertDialogDescription>
              将永久删除 <span className="font-mono">{pendingDelete ? shortURL(pendingDelete.url) : ""}</span>{" "}
              的请求与响应原文，此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(event) => {
                event.preventDefault();
                void confirmDelete();
              }}
            >
              {deleting && <Loader2Icon className="animate-spin" />}
              {deleting ? "删除中" : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
