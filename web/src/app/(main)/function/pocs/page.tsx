"use client";

import * as React from "react";

import {
  BookOpenIcon,
  CopyIcon,
  FolderInputIcon,
  Loader2Icon,
  PencilIcon,
  PlusIcon,
  SearchIcon,
  Trash2Icon,
  UploadIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Poc, PocImportOutcome, PocInput, PocStats } from "@/lib/types";
import { cn } from "@/lib/utils";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const PAGE_SIZE = 20;

function fmtTime(ts: string): string {
  if (!ts) return "-";
  return new Date(ts).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function severityVariant(sev: string): "default" | "secondary" | "destructive" | "outline" {
  switch (sev.toLowerCase()) {
    case "critical":
    case "high":
      return "destructive";
    case "medium":
      return "default";
    case "low":
      return "secondary";
    default:
      return "outline";
  }
}

function splitCVEs(s: string): string[] {
  return s
    .split(/[\s,;]+/)
    .map((x) => x.trim().toUpperCase())
    .filter(Boolean);
}

function splitList(s: string, refs = false): string[] {
  return s
    .split(refs ? /[\n,]+/ : /[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

const EMPTY_FORM = {
  name: "",
  cve: "",
  product: "",
  vuln_type: "",
  severity: "",
  tags: "",
  description: "",
  content: "",
  refs: "",
  enabled: true,
};

type FormState = typeof EMPTY_FORM;

function fromPoc(p: Poc): FormState {
  return {
    name: p.name,
    cve: (p.cve ?? []).join(", "),
    product: p.product,
    vuln_type: p.vuln_type,
    severity: p.severity,
    tags: (p.tags ?? []).join(", "),
    description: p.description,
    content: p.content,
    refs: (p.refs ?? []).join("\n"),
    enabled: p.enabled,
  };
}

// PocFormDialog is used for both create and edit. Editing keeps the row's
// identity on the backend; the content textarea is the raw material the agent
// receives, so it is intentionally full-width and monospace.
function PocFormDialog({
  open,
  onOpenChange,
  initial,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initial: Poc | null;
  onSaved: () => void;
}) {
  const [form, setForm] = React.useState<FormState>(EMPTY_FORM);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (!open) return;
    setForm(initial ? fromPoc(initial) : EMPTY_FORM);
  }, [open, initial]);

  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  async function submit() {
    if (!form.name.trim()) {
      toast.error("名称不能为空");
      return;
    }
    const input: PocInput = {
      name: form.name.trim(),
      cve: splitCVEs(form.cve),
      product: form.product.trim(),
      vuln_type: form.vuln_type.trim(),
      severity: form.severity.trim().toLowerCase(),
      tags: splitList(form.tags),
      description: form.description.trim(),
      content: form.content,
      refs: splitList(form.refs, true),
      source: initial?.source || "manual",
      enabled: form.enabled,
    };
    setSaving(true);
    try {
      if (initial) {
        await api.updatePoc(initial.id, input);
        toast.success("PoC 已更新");
      } else {
        await api.createPoc(input);
        toast.success("PoC 已创建");
      }
      onOpenChange(false);
      onSaved();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[90vh] flex-col sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{initial ? "编辑 PoC" : "新增 PoC"}</DialogTitle>
          <DialogDescription>
            content 是 agent 检索后直接拿到并改造的原文：可以是请求报文、脚本、nuclei 模板或复现笔记。
          </DialogDescription>
        </DialogHeader>
        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto pr-1">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="poc-name">名称 *</Label>
              <Input
                id="poc-name"
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="如 Apache Log4j2 JNDI RCE"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="poc-cve">CVE（逗号/空格分隔）</Label>
              <Input
                id="poc-cve"
                value={form.cve}
                onChange={(e) => set("cve", e.target.value)}
                placeholder="CVE-2021-44228"
                className="font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="poc-product">产品 / 组件</Label>
              <Input
                id="poc-product"
                value={form.product}
                onChange={(e) => set("product", e.target.value)}
                placeholder="log4j / weblogic / thinkphp"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="poc-type">漏洞类型</Label>
              <Input
                id="poc-type"
                value={form.vuln_type}
                onChange={(e) => set("vuln_type", e.target.value)}
                placeholder="rce / sqli / ssrf / upload"
                className="font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <Label>严重等级</Label>
              <Select value={form.severity || "none"} onValueChange={(v) => set("severity", v === "none" ? "" : v)}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="未标注" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">未标注</SelectItem>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="poc-tags">标签（逗号分隔）</Label>
              <Input
                id="poc-tags"
                value={form.tags}
                onChange={(e) => set("tags", e.target.value)}
                placeholder="log4j, rce, java"
              />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="poc-desc">描述 / 适用条件</Label>
              <Textarea
                id="poc-desc"
                value={form.description}
                onChange={(e) => set("description", e.target.value)}
                placeholder="命中特征、前置条件、影响版本、验证要点……"
                className="min-h-16 max-h-32"
              />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="poc-refs">参考链接（换行/逗号分隔）</Label>
              <Textarea
                id="poc-refs"
                value={form.refs}
                onChange={(e) => set("refs", e.target.value)}
                placeholder="https://..."
                className="min-h-16 max-h-32 font-mono text-xs"
              />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="poc-content">PoC 原文 *</Label>
              <Textarea
                id="poc-content"
                value={form.content}
                onChange={(e) => set("content", e.target.value)}
                placeholder={"GET /path HTTP/1.1\nHost: {{target}}\n\n或 curl / python / nuclei 模板……"}
                className="min-h-[220px] font-mono text-xs"
              />
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={form.enabled} onCheckedChange={(v) => set("enabled", v)} />
              <Label>启用（停用后 agent 检索不到）</Label>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            取消
          </Button>
          <Button onClick={submit} disabled={saving}>
            {saving && <Loader2Icon className="size-4 animate-spin" />}
            {initial ? "保存" : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PocDetailSheet({
  poc,
  open,
  onOpenChange,
  onEdit,
  onChanged,
}: {
  poc: Poc | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onEdit: (p: Poc) => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = React.useState<Poc | null>(null);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    if (!open || !poc) {
      setDetail(null);
      return;
    }
    let alive = true;
    setLoading(true);
    api
      .poc(poc.id)
      .then((p) => alive && setDetail(p))
      .catch((e) => alive && toast.error((e as Error).message))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [open, poc]);

  const p = detail ?? poc;

  async function copyContent() {
    if (!p?.content) return;
    try {
      await navigator.clipboard.writeText(p.content);
      toast.success("已复制 PoC 原文");
    } catch {
      toast.error("复制失败，请手动选择文本");
    }
  }

  async function toggle() {
    if (!p) return;
    try {
      const next = await api.togglePoc(p.id, !p.enabled);
      setDetail(next);
      toast.success(next.enabled ? "已启用" : "已停用");
      onChanged();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function remove() {
    if (!p) return;
    if (!window.confirm(`删除 PoC「${p.name}」？此操作不可撤销。`)) return;
    try {
      await api.deletePoc(p.id);
      toast.success("已删除");
      onOpenChange(false);
      onChanged();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="flex flex-col gap-0 p-0 data-[side=right]:w-[52vw] data-[side=right]:sm:max-w-[52vw]"
      >
        <SheetHeader className="border-b px-4 py-3">
          <SheetTitle className="pr-8">{p?.name || "PoC 详情"}</SheetTitle>
          <SheetDescription className="flex flex-wrap items-center gap-1.5">
            {p && <Badge variant={severityVariant(p.severity)}>{p.severity || "未标注"}</Badge>}
            {p?.vuln_type && (
              <Badge variant="outline" className="font-mono">
                {p.vuln_type}
              </Badge>
            )}
            {p?.source && <Badge variant="secondary">{p.source}</Badge>}
            {p && !p.enabled && <Badge variant="outline">已停用</Badge>}
          </SheetDescription>
        </SheetHeader>

        {loading ? (
          <div className="flex flex-1 items-center justify-center">
            <Loader2Icon className="size-5 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-3 text-sm">
            {p && (
              <>
                <div className="grid gap-2 text-xs sm:grid-cols-2">
                  <div>
                    <span className="text-muted-foreground">CVE：</span>
                    <span className="font-mono">{p.cve.length ? p.cve.join(", ") : "-"}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">产品：</span>
                    {p.product || "-"}
                  </div>
                  <div>
                    <span className="text-muted-foreground">来源：</span>
                    {p.source || "-"}
                  </div>
                  <div>
                    <span className="text-muted-foreground">更新时间：</span>
                    {fmtTime(p.updated_at)}
                  </div>
                  <div className="sm:col-span-2">
                    <span className="text-muted-foreground">标签：</span>
                    {p.tags.length ? p.tags.join(", ") : "-"}
                  </div>
                </div>
                {p.description && (
                  <div>
                    <div className="mb-1 text-xs text-muted-foreground">描述</div>
                    <p className="whitespace-pre-wrap text-sm leading-relaxed">{p.description}</p>
                  </div>
                )}
                {p.refs.length > 0 && (
                  <div>
                    <div className="mb-1 text-xs text-muted-foreground">参考链接</div>
                    <ul className="space-y-1">
                      {p.refs.map((u) => (
                        <li key={u}>
                          <a
                            href={u}
                            target="_blank"
                            rel="noreferrer"
                            className="text-primary break-all text-xs underline underline-offset-2"
                          >
                            {u}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div>
                  <div className="mb-1 flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">PoC 原文（agent 看到的内容）</span>
                    <Button variant="ghost" size="sm" className="h-7" onClick={copyContent}>
                      <CopyIcon className="size-3.5" />
                      复制
                    </Button>
                  </div>
                  <pre className="max-h-[46vh] overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap break-all">
                    {p.content || "（空）"}
                  </pre>
                </div>
              </>
            )}
          </div>
        )}

        <div className="flex items-center justify-end gap-2 border-t px-4 py-3">
          <Button variant="outline" size="sm" onClick={() => p && onEdit(p)}>
            <PencilIcon className="size-3.5" />
            编辑
          </Button>
          <Button variant="outline" size="sm" onClick={toggle}>
            {p?.enabled ? "停用" : "启用"}
          </Button>
          <Button variant="destructive" size="sm" onClick={remove}>
            <Trash2Icon className="size-3.5" />
            删除
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

function outcomeText(out: PocImportOutcome): string {
  const parts = [`新增 ${out.inserted}`, `更新 ${out.updated}`];
  if (out.scanned !== undefined) parts.unshift(`扫描 ${out.scanned} 个文件`);
  if (out.failed > 0) parts.push(`失败 ${out.failed}`);
  return parts.join("，");
}

function ImportDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDone: () => void;
}) {
  const [files, setFiles] = React.useState<File[]>([]);
  const [dir, setDir] = React.useState("");
  const [recursive, setRecursive] = React.useState(true);
  const [busy, setBusy] = React.useState<"upload" | "dir" | null>(null);
  const [outcome, setOutcome] = React.useState<PocImportOutcome | null>(null);

  React.useEffect(() => {
    if (!open) {
      setFiles([]);
      setDir("");
      setOutcome(null);
    }
  }, [open]);

  async function upload() {
    if (files.length === 0) {
      toast.error("请选择要导入的文件");
      return;
    }
    setBusy("upload");
    setOutcome(null);
    try {
      const out = await api.importPocs(files);
      setOutcome(out);
      toast.success(outcomeText(out));
      onDone();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function scanDir() {
    if (!dir.trim()) {
      toast.error("请输入服务器上的目录路径");
      return;
    }
    setBusy("dir");
    setOutcome(null);
    try {
      const out = await api.importPocDir(dir.trim(), recursive);
      setOutcome(out);
      toast.success(outcomeText(out));
      onDone();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>导入 PoC 素材</DialogTitle>
          <DialogDescription>
            支持 nuclei 模板（YAML）、通用 YAML/JSON、Markdown（可带 frontmatter）、以及任意 UTF-8
            文本/脚本。按内容自动识别；同一来源重复导入会更新而不是新增。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5">
          <div className="space-y-2 rounded-lg border p-3">
            <div className="flex items-center gap-2 text-sm font-medium">
              <UploadIcon className="size-4 text-muted-foreground" />
              上传文件
            </div>
            <Input
              type="file"
              multiple
              onChange={(e) => setFiles(Array.from(e.target.files ?? []))}
              className="cursor-pointer file:mr-2 file:rounded file:border-0 file:bg-muted file:px-2 file:py-1 file:text-xs"
            />
            <div className="flex items-center justify-between gap-2">
              <span className="text-muted-foreground text-xs">
                {files.length ? `已选 ${files.length} 个文件` : "可一次选择多个文件"}
              </span>
              <Button size="sm" onClick={upload} disabled={busy !== null || files.length === 0}>
                {busy === "upload" && <Loader2Icon className="size-4 animate-spin" />}
                开始导入
              </Button>
            </div>
          </div>

          <div className="space-y-2 rounded-lg border p-3">
            <div className="flex items-center gap-2 text-sm font-medium">
              <FolderInputIcon className="size-4 text-muted-foreground" />
              扫描服务器目录
            </div>
            <Input
              value={dir}
              onChange={(e) => setDir(e.target.value)}
              placeholder="例如 C:\poc-repo 或 /opt/nuclei-templates"
              className="font-mono text-xs"
            />
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Switch checked={recursive} onCheckedChange={setRecursive} />
                <Label className="text-xs">递归子目录</Label>
              </div>
              <Button size="sm" onClick={scanDir} disabled={busy !== null || !dir.trim()}>
                {busy === "dir" && <Loader2Icon className="size-4 animate-spin" />}
                扫描并导入
              </Button>
            </div>
            <p className="text-muted-foreground text-[11px]">
              跳过隐藏目录、node_modules、vendor、符号链接与二进制文件；单文件上限 8 MiB。
            </p>
          </div>

          {outcome && (
            <div className="rounded-lg border bg-muted/30 p-3 text-xs">
              <div className="font-medium">{outcomeText(outcome)}</div>
              {outcome.formats && Object.keys(outcome.formats).length > 0 && (
                <div className="mt-1 text-muted-foreground">
                  识别格式：
                  {Object.entries(outcome.formats)
                    .map(([k, v]) => `${k} ${v}`)
                    .join(" · ")}
                </div>
              )}
              {outcome.errors && outcome.errors.length > 0 && (
                <ul className="mt-2 max-h-24 space-y-0.5 overflow-y-auto text-destructive">
                  {outcome.errors.map((er) => (
                    <li key={`${er.file}-${er.error}`} className="truncate">
                      {er.file}: {er.error}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            关闭
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function PocsPage() {
  const [query, setQuery] = React.useState("");
  const [queryQ, setQueryQ] = React.useState("");
  const [severity, setSeverity] = React.useState("all");
  const [enabled, setEnabled] = React.useState<"all" | "1" | "0">("all");
  const [page, setPage] = React.useState(0);

  const [pocs, setPocs] = React.useState<Poc[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [stats, setStats] = React.useState<PocStats | null>(null);
  const [reloadKey, setReloadKey] = React.useState(0);

  const [detailOpen, setDetailOpen] = React.useState(false);
  const [selected, setSelected] = React.useState<Poc | null>(null);
  const [formOpen, setFormOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<Poc | null>(null);
  const [importOpen, setImportOpen] = React.useState(false);

  const reload = React.useCallback(() => setReloadKey((k) => k + 1), []);

  React.useEffect(() => {
    const t = setTimeout(() => setQueryQ(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: filters intentionally reset pagination.
  React.useEffect(() => {
    setPage(0);
  }, [queryQ, severity, enabled]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: reloadKey is the explicit "reload after mutation" trigger.
  React.useEffect(() => {
    let alive = true;
    api
      .pocStats()
      .then((s) => alive && setStats(s))
      .catch(() => alive && setStats(null));
    return () => {
      alive = false;
    };
  }, [reloadKey]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: reloadKey + filters are the reload triggers.
  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .pocs({
        q: queryQ || undefined,
        severity: severity === "all" ? undefined : severity,
        enabled,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      })
      .then((r) => {
        if (!alive) return;
        setPocs(r.pocs ?? []);
        setTotal(r.total ?? 0);
      })
      .catch(() => {
        if (!alive) return;
        setPocs([]);
        setTotal(0);
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [queryQ, severity, enabled, page, reloadKey]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const rangeStart = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const rangeEnd = page * PAGE_SIZE + pocs.length;
  const critical = (stats?.by_severity?.critical ?? 0) + (stats?.by_severity?.high ?? 0);

  function openCreate() {
    setEditing(null);
    setFormOpen(true);
  }

  function openEdit(p: Poc) {
    setEditing(p);
    setFormOpen(true);
  }

  async function remove(p: Poc) {
    if (!window.confirm(`删除 PoC「${p.name}」？此操作不可撤销。`)) return;
    try {
      await api.deletePoc(p.id);
      toast.success("已删除");
      reload();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <BookOpenIcon className="mt-1 size-5 text-muted-foreground" />
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold tracking-tight">PoC 库</h1>
              <Badge variant="secondary">{total}</Badge>
            </div>
            <p className="text-muted-foreground mt-0.5 text-sm">
              渗透时 agent 会先调用 <span className="font-mono">search_poc</span> 在本库检索；只有本地无命中才走{" "}
              <span className="font-mono">web_search</span> 联网。
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setImportOpen(true)}>
            <UploadIcon className="size-4" />
            导入
          </Button>
          <Button size="sm" onClick={openCreate}>
            <PlusIcon className="size-4" />
            新增 PoC
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {[
          { label: "总条目", value: stats?.total ?? 0 },
          { label: "启用", value: stats?.enabled ?? 0 },
          { label: "含 CVE", value: stats?.with_cve ?? 0 },
          { label: "高危 / 严重", value: critical },
        ].map((item) => (
          <Card key={item.label} className="py-0">
            <CardContent className="px-3.5 py-3">
              <div className="text-lg leading-none font-semibold tabular-nums">{item.value}</div>
              <div className="text-muted-foreground mt-1 text-[11px]">{item.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <SearchIcon className="text-muted-foreground absolute top-1/2 left-2.5 size-4 -translate-y-1/2" />
          <Input
            placeholder="关键词：产品 / CVE / 漏洞类型 / 利用方式…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="h-8 pl-8"
          />
        </div>
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger size="sm" className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部等级</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={enabled} onValueChange={(v) => setEnabled(v as "all" | "1" | "0")}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            <SelectItem value="1">仅启用</SelectItem>
            <SelectItem value="0">仅停用</SelectItem>
          </SelectContent>
        </Select>
        <div className="text-muted-foreground ml-auto flex items-center gap-2 text-xs">
          <span className="tabular-nums">
            {rangeStart}–{rangeEnd} / {total}
          </span>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={page <= 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            ‹
          </Button>
          <span className="tabular-nums">
            {page + 1} / {totalPages}
          </span>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={page + 1 >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
          >
            ›
          </Button>
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col">
        <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
          <div className="min-h-0 flex-1 overflow-auto">
            <Table>
              <TableHeader className="sticky top-0 z-10 bg-card">
                <TableRow>
                  <TableHead className="min-w-[220px]">名称</TableHead>
                  <TableHead className="w-[150px]">CVE</TableHead>
                  <TableHead className="w-[130px]">产品 / 类型</TableHead>
                  <TableHead className="w-[90px]">等级</TableHead>
                  <TableHead className="w-[90px]">来源</TableHead>
                  <TableHead className="w-[110px]">更新时间</TableHead>
                  <TableHead className="w-[70px]">状态</TableHead>
                  <TableHead className="w-[80px]">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && pocs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="py-12 text-center">
                      <Loader2Icon className="mx-auto size-5 animate-spin text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : pocs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="py-12 text-center text-sm text-muted-foreground">
                      暂无 PoC。可以点「新增 PoC」手工录入、用「导入」批量导入 nuclei 模板 / PoC 仓库，或在对话里让主 agent 用 add_poc 保存。
                    </TableCell>
                  </TableRow>
                ) : (
                  pocs.map((p) => (
                    <TableRow
                      key={p.id}
                      className={cn("cursor-pointer", selected?.id === p.id && "bg-accent")}
                      onClick={() => {
                        setSelected(p);
                        setDetailOpen(true);
                      }}
                    >
                      <TableCell className="max-w-[320px]">
                        <div className="truncate font-medium">{p.name}</div>
                        <div className="text-muted-foreground mt-0.5 line-clamp-1 text-xs">
                          {p.description || (p.tags.length ? p.tags.join(", ") : "—")}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{p.cve.length ? p.cve.join(", ") : "—"}</TableCell>
                      <TableCell className="text-xs">
                        <div className="truncate">{p.product || "—"}</div>
                        {p.vuln_type && (
                          <Badge variant="outline" className="mt-0.5 font-mono text-[10px]">
                            {p.vuln_type}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={severityVariant(p.severity)}>{p.severity || "未标注"}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">{p.source || "—"}</TableCell>
                      <TableCell className="text-muted-foreground text-xs tabular-nums">
                        {fmtTime(p.updated_at)}
                      </TableCell>
                      <TableCell>
                        {p.enabled ? (
                          <Badge variant="secondary" className="text-[10px]">
                            启用
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px]">
                            停用
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-1">
                          <Button variant="ghost" size="icon-sm" onClick={() => openEdit(p)}>
                            <PencilIcon className="size-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            className="text-muted-foreground hover:text-destructive"
                            onClick={() => remove(p)}
                          >
                            <Trash2Icon className="size-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </Card>
      </div>

      <PocFormDialog open={formOpen} onOpenChange={setFormOpen} initial={editing} onSaved={reload} />
      <ImportDialog open={importOpen} onOpenChange={setImportOpen} onDone={reload} />
      <PocDetailSheet
        poc={selected}
        open={detailOpen}
        onOpenChange={setDetailOpen}
        onEdit={(p) => {
          setDetailOpen(false);
          openEdit(p);
        }}
        onChanged={reload}
      />
    </div>
  );
}
