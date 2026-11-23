"use client";

import * as React from "react";

import { ChevronDownIcon, ChevronUpIcon, SearchIcon, XIcon } from "lucide-react";
import { toast } from "sonner";

import { HttpCodeBlock } from "@/components/http-code-block";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { FindingTrafficDetail, TrafficDetail } from "@/lib/types";

export function TrafficEvidenceViewer({
  findingId,
  bindingId,
  contextTask,
  onClose,
}: {
  findingId: string;
  bindingId: string | null;
  contextTask?: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = React.useState<FindingTrafficDetail | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [hitIndex, setHitIndex] = React.useState(0);
  React.useEffect(() => {
    if (!bindingId) return;
    let active = true;
    setDetail(null);
    setError("");
    api
      .findingTrafficDetail(findingId, bindingId, contextTask)
      .then((d) => {
        if (active) setDetail(d);
      })
      .catch((e: Error) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [findingId, bindingId, contextTask]);

  async function more(side: "request" | "response") {
    if (!detail || !bindingId) return;
    setBusy(true);
    try {
      const next = await api.findingTrafficBody(findingId, bindingId, side, detail[side].next_offset, contextTask);
      setDetail((current) =>
        current?.binding.id === bindingId
          ? { ...current, [side]: { ...next, content: current[side].content + next.content } }
          : current,
      );
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={bindingId !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>流量证据 #{bindingId}</DialogTitle>
          <DialogDescription className="break-all">
            {detail?.binding.snapshot.url ?? "查看绑定时保存的请求与响应"}
          </DialogDescription>
        </DialogHeader>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : detail ? (
          <Tabs defaultValue="request">
            <TabsList>
              <TabsTrigger value="request">请求 Request</TabsTrigger>
              <TabsTrigger value="response">响应 Response</TabsTrigger>
            </TabsList>
            {(["request", "response"] as const).map((side) => (
              <TabsContent key={side} value={side}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs text-muted-foreground">
                    正文 {detail[side].total.toLocaleString()} 字节{detail[side].truncated ? " · 当前为预览" : ""}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      void api
                        .downloadFindingTrafficBody(findingId, detail.binding.id, side, contextTask)
                        .catch((e: Error) => toast.error(e.message))
                    }
                  >
                    下载完整{side === "request" ? "请求" : "响应"}正文
                  </Button>
                </div>
                {(() => {
                  const head =
                    (side === "request"
                      ? detail.binding.snapshot.req_head
                      : detail.binding.snapshot.resp_head
                    )?.trimEnd() ?? "";
                  const full = `${head}\n\n${detail[side].content}`;
                  const hits = countHits(full, query);
                  const active = Math.min(hitIndex, Math.max(0, hits - 1));
                  return (
                    <>
                      <div className="flex flex-wrap items-center gap-2">
                        <div className="relative min-w-48 flex-1">
                          <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
                          <Input
                            value={query}
                            onChange={(event) => {
                              setQuery(event.target.value);
                              setHitIndex(0);
                            }}
                            placeholder="正文检索（关键字 / 参数 / 报错）"
                            className="h-8 pl-8 font-mono text-xs"
                          />
                          {query && (
                            <button
                              type="button"
                              aria-label="清除检索"
                              className="absolute top-1/2 right-2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                              onClick={() => {
                                setQuery("");
                                setHitIndex(0);
                              }}
                            >
                              <XIcon className="size-3.5" />
                            </button>
                          )}
                        </div>
                        <span className="text-muted-foreground text-xs tabular-nums">
                          {query ? `命中 ${hits} 处${hits > 0 ? ` · ${active + 1}/${hits}` : ""}` : "支持正文检索"}
                        </span>
                        <div className="flex items-center gap-0.5">
                          <Button
                            type="button"
                            size="icon-sm"
                            variant="ghost"
                            aria-label="上一处"
                            disabled={hits === 0}
                            onClick={() => setHitIndex((current) => (current - 1 + hits) % hits)}
                          >
                            <ChevronUpIcon />
                          </Button>
                          <Button
                            type="button"
                            size="icon-sm"
                            variant="ghost"
                            aria-label="下一处"
                            disabled={hits === 0}
                            onClick={() => setHitIndex((current) => (current + 1) % hits)}
                          >
                            <ChevronDownIcon />
                          </Button>
                        </div>
                      </div>
                      {query ? (
                        <HighlightedPre text={full} query={query} active={active} />
                      ) : (
                        <HttpCodeBlock raw={full} />
                      )}
                    </>
                  );
                })()}
                {detail[side].truncated && !detail[side].binary ? (
                  <Button variant="outline" size="sm" disabled={busy} onClick={() => void more(side)}>
                    加载更多正文
                  </Button>
                ) : null}
              </TabsContent>
            ))}
          </Tabs>
        ) : (
          <Skeleton className="h-56 w-full" />
        )}
      </DialogContent>
    </Dialog>
  );
}

export function CapturedTrafficViewer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const [detail, setDetail] = React.useState<TrafficDetail | null>(null);
  const [error, setError] = React.useState("");
  React.useEffect(() => {
    if (!id) return;
    let active = true;
    setDetail(null);
    setError("");
    api
      .trafficExchange(id)
      .then((d) => {
        if (active) setDetail(d);
      })
      .catch((e: Error) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [id]);
  return (
    <Dialog
      open={id !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>预览流量</DialogTitle>
          <DialogDescription>流量 ID：{id}。绑定时会保存完整正文。</DialogDescription>
        </DialogHeader>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : detail ? (
          <Tabs defaultValue="request">
            <TabsList>
              <TabsTrigger value="request">请求 Request</TabsTrigger>
              <TabsTrigger value="response">响应 Response</TabsTrigger>
            </TabsList>
            <TabsContent value="request">
              <HttpCodeBlock raw={detail.req} />
            </TabsContent>
            <TabsContent value="response">
              <HttpCodeBlock raw={detail.resp} />
            </TabsContent>
          </Tabs>
        ) : (
          <Skeleton className="h-56 w-full" />
        )}
      </DialogContent>
    </Dialog>
  );
}

function countHits(text: string, query: string): number {
  const needle = query.trim().toLowerCase();
  if (!needle) return 0;
  return text.toLowerCase().split(needle).length - 1;
}

/** 命中高亮：纯文本渲染（检索时暂时放弃语法着色），并用 mark 标出全部命中。 */
function HighlightedPre({ text, query, active }: { text: string; query: string; active: number }) {
  const ref = React.useRef<HTMLPreElement>(null);
  const needle = query.trim().toLowerCase();

  React.useEffect(() => {
    ref.current?.querySelector(`[data-hit="${active}"]`)?.scrollIntoView({ block: "center" });
  }, [active]);

  if (!needle) return <HttpCodeBlock raw={text} />;

  const parts: React.ReactNode[] = [];
  const lower = text.toLowerCase();
  let cursor = 0;
  let hit = 0;
  while (cursor < text.length) {
    const found = lower.indexOf(needle, cursor);
    if (found < 0) {
      parts.push(text.slice(cursor));
      break;
    }
    if (found > cursor) parts.push(text.slice(cursor, found));
    const end = found + needle.length;
    parts.push(
      <mark
        // biome-ignore lint/suspicious/noArrayIndexKey: 命中序号稳定且仅用于滚动定位
        key={`hit-${hit}`}
        data-hit={hit}
        className={
          hit === active ? "rounded bg-amber-400 px-0.5 text-slate-950" : "rounded bg-amber-200 px-0.5 text-slate-900"
        }
      >
        {text.slice(found, end)}
      </mark>,
    );
    hit += 1;
    cursor = end;
  }

  return (
    <pre
      ref={ref}
      className="max-h-[52vh] overflow-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-[11px] leading-relaxed break-words whitespace-pre-wrap"
    >
      {parts}
    </pre>
  );
}
