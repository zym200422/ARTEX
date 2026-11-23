"use client";

import * as React from "react";

import { Loader2Icon, RotateCcwIcon, SendIcon } from "lucide-react";
import { toast } from "sonner";

import { HttpCodeBlock } from "@/components/http-code-block";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { TrafficExchange, TrafficReplayResult } from "@/lib/types";
import { cn } from "@/lib/utils";

const REPLAY_DEFAULT_TIMEOUT = 15000;

function statusTone(status: number): string {
  if (status >= 500) return "bg-red-500/15 text-red-700 dark:text-red-400";
  if (status >= 400) return "bg-amber-500/15 text-amber-700 dark:text-amber-400";
  if (status >= 300) return "bg-blue-500/15 text-blue-700 dark:text-blue-400";
  return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400";
}

/** 从原始请求里解析 Host 头（没有则空，交给用户手填）。 */
function hostFromRaw(raw: string): string {
  for (const line of raw.split(/\r?\n/)) {
    if (!line.trim()) break;
    if (/^host\s*:/i.test(line)) return line.replace(/^host\s*:\s*/i, "").trim();
  }
  return "";
}

/**
 * 流量重放：把录制的原始请求原样（或改参后）重新发给目标，回显真实响应。
 * 发送走服务端代理（POST /api/traffic/replay），不受浏览器 CORS/HTTPS 限制；
 * 目标主机会先过「资产拦截规则」红线，命中即 403。
 */
export function TrafficReplayDialog({
  open,
  onOpenChange,
  exchange,
  prefillRaw,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  exchange: TrafficExchange | null;
  /** 父组件已拼好 Host 头的报文；传入则跳过详情拉取。 */
  prefillRaw?: string;
}) {
  const [raw, setRaw] = React.useState("");
  const [host, setHost] = React.useState("");
  const [tls, setTls] = React.useState(false);
  const [noGzip, setNoGzip] = React.useState(true);
  const [sending, setSending] = React.useState(false);
  const [result, setResult] = React.useState<TrafficReplayResult | null>(null);

  // 打开时预填：优先用父组件拼好 Host 的报文，否则拉取详情；目标默认取录制主机。
  React.useEffect(() => {
    if (!open || !exchange) return;
    setResult(null);
    setTls(/:443$/.test(exchange.host) || exchange.url.startsWith("https://"));
    const prefill = prefillRaw !== undefined && prefillRaw.trim() ? prefillRaw : "";
    if (prefill) {
      const filled = /\r?\nhost\s*:/i.test(prefill) ? prefill : `${prefill}\r\nHost: ${exchange.host}`;
      setRaw(filled);
      setHost(hostFromRaw(filled) || exchange.host);
      return;
    }
    api
      .trafficExchange(exchange.id)
      .then((d) => {
        const full = d.req?.trim() ? d.req : `GET ${exchange.url} HTTP/1.1`;
        const filled = /\r?\nhost\s*:/i.test(full) ? full : `${full}\r\nHost: ${exchange.host}`;
        setRaw(filled);
        setHost(hostFromRaw(filled) || exchange.host);
      })
      .catch(() => {
        setRaw(`GET ${exchange.url} HTTP/1.1\r\nHost: ${exchange.host}`);
        setHost(exchange.host);
      });
  }, [open, exchange, prefillRaw]);

  async function send() {
    if (!raw.trim()) {
      toast.error("请求报文为空");
      return;
    }
    setSending(true);
    try {
      const result = await api.trafficReplay({
        raw,
        host,
        tls,
        timeout_ms: REPLAY_DEFAULT_TIMEOUT,
        no_gzip: noGzip,
      });
      setResult(result);
    } catch (error) {
      toast.error(`重放失败：${(error as Error).message}`);
    } finally {
      setSending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <RotateCcwIcon className="size-4" />
            流量重放
            {exchange && <span className="text-muted-foreground font-mono text-xs">#{exchange.id}</span>}
          </DialogTitle>
          <DialogDescription>
            请求报文可自由改参后原样重发；发送走服务端代理，目标主机会先过「资产拦截规则」。
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-56 flex-1">
            <Label htmlFor="replay-host" className="text-xs">
              目标主机 host[:port]
            </Label>
            <Input
              id="replay-host"
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="target.example.com[:port]"
              className="mt-1 font-mono text-xs"
            />
          </div>
          <label htmlFor="replay-tls" className="flex items-center gap-2 pb-0.5 text-xs">
            <Switch id="replay-tls" checked={tls} onCheckedChange={setTls} />
            HTTPS
          </label>
          <label htmlFor="replay-no-gzip" className="flex items-center gap-2 pb-0.5 text-xs text-muted-foreground">
            <Switch id="replay-no-gzip" checked={noGzip} onCheckedChange={setNoGzip} />
            自动去 gzip
          </label>
        </div>

        <Field>
          <Label htmlFor="replay-raw" className="text-xs">
            请求报文（可改参，原样发送）
          </Label>
          <Textarea
            id="replay-raw"
            value={raw}
            onChange={(event) => setRaw(event.target.value)}
            className="min-h-48 font-mono text-xs leading-relaxed"
            spellCheck={false}
          />
        </Field>

        {result && (
          <div className="rounded-lg border">
            <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
              <Badge className={cn("font-mono tabular-nums", statusTone(result.status))}>{result.status}</Badge>
              <span className="text-muted-foreground font-mono text-[11px]">{result.status_line}</span>
              <span className="text-muted-foreground ml-auto text-[11px] tabular-nums">
                {result.duration_ms} ms · {result.target}
                {result.body_truncated ? " · 正文截断" : ""}
              </span>
            </div>
            <div className="px-3 py-2">
              <HttpCodeBlock
                raw={`HTTP/1.1 ${result.status}\n${Object.entries(result.headers)
                  .map(([key, value]) => `${key}: ${value}`)
                  .join("\n")}\n\n${result.body}`}
              />
            </div>
          </div>
        )}

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            关闭
          </Button>
          <Button type="button" onClick={() => void send()} disabled={sending || !raw.trim()}>
            {sending ? <Loader2Icon className="animate-spin" /> : <SendIcon data-icon="inline-start" />}
            {sending ? "发送中" : "重放发送"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
