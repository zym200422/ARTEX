"use client";

import * as React from "react";
import { useSyncExternalStore } from "react";

import { PencilIcon, PlusIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { ApprovalVerdictBadge } from "@/components/delivery/approval-badge";
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
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  ACTION_META,
  type ApprovalAction,
  type ApprovalReview,
  BUILTIN_RULE_META as BUILTIN_RULES,
  type CustomApprovalRule,
} from "@/lib/approval-engine";
import {
  approvalServerVersion,
  approvalVersion,
  deleteCustomRule,
  getApprovalReviews,
  getCustomRules,
  getRuleDisabledMap,
  setRuleEnabled,
  subscribeApproval,
  upsertCustomRule,
} from "@/lib/approval-store";
import { cn } from "@/lib/utils";

function fmtTime(at: number): string {
  return new Date(at * 1000).toLocaleString("zh-CN", { hour12: false });
}

function emptyRule(): CustomApprovalRule {
  return {
    id: "",
    name: "",
    mode: "block",
    scope: "any",
    keywords: [],
    action: "reject",
    enabled: true,
    note: "",
  };
}

function RuleLibrary({
  onEditRule,
  onDeletedRule,
}: {
  onEditRule: (rule: CustomApprovalRule) => void;
  onDeletedRule: () => void;
}) {
  const version = useSyncExternalStore(subscribeApproval, approvalVersion, approvalServerVersion);
  // biome-ignore lint/correctness/useExhaustiveDependencies: version 仅用于触发重算
  const disabledMap = React.useMemo(() => getRuleDisabledMap(), [version]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: version 仅用于触发重算
  const customRules = React.useMemo(() => getCustomRules(), [version]);
  const [pendingDelete, setPendingDelete] = React.useState<CustomApprovalRule | null>(null);

  const groups = React.useMemo(() => {
    const map = new Map<string, typeof BUILTIN_RULES>();
    for (const rule of BUILTIN_RULES) {
      const list = map.get(rule.group) ?? [];
      list.push(rule);
      map.set(rule.group, list);
    }
    return [...map.entries()];
  }, []);

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-sm">自定义规则</CardTitle>
            <CardDescription>
              关键词类规则：block=命中即违规；require=必须包含关键词。生效范围/动作可配。
            </CardDescription>
          </div>
          <Button size="sm" variant="outline" onClick={() => onEditRule(emptyRule())}>
            <PlusIcon data-icon="inline-start" />
            添加规则
          </Button>
        </CardHeader>
        <CardContent>
          {customRules.length === 0 ? (
            <p className="text-muted-foreground py-3 text-xs">还没有自定义规则。</p>
          ) : (
            <div className="space-y-2">
              {customRules.map((rule) => (
                <div key={rule.id} className="flex flex-wrap items-center gap-2 rounded-lg border px-3 py-2.5">
                  <span className="text-sm font-medium">{rule.name}</span>
                  <Badge variant="outline" className={cn("h-5 px-1.5 text-[10px]", ACTION_META[rule.action].tone)}>
                    {ACTION_META[rule.action].label}
                  </Badge>
                  <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
                    {rule.mode === "block" ? "命中拦截" : "必须包含"}
                  </Badge>
                  <span className="text-muted-foreground truncate text-[11px]">
                    [{rule.scope}] {rule.keywords.join("、")}
                  </span>
                  <div className="ml-auto flex items-center gap-2">
                    <Switch
                      checked={rule.enabled}
                      onCheckedChange={(value) => upsertCustomRule({ ...rule, enabled: value === true })}
                      aria-label={`启停规则 ${rule.name}`}
                    />
                    <Button type="button" size="icon-sm" variant="ghost" onClick={() => onEditRule(rule)}>
                      <PencilIcon />
                    </Button>
                    <Button
                      type="button"
                      size="icon-sm"
                      variant="ghost"
                      aria-label="删除规则"
                      onClick={() => setPendingDelete(rule)}
                    >
                      <Trash2Icon />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">内置规则库（{BUILTIN_RULES.length} 条）</CardTitle>
          <CardDescription>
            按组展示；「拒绝」= 不满足直接拦截，「退回」= 需补证后再上报，「提醒」= 仅提示不拦截。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {groups.map(([group, rules]) => (
            <div key={group}>
              <div className="text-muted-foreground mb-2 text-xs font-medium">{group}</div>
              <div className="space-y-2">
                {rules.map((rule) => {
                  const enabled = !disabledMap[rule.id];
                  return (
                    <div key={rule.id} className="flex items-start gap-3 rounded-lg border p-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-sm font-medium">{rule.name}</span>
                          <Badge
                            variant="outline"
                            className={cn("h-5 px-1.5 text-[10px]", ACTION_META[rule.action].tone)}
                          >
                            {ACTION_META[rule.action].label}
                          </Badge>
                          <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
                            内置
                          </Badge>
                        </div>
                        <p className="mt-1 text-muted-foreground text-xs leading-relaxed">{rule.criterion}</p>
                      </div>
                      <Switch
                        checked={enabled}
                        onCheckedChange={(value) => setRuleEnabled(rule.id, value === true)}
                        aria-label={`启停规则 ${rule.name}`}
                      />
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <AlertDialog open={pendingDelete !== null} onOpenChange={(next) => !next && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除规则「{pendingDelete?.name}」？</AlertDialogTitle>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                if (pendingDelete) deleteCustomRule(pendingDelete.id);
                setPendingDelete(null);
                onDeletedRule();
              }}
            >
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function ReviewRecords() {
  const version = useSyncExternalStore(subscribeApproval, approvalVersion, approvalServerVersion);
  // biome-ignore lint/correctness/useExhaustiveDependencies: version 仅用于触发重算
  const reviews = React.useMemo(() => getApprovalReviews(), [version]);
  const [detail, setDetail] = React.useState<ApprovalReview | null>(null);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">审批记录</CardTitle>
        <CardDescription>每次 AI 审批都会留档；同发现同结论只保留最近一条。</CardDescription>
      </CardHeader>
      <CardContent className="px-0">
        {reviews.length === 0 ? (
          <p className="text-muted-foreground py-6 text-center text-xs">还没有审批记录。</p>
        ) : (
          <div className="divide-y">
            {reviews.map((review) => (
              <div key={`${review.findingId}-${review.at}`} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">{review.findingName}</span>
                  <span className="block truncate text-muted-foreground text-[11px]">{review.summary}</span>
                </span>
                <span className="text-muted-foreground text-[11px] whitespace-nowrap">{fmtTime(review.at)}</span>
                <ApprovalVerdictBadge verdict={review.verdict} score={review.score} />
                <Button type="button" size="sm" variant="ghost" onClick={() => setDetail(review)}>
                  详情
                </Button>
              </div>
            ))}
          </div>
        )}

        <Dialog open={detail !== null} onOpenChange={(next) => !next && setDetail(null)}>
          <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>审批详情 · {detail?.findingName}</DialogTitle>
              <DialogDescription>{detail?.summary}</DialogDescription>
            </DialogHeader>
            {detail && (
              <div className="space-y-1.5">
                {detail.hits.map((hit) => {
                  const meta = ACTION_META[hit.action];
                  return (
                    <div
                      key={`${hit.ruleId}-${hit.ruleName}`}
                      className={cn(
                        "flex items-start gap-2 rounded-md border px-2.5 py-2",
                        hit.passed ? "border-border" : "border-amber-500/30 bg-amber-500/5",
                      )}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-xs font-medium">{hit.ruleName}</span>
                          <Badge variant="outline" className={cn("h-4 px-1 text-[9px]", meta.tone)}>
                            {meta.label}
                          </Badge>
                          <Badge variant={hit.passed ? "default" : "destructive"} className="h-4 px-1 text-[9px]">
                            {hit.passed ? "通过" : "未通过"}
                          </Badge>
                        </div>
                        <p className="mt-0.5 text-muted-foreground text-[11px] leading-relaxed">{hit.detail}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setDetail(null)}>
                关闭
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}

function RuleEditor({
  open,
  onOpenChange,
  draft,
  onDraftChange,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  draft: CustomApprovalRule;
  onDraftChange: (rule: CustomApprovalRule) => void;
  onSaved: () => void;
}) {
  function save() {
    if (!draft.name.trim()) {
      toast.error("请填写规则名称");
      return;
    }
    const keywords = draft.keywords.map((item) => item.trim()).filter(Boolean);
    if (keywords.length === 0) {
      toast.error("至少填写一个关键词");
      return;
    }
    const id = draft.id || `custom-${Date.now().toString(36)}`;
    upsertCustomRule({ ...draft, id, keywords });
    onOpenChange(false);
    onSaved();
    toast.success("规则已保存");
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{draft.id ? "编辑审批规则" : "添加审批规则"}</DialogTitle>
          <DialogDescription>
            规则会在每次上报审批时执行；先用关键词类规则跑起来，后续再扩展更复杂的判定。
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <Field>
            <FieldLabel>规则名称</FieldLabel>
            <Input
              value={draft.name}
              onChange={(event) => onDraftChange({ ...draft, name: event.target.value })}
              placeholder="例如：禁止上报 XSS Stirred 误报"
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field>
              <FieldLabel>判定方式</FieldLabel>
              <NativeSelect
                value={draft.mode}
                onChange={(event) =>
                  onDraftChange({ ...draft, mode: event.target.value as CustomApprovalRule["mode"] })
                }
              >
                <NativeSelectOption value="block">block · 命中关键词即违规</NativeSelectOption>
                <NativeSelectOption value="require">require · 必须包含关键词</NativeSelectOption>
              </NativeSelect>
            </Field>
            <Field>
              <FieldLabel>动作</FieldLabel>
              <NativeSelect
                value={draft.action}
                onChange={(event) => onDraftChange({ ...draft, action: event.target.value as ApprovalAction })}
              >
                <NativeSelectOption value="reject">reject · 拒绝上报</NativeSelectOption>
                <NativeSelectOption value="return">return · 退回补证</NativeSelectOption>
                <NativeSelectOption value="warn">warn · 仅提醒</NativeSelectOption>
              </NativeSelect>
            </Field>
          </div>
          <Field>
            <FieldLabel>检索范围</FieldLabel>
            <NativeSelect
              value={draft.scope}
              onChange={(event) =>
                onDraftChange({ ...draft, scope: event.target.value as CustomApprovalRule["scope"] })
              }
            >
              <NativeSelectOption value="any">全文（名称+描述+证据+复现）</NativeSelectOption>
              <NativeSelectOption value="name">仅漏洞名称</NativeSelectOption>
              <NativeSelectOption value="description">仅描述/影响/修复</NativeSelectOption>
              <NativeSelectOption value="evidence">仅证据（请求/响应/原文）</NativeSelectOption>
            </NativeSelect>
            <FieldDescription>require + evidence：例如「证据里必须包含 DNSLog 外带回显」。</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>关键词（一行一个，任一命中）</FieldLabel>
            <Textarea
              className="min-h-24 font-mono text-xs"
              value={draft.keywords.join("\n")}
              onChange={(event) =>
                onDraftChange({
                  ...draft,
                  keywords: event.target.value.split("\n").map((line) => line.trimStart()),
                })
              }
              placeholder={"理论上\n可能存在\n未复现"}
            />
          </Field>
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button type="button" onClick={save}>
            保存规则
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ApprovalRulesPage() {
  const [tab, setTab] = React.useState("rules");
  const [tplOpen, setTplOpen] = React.useState(false);
  const [tplDraft, setTplDraft] = React.useState<CustomApprovalRule>(emptyRule());

  const builtinEnabled = BUILTIN_RULES.filter((rule) => !getRuleDisabledMap()[rule.id]).length;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
            <ShieldCheckIcon className="size-5" />
            上报审批
          </h1>
          <p className="text-muted-foreground text-sm">
            报告导出前由 AI 逐条核查：漏洞必须有实际危害证据（命令回显/数据外带/文件读取/写成功），理论漏洞一律拦截。
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>
            内置 {BUILTIN_RULES.length} 条 · 启用 {builtinEnabled} 条
          </span>
        </div>
      </div>

      <Tabs value={tab} onValueChange={setTab} className="gap-4">
        <TabsList>
          <TabsTrigger value="rules">规则库</TabsTrigger>
          <TabsTrigger value="records">审批记录</TabsTrigger>
        </TabsList>
        <TabsContent value="rules">
          <RuleLibrary
            onEditRule={(rule) => {
              setTplDraft({ ...rule, keywords: [...rule.keywords] });
              setTplOpen(true);
            }}
            onDeletedRule={() => setTab("rules")}
          />
        </TabsContent>
        <TabsContent value="records">
          <ReviewRecords />
        </TabsContent>
      </Tabs>

      <RuleEditor
        open={tplOpen}
        onOpenChange={setTplOpen}
        draft={tplDraft}
        onDraftChange={setTplDraft}
        onSaved={() => setTab("rules")}
      />
    </div>
  );
}
