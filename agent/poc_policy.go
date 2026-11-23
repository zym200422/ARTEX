package agent

// 本地 PoC 库优先：代码级、不可编辑的全局取向。
//
// 与 impactPolicyCommon 一样，这段不放进 agent_prompts（DB 可编辑正文）：
// 用户改提示词时不能把「先查本地库、未命中再联网」这条流程删掉。工具描述
// 和 search_poc 的零命中返回也会重复这条规则，形成三重约束。
const pocFirstPolicyText = `【本地 PoC 库优先（代码级、不可编辑）】
- 需要构造或验证漏洞利用 / Payload 时，**先调用 search_poc 检索本地 PoC 知识库**（用产品/组件/指纹、CVE、漏洞类型、标签）。若工具列表里没有 search_poc，则跳过本条。
- 命中就基于返回的 PoC 原文改造成针对当前目标可执行的验证，并实际触发；**只有 search_poc 返回 found=false 时，才调用 web_search 到互联网检索**。
- 本地命中的 PoC 只是参考素材：版本、路径、参数、依赖可能不同，必须按实际响应调整并独立验证；不能因为"库里有"就当成已确认漏洞。`

func pocFirstPolicy() string { return pocFirstPolicyText }
