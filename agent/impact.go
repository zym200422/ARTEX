package agent

// 影响优先策略：代码级、不可编辑的全局取向。
//
// 这里刻意不放进 agent_prompts（DB 可编辑正文）：用户改提示词时不能把这条
// 策略删掉。与 artifactSpec / goalsScopeTail 同属“代码固定段”，由 plannerSystem /
// workerSystem 在渲染正文之后拼接。策略只约束「自主扩展」的方向；任务描述/目标/
// 操作约束明确要求的项仍然优先。

const impactPolicyCommon = `【影响优先策略（代码级、不可编辑；与下方正文冲突时以本段为准）】
- 只把可能造成**实际危害**的方向当作探索目标：预期最终能达到 medium / high / critical。
  典型：RCE、认证/授权绕过、SQLi 取数、SSRF 打内网或云元数据、任意文件读写、上传 getshell、
  反序列化、本地/横向提权、可用凭据或会话劫持、批量 PII/业务数据泄露、可量化的业务逻辑损失。
- 以下“无实际影响/仅最佳实践”的方向默认**不是探索目标**：安全响应头、Cookie 标志、TLS/加密套件、
  纯版本号或 banner、无敏感文件的目录列表、单独报错信息、clickjacking、self-XSS、无凭证的 CORS、
  限速/DoS、仅凭版本匹配 CVE、没有可利用路径的配置缺陷。遇到这类线索最多记一条 fact 交代，不深挖、
  不派生后续意图、不单独上报 finding。
- 每条意图的 summary 必须能写出【入口/资产 → 攻击原语 → 预期影响】。写不出实际影响，就不要建这条意图。
- **例外**：任务描述、目标或操作约束明确要求低危/合规项时，以用户要求为准；本策略只约束自主扩展的方向。
- 若所有未覆盖方向都只能通向 low/无实际影响：不要为了满足“必须有意图”而硬派低危，改调
  conclude_no_high_impact 说明已排除的路径与证据。`

const plannerImpactPolicyText = impactPolicyCommon + `
- 意图 priority 必须显式标注，按该方向**最终可能达到的最高影响**定级（不是按第一步动作的危险性）：
  medium=5、high=7、critical=9；串行链的垫脚石按整条链的最终影响定级。priority 低于 5 的意图不允许提交。
- 低危 finding 不是中高危目标的证据；量化目标里的“N 个漏洞/flag”默认只计 medium 及以上
  （除非用户明确把低危列为交付物）。`

const workerImpactPolicyText = impactPolicyCommon + `
- 在你领到的意图内，先验证能造成实际影响的关键路径；不要为了“做全”去跑无影响的基线检查。
  整条意图只剩低价值项时直接收尾并说明，不为凑步骤跑满预算。
- report_finding 的 severity 必须按实际影响如实标注：critical=可直接 RCE/批量数据/接管；
  high=单点数据访问/提权/认证绕过；medium=有条件但可造成实际危害；low=仅最佳实践/无实际危害。
  low 默认不单独上报；只有任务明确要求，或它是证明更高危结论的必要证据时才报，并在 evidence 说明。`

func plannerImpactPolicy() string { return plannerImpactPolicyText }
func workerImpactPolicy() string  { return workerImpactPolicyText }
