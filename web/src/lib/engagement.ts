// 作战模式（Engagement Mode）领域模型。
//
// 解决的痛点：ARTEX 原先对所有任务只有「描述 + 目标」两个输入，planner 用同一套
// 探索策略应对所有场景 —— SRC 要的是高危可复现、众测要的是抢时间广度、代码审计
// 要的是行号级证据，三套打法混在一起就是「流程冗余」。
//
// 这里把打法拆成三件事：
//   1. 模式（mode）    —— 本次交战的规则：盒型、强度、允许动作、交付物
//   2. 阶段（stage）   —— 有顺序的推进单元，每阶段带准入/准出闸门（gate）
//   3. 演进（evolution）—— 盒型/打法发生变化的触发点，例如：
//        纯黑盒 ──(RCE 拿 shell / 发现 .git 泄露 / 指纹命中开源框架)──▶ 白加黑
//
// 前端先以内置模板落地；任务的真实作战状态由后端按同一结构返回（见 TaskEngagement）。

/** 盒型：我们对目标了解多少。black=零信息，white=有源码。 */
export type BoxType = "black" | "grey" | "white" | "hybrid";

/** 模式分类，用于模式库筛选与图标着色。 */
export type EngagementCategory = "bounty" | "audit" | "offensive" | "compliance" | "lab";

/** 暴露强度：决定是否允许自动化扫描、爆破、高频请求。 */
export type ExposureLevel = "stealth" | "balanced" | "aggressive";

export type GateKind = "artifact" | "evidence" | "approval" | "signal";

export interface StageGate {
  id: string;
  label: string;
  kind: GateKind;
  /** 该闸门的判定口径：满足什么才算过。 */
  criterion: string;
  /** 由人工确认（true）还是 agent 自证（false）。 */
  manual: boolean;
}

export interface EngagementStage {
  id: string;
  name: string;
  /** 流水线上显示的短名（2-4 字）。 */
  short: string;
  /** 本阶段要回答的核心问题，planner 会把它作为阶段目标。 */
  intent: string;
  /** 该阶段主导盒型；同一任务可在不同阶段切换盒型。 */
  box: BoxType;
  /** 允许的动作类别（给人看的白名单摘要，真正的工具开关由任务级拦截规则兜底）。 */
  actions: string[];
  /** 进入下一阶段前必须满足的闸门。 */
  gates: StageGate[];
  /** 本阶段必须落地的交付物（发现/流量/资产/文件）。 */
  deliverables: string[];
  /** 建议的预算占比（整数百分比），用于在 UI 上画预算条。 */
  budget: number;
}

/** 演进触发：命中后建议（或自动）切换盒型 / 模式 / 阶段。 */
export interface EvolutionRule {
  id: string;
  /** 触发信号的通俗描述。 */
  trigger: string;
  /** 可被 agent 匹配的具体信号列表（指纹、文件、命令输出特征等）。 */
  signals: string[];
  /** 命中后前往的阶段（同模式内）——与 to_mode 二选一。 */
  to_stage?: string;
  /** 命中后建议切换到的模式 key。 */
  to_mode?: string;
  /** 命中后的目标盒型；留空表示不变。 */
  to_box?: BoxType;
  /** suggest=只提示；auto=置信度高时自动切换。 */
  action: "suggest" | "auto";
  /** 为什么这条演进能省时间/提命中率。 */
  rationale: string;
}

export interface EngagementMode {
  key: string;
  name: string;
  /** 一句话定位。 */
  tagline: string;
  description: string;
  category: EngagementCategory;
  /** 起始盒型与目标盒型。 */
  entry_box: BoxType;
  target_box: BoxType;
  exposure: ExposureLevel;
  /** 适用场景（什么时候选它）。 */
  fit: string[];
  /** 硬约束：写进 planner 的禁止项，防止越界。 */
  constraints: string[];
  /** 交付物清单。 */
  deliverables: string[];
  stages: EngagementStage[];
  evolutions: EvolutionRule[];
  /** 选择该模式时预填的目标模板。 */
  default_goal: string;
  /** 选择该模式时预填的描述模板。 */
  default_description: string;
  /** 是否建议开启「直接下发首个意图」（CTF 这类一步到位场景）。 */
  seed_first_intent: boolean;
  /** 是否以 URL 清单（url.txt，一行一个 URL）为作业对象。 */
  url_list?: boolean;
  /** 额外的执行纪律（会写入任务简报）。 */
  execution_notes?: string[];
  /** 内置模板不可删；自定义模式可编辑。 */
  builtin: boolean;
}

// ── 盒型元数据 ────────────────────────────────────────────────────────────────

export const BOX_META: Record<BoxType, { label: string; short: string; tone: string; description: string }> = {
  black: {
    label: "纯黑盒",
    short: "黑盒",
    tone: "bg-slate-600 text-white border-slate-600",
    description: "零信息起步：只有域名/IP，靠外部行为推断一切。",
  },
  grey: {
    label: "灰盒",
    short: "灰盒",
    tone: "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30",
    description: "已有凭据、配置片段或内部文档，可跳过部分侦察。",
  },
  white: {
    label: "白盒",
    short: "白盒",
    tone: "bg-sky-500/15 text-sky-700 dark:text-sky-400 border-sky-500/30",
    description: "持有源码，可做数据流追踪与精确到行的验证。",
  },
  hybrid: {
    label: "白加黑",
    short: "白+黑",
    tone: "bg-violet-500/15 text-violet-700 dark:text-violet-400 border-violet-500/30",
    description: "有源码但仍在真实环境验证：白盒定位、黑盒证伪，命中率最高。",
  },
};

export const EXPOSURE_META: Record<ExposureLevel, { label: string; tone: string; hint: string }> = {
  stealth: {
    label: "隐蔽",
    tone: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30",
    hint: "限速、禁用爆破与大规模扫描，避免触发告警。",
  },
  balanced: {
    label: "均衡",
    tone: "bg-sky-500/15 text-sky-700 dark:text-sky-400 border-sky-500/30",
    hint: "默认限速，允许验证性请求，禁止破坏性操作。",
  },
  aggressive: {
    label: "激进",
    tone: "bg-red-500/15 text-red-700 dark:text-red-400 border-red-500/30",
    hint: "允许高频与爆破，仅在明确授权环境使用。",
  },
};

export const CATEGORY_META: Record<EngagementCategory, { label: string; tone: string }> = {
  bounty: { label: "漏洞赏金", tone: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400" },
  audit: { label: "白盒审计", tone: "bg-sky-500/15 text-sky-700 dark:text-sky-400" },
  offensive: { label: "攻击模拟", tone: "bg-red-500/15 text-red-700 dark:text-red-400" },
  compliance: { label: "合规评估", tone: "bg-amber-500/15 text-amber-700 dark:text-amber-400" },
  lab: { label: "靶场竞赛", tone: "bg-violet-500/15 text-violet-700 dark:text-violet-400" },
};

// ── 内置模式 ──────────────────────────────────────────────────────────────────
//
// 六个模板覆盖日常 90% 的场景。每个阶段的闸门都刻意做成「能自证/能审」的形态：
// 没有证据就不能进下一阶段，这正是把流程从「随便探」变成「作战序列」的关键。

const SRC_MODE: EngagementMode = {
  key: "src",
  name: "SRC 漏洞挖掘",
  tagline: "先全量轻量分诊，再按高收益、易验证优先并行打穿",
  description:
    "面向厂商 SRC / 漏洞赏金计划的清单式挖掘。先解析去重，再对清单内每个 URL 做一次低频、只读的轻量指纹分诊，标注应用/技术栈、可达性、易中难和验证优先级；随后按预期收益高且容易验证者优先派发。不同 URL 可由多个 worker 并行验证，同一规范化 URL 同时只允许一个 worker，避免重复；每个 URL 最终都要有结论（有漏洞 / 无发现 / 不可达）。分诊不是漏洞扫描，不做跨目标资产扩展。",
  category: "bounty",
  entry_box: "black",
  target_box: "hybrid",
  exposure: "stealth",
  url_list: true,
  fit: [
    "甲方/项目方直接提供 url.txt 清单的 SRC 项目",
    "需要逐个 URL 出结论、可核对的批量测试",
    "对业务影响敏感、禁止大规模扫描的生产环境",
  ],
  constraints: [
    "以描述中附带的 url.txt 为唯一作业对象：逐行读取、规范化、去重，并保留原始序号；不扩展清单外目标",
    "先完成全清单轻量分诊：每个 URL 只做低频、只读的可达性/标题/响应头/技术栈识别；分诊不是漏洞测试，不发送漏洞 payload",
    "分诊后按预期收益与验证难度排序：高收益、容易确认的 URL 优先；同等级按原始序号稳定排序，不因优先级调整而遗漏 URL",
    "不同 URL 可由不同 worker 并行验证；同一规范化 URL 同一时间只能有一个 worker 处理，避免重复请求",
    "禁止跨 URL 批量发送漏洞 payload、Fuzz、爆破或利用请求；仅允许分诊阶段对清单内 URL 做低频、只读指纹请求",
    "每个 URL 最终必须落一条结论（有漏洞 / 无发现 / 不可达）；未完成的 URL 保留在队列中，不得伪报完成",
    "每完成 10 个 URL 汇报一次进度（已完成 / 总数），并按原始序号输出最终结果表",
    "禁止任何破坏性、拒绝服务类操作；禁止写入 webshell 或留下持久化后门",
    "禁止访问与漏洞无关的用户真实数据，读取量以证明漏洞为限",
    "对单个 URL 遵守授权范围和低频限速，禁用目录爆破字典以外的暴力枚举",
  ],
  execution_notes: [
    "url.txt 的绝对路径在任务描述的「上传文件」清单里；先 Read 该文件，不要凭记忆猜 URL。",
    "第一轮只做清单规范化和轻量分诊：每个 URL 记录原始序号、可达性、标题/响应头/技术栈线索、应用类型、难度（易/中/难）和验证优先级；每个 URL 至多一次低频只读请求，确有必要才补一次。",
    "分诊只记录观察，不把版本匹配或指纹命中当漏洞；优先级综合潜在影响、可达入口、已知技术栈/公开源码线索、验证成本和授权限制。",
    "分诊完成后建立排序队列：先验证预期收益高且容易验证的 URL，再处理中等、困难项；优先级相同则按原始序号，所有有效 URL 最终都要有结论。",
    "分诊结束时用 record_fact 记一条 summary 含「SRC分诊完成」的事实（附分诊表位置与统计），让阶段的「已分类/已排序」闸门可以由数据推进。",
    "验证队列按收益/难度优先级派发，最多使用 SRC worker 池并发数处理不同 URL；同一规范化 URL 只能有一个 worker 占用，完成后释放该 URL。分诊顺序可不同于文件顺序，但保留原始序号。", 
    "发现漏洞时立即记录请求/响应与影响面，再完成当前 URL 的结论；不要因此丢弃队列里其他 URL。",
    "全部 URL 处理完后，输出一张「原始序号 / URL / 分类 / 难度 / 优先级 / 结论 / 漏洞数」结果表。",
    "【重要】分诊或验证阶段一旦认出目标属于公开项目/靶场（pikachu、DVWA、bWAPP、WebGoat、Juice Shop、Vulhub 等），立即获取其公开源码转白盒：定位到具体文件与行号，构造精确 payload 再回线上验证（白加黑）。不要因为 url.txt 没给源码路径就在黑盒里盲猜参数。",
    "获取源码的合法途径：GitHub 公开仓库克隆、目标泄露的 .git/备份包、容器镜像内的源码目录。拿到源码后在报告里给出「文件:行号」级证据。",
  ],
  deliverables: ["URL 测试结果表（每个 URL 的结论）", "可复现漏洞报告（请求/响应）", "修复建议"],
  default_description:
    "对描述中附带的 url.txt 清单进行 SRC 漏洞挖掘。清单每行一个 URL；先逐行解析、去重，再对全清单做低频只读分诊并按收益/难度排序，优先验证高收益且容易确认的 URL，随后处理较难项；保留原序号并确保每个 URL 最终有结论。",
  default_goal:
    "先完成 url.txt 全清单的轻量分类（应用/技术栈、可达性、易中难、验证优先级），再按预期收益高且验证容易者优先逐个验证；为每个 URL 输出明确结论（有漏洞 / 无发现 / 不可达），有漏洞的提供可复现证据与修复建议。",
  seed_first_intent: false,
  builtin: true,
  stages: [
    {
      id: "src-intake",
      name: "清单解析与队列建立",
      short: "清单",
      intent: "读取 url.txt，逐行规范化、去重、剔除越界项，建立带编号与状态的待测队列。",
      box: "black",
      actions: ["读取 url.txt", "URL 规范化", "去重", "剔除越界/无效项", "生成带序号的队列"],
      gates: [
        {
          id: "src-intake-read",
          label: "清单已读取并统计",
          kind: "artifact",
          criterion: "已读取 url.txt，记录原始行数、去重后有效 URL 数，并在黑板中保存队列。",
          manual: false,
        },
        {
          id: "src-intake-queue",
          label: "队列已建立",
          kind: "evidence",
          criterion: "每个 URL 有序号与初始状态（待测）；无效/越界项已剔除并说明原因。",
          manual: false,
        },
      ],
      deliverables: ["URL 队列（序号 / URL / 状态）"],
      budget: 5,
    },
    {
      id: "src-triage",
      name: "全清单轻量分诊",
      short: "分诊",
      intent: "对 url.txt 中每个 URL 做低频只读指纹，不发漏洞 payload；标注应用/技术栈、可达性、易中难和预期收益/验证优先级，然后稳定排序。",
      box: "black",
      actions: ["每 URL 一次只读请求", "标题/响应头/技术栈识别", "易中难分类", "收益与验证成本排序"],
      gates: [
        {
          id: "src-triage-classified",
          label: "有效 URL 已完成分类",
          kind: "artifact",
          criterion: "每个有效 URL 都有可达性、应用/技术栈、难度（易/中/难）和验证优先级；分诊未做漏洞验证。",
          manual: true,
        },
        {
          id: "src-triage-ordered",
          label: "验证队列已按优先级排序",
          kind: "artifact",
          criterion: "高收益且容易验证的 URL 排前面，同优先级按原始序号；原序号保留且无 URL 遗漏。",
          manual: true,
        },
      ],
      deliverables: ["URL 分诊表（原序号 / URL / 指纹 / 易中难 / 优先级）", "按优先级排序的验证队列"],
      budget: 10,
    },
    {
      id: "src-recon",
      name: "优先 URL 定向侦察",
      short: "定向侦察",
      intent: "按分诊优先级并行派发不同 URL 的定向侦察与验证；同一规范化 URL 同时只允许一个 worker 处理，每条意图只覆盖一个 URL。", 
      box: "black",
      actions: ["单 URL 连通性", "定向入口识别", "限速参数枚举", "角色/鉴权识别"],
      gates: [
        {
          id: "src-recon-current",
          label: "当前优先 URL 侦察完成",
          kind: "evidence",
          criterion: "当前最高优先级待测 URL 的可达入口和验证方向已记录；其他 URL 不做漏洞探测。",
          manual: false,
        },
        {
          id: "src-recon-serial",
          label: "同 URL 不重复并发",
          kind: "approval",
          criterion: "不同 URL 可并行；同一规范化 URL 同一时刻最多一个 worker 处理。",
          manual: true,
        },
      ],
      deliverables: ["优先 URL 定向侦察记录"],
      budget: 25,
    },
    {
      id: "src-verify",
      name: "逐 URL 漏洞验证",
      short: "逐条验证",
      intent: "对分诊队列中的 URL 并行验证（每条意图只验证一个 URL）：不同 URL 可同时进行，同一 URL 不重复派发；写回该 URL 结论后释放该 URL。",
      box: "black",
      actions: ["参数 Fuzz", "越权测试", "鉴权绕过", "注入验证", "文件上传验证"],
      gates: [
        {
          id: "src-verify-conclusion",
          label: "当前 URL 有结论",
          kind: "evidence",
          criterion: "该 URL 已标记为「有漏洞 / 无发现 / 不可达」之一；无发现与不可达需记录判断依据。",
          manual: false,
        },
        {
          id: "src-verify-proof",
          label: "漏洞证据完整",
          kind: "evidence",
          criterion: "该 URL 下每个确认漏洞都有可回放的请求/响应；影响面已界定且未超出证明所需数据量。",
          manual: true,
        },
      ],
      deliverables: ["单 URL 结论", "漏洞流量证据"],
      budget: 45,
    },
    {
      id: "src-report",
      name: "队列汇总与交付",
      short: "汇总",
      intent: "汇总全部 URL 的结论，按模板整理漏洞报告与 URL 测试结果表。",
      box: "hybrid",
      actions: ["核对队列无遗漏", "生成 URL 结果表", "整理漏洞报告", "自检去重"],
      gates: [
        {
          id: "src-report-queue",
          label: "队列全部处理完",
          kind: "artifact",
          criterion: "队列中不存在「待测 / 进行中」的 URL；总数与结论数一致。",
          manual: true,
        },
        {
          id: "src-report-ready",
          label: "报告可提交",
          kind: "artifact",
          criterion: "报告含标题/等级/复现/影响/修复建议，且与发现记录一一对应。",
          manual: true,
        },
      ],
      deliverables: ["URL 测试结果表", "漏洞报告"],
      budget: 10,
    },
  ],
  evolutions: [
    {
      id: "src-evo-leak",
      trigger: "某个 URL 发现 .git / 备份文件 / 源码泄露",
      signals: [".git/config", ".svn/entries", "www.zip", "backup.tar.gz", "源码目录可列"],
      to_mode: "code-audit",
      to_box: "white",
      action: "auto",
      rationale: "拿到源码后可直接定位可利用链，比在黑盒里猜参数命中率高一个数量级；其余 URL 继续按队列测试。",
    },
    {
      id: "src-evo-fingerprint",
      trigger: "某个 URL 指纹命中开源框架且版本已知",
      signals: ["Shiro", "Fastjson", "ThinkPHP", "Spring Boot", "JeecgBoot", "Struts2", "Jenkins", "Confluence"],
      to_mode: "greybox",
      to_box: "hybrid",
      action: "suggest",
      rationale: "已知版本的开源组件可对照公开补丁做定点验证；仅对命中该指纹的 URL 适用，不改变队列顺序。",
    },
    {
      id: "src-evo-shell",
      trigger: "某个 URL 获得命令执行 / 上传成功拿到 shell",
      signals: ["id 回显", "whoami 回显", "webshell 访问成功", "反弹 shell 上线"],
      to_stage: "src-verify",
      to_box: "grey",
      action: "suggest",
      rationale: "拿到执行权限后视野从外部转为内部，可读取配置与源码；先记录该 URL 结论，再决定是否转灰盒。",
    },
  ],
};

const CROWDTEST_MODE: EngagementMode = {
  key: "crowdtest",
  name: "众测冲刺",
  tagline: "按漏洞类型抢首杀：高危优先，确认即提交，绝不重复投入",
  description:
    "面向限时众测项目。多数厂商按漏洞类型取「第一个上报」计分（首杀制）：每个类型只认第一个提交的人。打法必须是——先建「漏洞类型×资产」矩阵，高危类型优先，单点快速验证，确认即提交抢首杀，然后立刻切下一个类型；已抢到的类型绝不回头深挖。",
  category: "bounty",
  entry_box: "black",
  target_box: "grey",
  exposure: "balanced",
  fit: [
    "按漏洞类型首杀计分的众测项目（同类型只认第一个上报）",
    "有明确时间窗、需要快速产出多个不同类型漏洞的项目",
    "资产多、需要广度铺开抢窗口期",
  ],
  constraints: [
    "按「漏洞类型」抢首杀：每个类型只提交第一个确认漏洞，同类型已提交后立即切换下一类型，禁止重复投入",
    "高危类型优先：RCE/命令注入/SQLi/越权/任意文件上传/敏感信息泄露，低危类型放加时补扫",
    "确认即提交：证据满足最小可复现（请求/响应+影响说明）就提交，不等完美报告",
    "发现疑似重复（已被他人提交/已有同类型首杀）立即放弃该组合，转向未覆盖的类型×资产",
    "禁止破坏性验证，所有 PoC 必须可回滚；遵守平台限速与工具白名单",
    "并发控制在 20–30 之间（限时赛要抢速度，但高于 30 容易触发 WAF/封禁，反而更慢）",
  ],
  execution_notes: [
    "先读计分规则：确认哪些类型按首杀计分、哪些有数量上限，据此排类型优先级。",
    "建立「漏洞类型×资产」矩阵：行=目标类型（高危优先），列=资产/入口；每格状态：待测/进行中/已确认/已提交。",
    "队列规则：一次只聚焦一个「类型×资产」组合，优先取高危且大概率未被抢的组合；确认后立即提交。",
    "该类型首杀到手后立即标记完成，绝不回头深挖；重复投入同类型=浪费窗口期。",
    "提交材料按模板五段：漏洞标题/危害/描述/复现（请求+响应）/修复建议，先达标再补细节。",
    "认出目标是公开项目/靶场（pikachu、DVWA、Juice Shop、Vulhub 等）时，直接取公开源码定位到行，比盲猜快得多——这是限时赛里最划算的投入。",
    "并发 20–30：抢首杀需要速度，但超过 30 会触发 WAF 拦截/账号封禁，反而丢掉窗口期。",
  ],
  deliverables: ["类型首杀清单（每类型第一条漏洞）", "合格漏洞报告", "类型×资产覆盖矩阵"],
  default_description:
    "限时众测项目冲刺。厂商按漏洞类型首杀计分：先建「漏洞类型×资产」矩阵，高危类型优先（RCE/SQLi/越权/上传/敏感信息），单点快速验证，确认即提交抢首杀，同类型绝不重复投入。",
  default_goal:
    "按漏洞类型各抢一个首杀：优先 RCE/SQLi/越权/任意文件上传/敏感信息等高危类型，每个类型确认 1 个即提交并切换下一类型。",
  seed_first_intent: false,
  builtin: true,
  stages: [
    {
      id: "ct-scope",
      name: "规则与首杀解读",
      short: "规则",
      intent: "读清计分与首杀规则，产出「目标漏洞类型清单」并按分值×出洞概率×被抢风险排序。",
      box: "black",
      actions: ["读取项目规则", "确认首杀计分类型", "高危类型排序", "标记低价值面"],
      gates: [
        {
          id: "ct-scope-types",
          label: "类型清单已排序",
          kind: "artifact",
          criterion: "已产出目标漏洞类型清单（高危优先），并标注每个类型的计分/首杀规则。",
          manual: true,
        },
        {
          id: "ct-scope-assets",
          label: "类型×资产矩阵已建立",
          kind: "artifact",
          criterion: "每个类型已映射到候选资产/入口，形成带状态的类型×资产矩阵。",
          manual: false,
        },
      ],
      deliverables: ["类型×资产矩阵", "首杀优先级清单"],
      budget: 5,
    },
    {
      id: "ct-type-fire",
      name: "逐类型快打",
      short: "快打",
      intent: "一次只攻一个「类型×资产」组合：快速定位该类型的高危点并验证，确认后立即转入提交。",
      box: "black",
      actions: ["指纹/入口快筛", "该类型定向 Fuzz", "快速验证", "最小化 PoC"],
      gates: [
        {
          id: "ct-type-current",
          label: "当前组合有结论",
          kind: "evidence",
          criterion: "当前「类型×资产」组合已有结论：确认漏洞 / 无发现 / 不可达；未完成不得切换组合。",
          manual: false,
        },
        {
          id: "ct-type-first",
          label: "高危类型优先推进",
          kind: "evidence",
          criterion: "队列严格按「高危优先且未被抢」取下一个组合；已确认的类型不再重复投入。",
          manual: false,
        },
      ],
      deliverables: ["逐组合测试记录", "最小化 PoC"],
      budget: 55,
    },
    {
      id: "ct-submit",
      name: "抢首杀提交",
      short: "提交",
      intent: "确认即提交：按模板五段（标题/危害/描述/复现/修复）快速成稿提交，抢占首杀并标记类型完成。",
      box: "grey",
      actions: ["生成最小报告", "自检重复", "提交", "标记类型完成"],
      gates: [
        {
          id: "ct-submit-proof",
          label: "最小可复现证据",
          kind: "evidence",
          criterion: "提交材料含请求/响应与影响说明，满足平台最低要求；先达标再补细节。",
          manual: false,
        },
        {
          id: "ct-submit-type-done",
          label: "类型标记完成",
          kind: "artifact",
          criterion: "已提交的类型在矩阵中标记完成，队列切换到下一个未覆盖类型。",
          manual: false,
        },
      ],
      deliverables: ["已提交报告", "类型完成标记"],
      budget: 25,
    },
    {
      id: "ct-mopup",
      name: "加时补扫",
      short: "加时",
      intent: "时间窗允许时补扫低优先类型、加深已提交漏洞的影响链，进一步提高总分。",
      box: "grey",
      actions: ["低优先类型补扫", "影响链加深", "补充利用"],
      gates: [
        {
          id: "ct-mopup-time",
          label: "窗口结束前收口",
          kind: "approval",
          criterion: "时间窗结束前停止新测试，确保已确认漏洞全部提交、材料完整。",
          manual: true,
        },
      ],
      deliverables: ["加时补扫记录"],
      budget: 15,
    },
  ],
  evolutions: [
    {
      id: "ct-evo-firstblood",
      trigger: "某类型高危漏洞已确认并提交（首杀到手）",
      signals: ["提交成功", "首杀到手", "类型标记完成"],
      to_stage: "ct-type-fire",
      action: "auto",
      rationale: "首杀到手后继续深挖同类型是零分投入，应立即切到下一个未覆盖的高危类型。",
    },
    {
      id: "ct-evo-duplicate",
      trigger: "疑似已被他人提交（重复）",
      signals: ["平台提示重复", "公开披露", "扫描器指纹命中"],
      to_stage: "ct-type-fire",
      action: "auto",
      rationale: "重复提交不计分，立即转向未覆盖的「类型×资产」组合。",
    },
    {
      id: "ct-evo-source",
      trigger: "命中开放源码 / 泄露源码",
      signals: [".git 泄露", "开源组件指纹", "源码包暴露"],
      to_mode: "code-audit",
      to_box: "white",
      action: "suggest",
      rationale: "源码能把验证成本降到最低，在限时赛里是最划算的投入；确认后回到队列继续抢其他类型。",
    },
  ],
};

const CODE_AUDIT_MODE: EngagementMode = {
  key: "code-audit",
  name: "源码审计",
  tagline: "从入口到 Sink 追数据流，只报告能走到利用链的问题",
  description:
    "纯白盒源码审计。以「可控输入 → 危险汇聚点」的数据流为主线，结合框架路由与鉴权中间件判断可达性，最后在真实环境回放验证。产出必须精确到文件与行号。",
  category: "audit",
  entry_box: "white",
  target_box: "hybrid",
  exposure: "stealth",
  fit: ["拿到完整源码的授权审计", "需要精确到行号的修复建议", "开源项目漏洞挖掘"],
  constraints: [
    "源码与数据不得外传，禁止提交到公网仓库",
    "在本地/隔离环境复现，禁止直接对生产环境发包验证",
    "报告必须标注真实可达性，不把「理论存在」当「可利用」",
  ],
  deliverables: ["数据流图", "可利用漏洞清单（含文件:行号）", "修复补丁建议"],
  default_description: "对提供的源码进行白盒审计，追踪可控输入到危险汇聚点的数据流，输出带行号的可利用链。",
  default_goal: "找出至少 1 条从外部可控输入到危险操作的完整利用链，并给出修复方案。",
  seed_first_intent: false,
  builtin: true,
  stages: [
    {
      id: "ca-intake",
      name: "源码与运行时摸底",
      short: "摸底",
      intent: "确认代码版本、依赖清单、部署形态，建立可审计的基线。",
      box: "white",
      actions: ["拉取源码", "解析依赖", "识别框架与中间件", "确认入口形态"],
      gates: [
        {
          id: "ca-intake-dep",
          label: "依赖清单与版本已产出",
          kind: "artifact",
          criterion: "已生成依赖清单（语言生态对应 lock 文件），标注高危组件版本。",
          manual: false,
        },
        {
          id: "ca-intake-entry",
          label: "入口形态已确认",
          kind: "evidence",
          criterion: "已确认 HTTP 入口、鉴权中间件与路由注册方式。",
          manual: false,
        },
      ],
      deliverables: ["依赖清单", "入口清单"],
      budget: 10,
    },
    {
      id: "ca-map",
      name: "路由与鉴权测绘",
      short: "测绘",
      intent: "把全部可外部触达的路由、鉴权装饰、参数绑定方式梳理成攻击面地图。",
      box: "white",
      actions: ["路由枚举", "鉴权装饰分析", "参数绑定分析", "文件上传点定位"],
      gates: [
        {
          id: "ca-map-coverage",
          label: "无鉴权路由已穷举",
          kind: "evidence",
          criterion: "所有未挂鉴权中间件的路由已列出，标注其参数来源。",
          manual: false,
        },
      ],
      deliverables: ["路由鉴权矩阵"],
      budget: 20,
    },
    {
      id: "ca-sink",
      name: "危险汇聚点扫描",
      short: "Sink",
      intent: "围绕 SQL / 命令 / 反序列化 / 模板 / 文件 / SSRF 等汇聚点做定向检索。",
      box: "white",
      actions: ["危险函数检索", "第三方组件漏洞匹配", "补丁 diff 对照"],
      gates: [
        {
          id: "ca-sink-list",
          label: "Sink 清单完成",
          kind: "artifact",
          criterion: "六大类汇聚点均已检索，命中项标注文件与行号。",
          manual: false,
        },
      ],
      deliverables: ["Sink 清单"],
      budget: 20,
    },
    {
      id: "ca-flow",
      name: "数据流追踪",
      short: "追踪",
      intent: "从可控输入向 Sink 追踪，排除过滤与转义，只保留真实可达链路。",
      box: "white",
      actions: ["污点追踪", "过滤器绕过分析", "编码/解码链路还原"],
      gates: [
        {
          id: "ca-flow-chain",
          label: "至少 1 条完整可控链路",
          kind: "evidence",
          criterion: "给出 source→sink 的完整调用链，标注过滤点与其绕过方式。",
          manual: false,
        },
      ],
      deliverables: ["数据流图", "候选利用链"],
      budget: 30,
    },
    {
      id: "ca-verify",
      name: "隔离环境复现",
      short: "复现",
      intent: "在本地/隔离环境构造最小 PoC，把静态结论变成可执行证据。",
      box: "hybrid",
      actions: ["本地部署", "构造 payload", "抓包留证"],
      gates: [
        {
          id: "ca-verify-poc",
          label: "PoC 可稳定复现",
          kind: "evidence",
          criterion: "同环境连续两次以上成功执行，流量与日志齐全。",
          manual: false,
        },
      ],
      deliverables: ["PoC 脚本", "复现流量"],
      budget: 15,
    },
    {
      id: "ca-report",
      name: "代码级报告",
      short: "报告",
      intent: "输出带文件:行号、调用链、修复补丁的报告。",
      box: "hybrid",
      actions: ["撰写报告", "生成修复补丁"],
      gates: [
        {
          id: "ca-report-done",
          label: "报告与补丁齐备",
          kind: "artifact",
          criterion: "每条漏洞含文件:行号、调用链、PoC、修复 diff。",
          manual: true,
        },
      ],
      deliverables: ["审计报告", "修复补丁"],
      budget: 5,
    },
  ],
  evolutions: [
    {
      id: "ca-evo-deploy",
      trigger: "发现源码对应线上实例",
      signals: ["配置文件中生产域名", "发布脚本", "CI 配置"],
      to_mode: "greybox",
      to_box: "hybrid",
      action: "suggest",
      rationale: "白盒结论在真实实例上验证，可确认可达性并获得真实影响面。",
    },
  ],
};

const GREYBOX_MODE: EngagementMode = {
  key: "greybox",
  name: "白加黑联动",
  tagline: "白盒定位、黑盒证伪：用源码把利用链一次打穿",
  description:
    "白加黑模式：已有源码（或部分源码）+ 真实运行环境。白盒负责定位与构造精确 payload，黑盒负责验证可达性与真实影响。两者交替推进，是投入产出比最高的打法。",
  category: "audit",
  entry_box: "hybrid",
  target_box: "hybrid",
  exposure: "balanced",
  fit: ["可拿到源码同时能访问真实环境", "SRC 中命中开源组件后转白盒", "需要证明真实影响面的代码审计"],
  constraints: [
    "真实环境验证前必须确认授权与限速",
    "禁止在生产环境执行破坏性 payload",
    "源码版本必须与线上版本一致，不一致处需显式标注",
  ],
  deliverables: ["白盒定位清单", "黑盒验证流量", "真实影响面报告"],
  default_description: "白加黑联动评估：白盒读源码定位漏洞，黑盒在真实环境验证可达性与影响面。",
  default_goal: "产出至少 1 条「源码定位 + 线上验证」闭环的漏洞证据链。",
  seed_first_intent: false,
  builtin: true,
  stages: [
    {
      id: "gb-sync",
      name: "源码与实例对齐",
      short: "对齐",
      intent: "确认线上版本与源码版本一致，建立「代码行 ↔ 线上行为」映射。",
      box: "hybrid",
      actions: ["版本比对", "指纹核对", "配置对照"],
      gates: [
        {
          id: "gb-sync-done",
          label: "版本一致性已确认",
          kind: "evidence",
          criterion: "源码版本与线上指纹一致；不一致处已标注影响范围。",
          manual: false,
        },
      ],
      deliverables: ["版本对照表"],
      budget: 10,
    },
    {
      id: "gb-locate",
      name: "白盒定位可疑点",
      short: "定位",
      intent: "从源码中圈定 3-5 个最可能可达的高危点，排出验证顺序。",
      box: "white",
      actions: ["数据流追踪", "补丁 diff", "危险函数定位"],
      gates: [
        {
          id: "gb-locate-list",
          label: "验证清单已排序",
          kind: "artifact",
          criterion: "可疑点按「可达概率 × 危害」排序，每个含文件:行号。",
          manual: false,
        },
      ],
      deliverables: ["待验证清单"],
      budget: 25,
    },
    {
      id: "gb-verify",
      name: "黑盒线上验证",
      short: "验证",
      intent: "用白盒给出的精确 payload 在真实环境验证，确认可达性与影响。",
      box: "hybrid",
      actions: ["定向发包", "绕过 WAF", "影响面取证"],
      gates: [
        {
          id: "gb-verify-proof",
          label: "闭环证据链",
          kind: "evidence",
          criterion: "源码位置 + 线上请求/响应 + 影响证明三者齐全。",
          manual: true,
        },
      ],
      deliverables: ["验证流量", "影响面证明"],
      budget: 45,
    },
    {
      id: "gb-report",
      name: "闭环报告",
      short: "报告",
      intent: "把白盒定位与黑盒证据合并成一份闭环报告。",
      box: "hybrid",
      actions: ["撰写报告", "附源码片段与流量"],
      gates: [
        {
          id: "gb-report-done",
          label: "报告含双层证据",
          kind: "artifact",
          criterion: "每条漏洞同时给出源码位置与线上验证流量。",
          manual: true,
        },
      ],
      deliverables: ["闭环报告"],
      budget: 20,
    },
  ],
  evolutions: [
    {
      id: "gb-evo-source",
      trigger: "发现源码版本与线上不一致",
      signals: ["指纹版本不同", "代码分支差异"],
      to_mode: "code-audit",
      to_box: "white",
      action: "suggest",
      rationale: "先回到纯白盒把代码审计透彻，避免用错版本得出错误结论。",
    },
  ],
};

const REDTEAM_MODE: EngagementMode = {
  key: "redteam",
  name: "红队攻击模拟",
  tagline: "以目标资产失陷为成功标准，模拟真实攻击者链路",
  description:
    "面向红蓝对抗的攻击模拟。不追求漏洞数量，只追求「打穿」：外网立足、权限维持、内网横移、目标达成。强调隐蔽性和可复盘的攻击链路。",
  category: "offensive",
  entry_box: "black",
  target_box: "grey",
  exposure: "stealth",
  fit: ["红蓝对抗演练", "以打穿核心系统为验收标准", "需要检验蓝队检测能力"],
  constraints: [
    "严禁触碰工控、医疗等生命线系统",
    "所有持久化操作需登记并在结束后清理",
    "禁止使用真实钓鱼邮件，社工演练须走审批",
    "操作留痕：每条命令、每个上传文件必须可追溯",
  ],
  deliverables: ["攻击链路图", "失陷资产清单", "检测规避复盘"],
  default_description: "红队攻击模拟：以打穿目标核心资产为成功标准，输出完整攻击链路与检测复盘。",
  default_goal: "拿下至少 1 个边界系统并形成可复盘的攻击链，最终触达核心目标。",
  seed_first_intent: false,
  builtin: true,
  stages: [
    {
      id: "rt-foothold",
      name: "外网立足",
      short: "立足",
      intent: "通过暴露面找到一个可执行代码/可登录的入口，取得第一个据点。",
      box: "black",
      actions: ["暴露面测绘", "边界漏洞利用", "弱口令", "供应链入口"],
      gates: [
        {
          id: "rt-foothold-done",
          label: "取得可交互据点",
          kind: "evidence",
          criterion: "获得命令执行、可用凭据或可登录的后台权限之一，并留存证据。",
          manual: true,
        },
      ],
      deliverables: ["据点清单", "入口漏洞证据"],
      budget: 35,
    },
    {
      id: "rt-persist",
      name: "权限维持",
      short: "维持",
      intent: "建立稳定的回连通道，保证后续操作不因单点失效而中断。",
      box: "grey",
      actions: ["建立隧道", "凭据收集", "计划任务/服务"],
      gates: [
        {
          id: "rt-persist-done",
          label: "稳定通道可用",
          kind: "evidence",
          criterion: "至少一条独立于初始漏洞的回连通道可用，且已登记。",
          manual: true,
        },
      ],
      deliverables: ["通道登记表", "凭据清单"],
      budget: 15,
    },
    {
      id: "rt-enum",
      name: "内网侦察",
      short: "侦察",
      intent: "以据点为跳板测绘内网：网段、主机、域控、可达服务。",
      box: "grey",
      actions: ["内网存活探测", "端口服务识别", "域信息收集", "凭据喷洒"],
      gates: [
        {
          id: "rt-enum-map",
          label: "内网拓扑已成型",
          kind: "artifact",
          criterion: "内网资产图含存活主机与关键服务，标注通往目标的最短路径。",
          manual: false,
        },
      ],
      deliverables: ["内网资产图", "路径规划"],
      budget: 20,
    },
    {
      id: "rt-lateral",
      name: "横向移动",
      short: "横向",
      intent: "利用凭据与漏洞逐跳推进，直到触达任务目标资产。",
      box: "grey",
      actions: ["凭据复用", "远程执行", "票据利用", "跳板搭建"],
      gates: [
        {
          id: "rt-lateral-target",
          label: "触达目标资产",
          kind: "evidence",
          criterion: "取得目标任务所要求的主机/系统的控制权，并留存证据。",
          manual: true,
        },
      ],
      deliverables: ["横移路径", "目标控制证据"],
      budget: 25,
    },
    {
      id: "rt-report",
      name: "链路复盘",
      short: "复盘",
      intent: "整理完整攻击链、蓝队检测盲区与清理记录。",
      box: "grey",
      actions: ["链路还原", "检测复盘", "后门清理"],
      gates: [
        {
          id: "rt-report-done",
          label: "链路与清理均完成",
          kind: "artifact",
          criterion: "攻击链可逐步复述；所有持久化后门已确认清理。",
          manual: true,
        },
      ],
      deliverables: ["攻击链路图", "清理确认单"],
      budget: 5,
    },
  ],
  evolutions: [
    {
      id: "rt-evo-source",
      trigger: "据点主机上发现源码或构建产物",
      signals: ["/var/www 源码", "jar/war 包", "CI 配置", "构建脚本"],
      to_mode: "code-audit",
      to_box: "white",
      action: "auto",
      rationale: "从据点主机拿到的源码可直接审计，快速找到通往核心系统的下一跳漏洞。",
    },
    {
      id: "rt-evo-dc",
      trigger: "触达域控或核心数据库",
      signals: ["域控可登录", "数据库可达", "堡垒机"],
      to_stage: "rt-report",
      to_box: "grey",
      action: "auto",
      rationale: "目标已达成，继续横移只会扩大影响面，应立即转入复盘与清理。",
    },
  ],
};

const CTF_MODE: EngagementMode = {
  key: "ctf",
  name: "CTF 竞赛",
  tagline: "单题单目标，先拿到 flag 再谈优雅",
  description:
    "面向 CTF 靶场的解题模式。目标唯一：拿到 flag。允许激进手段，鼓励直接下发首个意图让 worker 立刻开跑，跳过冗长的规划阶段。",
  category: "lab",
  entry_box: "black",
  target_box: "hybrid",
  exposure: "aggressive",
  fit: ["CTF 赛事解题", "靶场练习", "单点目标快速验证"],
  constraints: ["仅在比赛/靶场环境使用", "禁止对赛题以外的资产发起任何请求"],
  deliverables: ["flag", "解题思路", "writeup"],
  default_description: "CTF 解题：目标靶场 / 题目说明如下，拿到 flag 即可。",
  default_goal: "在最短时间内拿到 flag，并整理可复现的解题思路。",
  seed_first_intent: true,
  builtin: true,
  stages: [
    {
      id: "ctf-recon",
      name: "情报收集",
      short: "情报",
      intent: "快速判定题型与入口：Web / Pwn / 逆向 / 杂项。",
      box: "black",
      actions: ["端口与路径探测", "附件分析", "源码泄露检查"],
      gates: [
        {
          id: "ctf-recon-type",
          label: "题型已判定",
          kind: "evidence",
          criterion: "明确题型与首选攻击方向，记录依据。",
          manual: false,
        },
      ],
      deliverables: ["题型判定"],
      budget: 15,
    },
    {
      id: "ctf-exploit",
      name: "利用与提权",
      short: "利用",
      intent: "沿判定方向构造并迭代利用，直到拿到 flag。",
      box: "black",
      actions: ["漏洞利用", "绕过 WAF", "RCE", "文件读取"],
      gates: [
        {
          id: "ctf-exploit-flag",
          label: "flag 已获取",
          kind: "evidence",
          criterion: "拿到符合格式的 flag 并完成校验。",
          manual: false,
        },
      ],
      deliverables: ["flag", "利用脚本"],
      budget: 70,
    },
    {
      id: "ctf-writeup",
      name: "Writeup",
      short: "复盘",
      intent: "整理可复现的解题步骤与关键 payload。",
      box: "hybrid",
      actions: ["撰写 writeup"],
      gates: [
        {
          id: "ctf-writeup-done",
          label: "writeup 可复现",
          kind: "artifact",
          criterion: "他人可照 writeup 复现 flag。",
          manual: true,
        },
      ],
      deliverables: ["writeup"],
      budget: 15,
    },
  ],
  evolutions: [],
};

const COMPLIANCE_MODE: EngagementMode = {
  key: "compliance",
  name: "合规基线评估",
  tagline: "以等保/行业基线为准绳，产出可交付的差距清单",
  description:
    "面向等保测评、行业监管要求的合规评估。以基线核查为主、渗透验证为辅，强调可审计、可交付、可整改，不做超出基线范围的深度利用。",
  category: "compliance",
  entry_box: "grey",
  target_box: "grey",
  exposure: "stealth",
  fit: ["等保测评前的自查", "监管检查前的合规差距梳理", "需要整改工单的甲方项目"],
  constraints: [
    "严格按基线条目核查，不做基线外的深度利用",
    "所有核查项必须留存截图或命令输出",
    "不得修改目标配置，整改建议由甲方执行",
  ],
  deliverables: ["基线核查表", "差距清单", "整改建议工单"],
  default_description: "按等保/行业基线对目标做合规评估，逐项核查并输出差距与整改建议。",
  default_goal: "完成全部基线条目核查，输出可交付的差距清单与整改建议。",
  seed_first_intent: false,
  builtin: true,
  stages: [
    {
      id: "cp-asset",
      name: "资产与定级确认",
      short: "定级",
      intent: "确认系统定级、边界与资产清单，明确核查范围。",
      box: "grey",
      actions: ["资产盘点", "定级确认", "边界确认"],
      gates: [
        {
          id: "cp-asset-done",
          label: "范围确认单签署",
          kind: "approval",
          criterion: "资产清单与定级结果经甲方确认。",
          manual: true,
        },
      ],
      deliverables: ["资产清单", "范围确认单"],
      budget: 15,
    },
    {
      id: "cp-baseline",
      name: "基线逐项核查",
      short: "核查",
      intent: "按基线条目核查主机/应用/数据/管理四个层面。",
      box: "grey",
      actions: ["配置核查", "账户与权限核查", "日志与审计核查"],
      gates: [
        {
          id: "cp-baseline-covered",
          label: "条目全部覆盖",
          kind: "artifact",
          criterion: "每个基线条目有结论（符合/不符合/不适用）与证据。",
          manual: false,
        },
      ],
      deliverables: ["基线核查表"],
      budget: 45,
    },
    {
      id: "cp-verify",
      name: "轻量渗透验证",
      short: "验证",
      intent: "对核查中发现的疑似风险做最小化验证，避免误报。",
      box: "grey",
      actions: ["弱口令验证（授权内）", "未授权访问验证", "配置缺陷验证"],
      gates: [
        {
          id: "cp-verify-proof",
          label: "疑似项已定性",
          kind: "evidence",
          criterion: "所有「疑似不符合」项均给出验证结论与证据。",
          manual: false,
        },
      ],
      deliverables: ["验证记录"],
      budget: 25,
    },
    {
      id: "cp-report",
      name: "合规报告",
      short: "报告",
      intent: "输出差距清单与整改建议，可直接转为整改工单。",
      box: "grey",
      actions: ["生成报告", "排序整改优先级"],
      gates: [
        {
          id: "cp-report-done",
          label: "报告可交付",
          kind: "artifact",
          criterion: "报告含条目结论、证据索引、整改建议与优先级。",
          manual: true,
        },
      ],
      deliverables: ["合规报告", "整改工单"],
      budget: 15,
    },
  ],
  evolutions: [],
};

export const ENGAGEMENT_MODES: EngagementMode[] = [
  SRC_MODE,
  CROWDTEST_MODE,
  CODE_AUDIT_MODE,
  GREYBOX_MODE,
  REDTEAM_MODE,
  CTF_MODE,
  COMPLIANCE_MODE,
];

// ── 运行时状态（后端按此结构返回任务的实际作战进度） ──────────────────────────

export type StageStatus = "pending" | "active" | "done" | "blocked";

export interface TaskStageState {
  stage_id: string;
  status: StageStatus;
  /** 已满足的闸门 id。 */
  passed_gates: string[];
  /** 该阶段的产出摘要（给看板用）。 */
  note?: string;
  entered_at?: number;
  finished_at?: number;
}

export interface TaskEvolutionEvent {
  id: string;
  /** 触发描述，例如「发现 .git 泄露」。 */
  trigger: string;
  from_box: BoxType;
  to_box: BoxType;
  from_mode?: string;
  to_mode?: string;
  at: number;
  /** 自动切换还是人工确认。 */
  auto: boolean;
}

export interface TaskEngagement {
  mode: string;
  box: BoxType;
  current_stage: string;
  stages: TaskStageState[];
  evolutions: TaskEvolutionEvent[];
  /** 后端给出的下一步建议（可为空）。 */
  next_hint?: string;
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

export function modeByKey(key: string | undefined | null): EngagementMode | null {
  if (!key) return null;
  return ENGAGEMENT_MODES.find((mode) => mode.key === key) ?? null;
}

export function stageIndex(mode: EngagementMode, stageID: string): number {
  const idx = mode.stages.findIndex((stage) => stage.id === stageID);
  return idx < 0 ? 0 : idx;
}

export function stageByID(mode: EngagementMode, stageID: string): EngagementStage | null {
  return mode.stages.find((stage) => stage.id === stageID) ?? null;
}

/** 已通过闸门数 / 总闸门数（含此前阶段，用于总进度）。 */
export function engagementProgress(mode: EngagementMode, state: TaskEngagement | null): number {
  if (!state) return 0;
  const total = mode.stages.reduce((sum, stage) => sum + stage.gates.length, 0);
  if (total === 0) return 0;
  const passed = state.stages.reduce((sum, stage) => sum + stage.passed_gates.length, 0);
  return Math.min(100, Math.round((passed / total) * 100));
}

/** 按当前盒型从模式里筛出可用的演进建议。 */
export function evolutionsFrom(mode: EngagementMode, box: BoxType): EvolutionRule[] {
  return mode.evolutions.filter((rule) => {
    if (!rule.to_box) return true;
    return rule.to_box !== box;
  });
}

/**
 * 解析 url.txt 清单：逐行去空、去列表符号、补全协议、校验 http/https、去重。
 * 返回可直接上传给 agent 的规范化 URL 队列，以及无效行与重复数。
 */
export function parseUrlList(text: string): { urls: string[]; invalid: string[]; duplicates: number } {
  const urls: string[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();
  let duplicates = 0;
  for (const rawLine of text.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const line = rawLine
      .trim()
      .replace(/^[-*+]\s+/, "")
      .replace(/^\d+[.)]\s+/, "")
      .replace(/^["'<]+|["'>]+$/g, "")
      .trim();
    if (!line || line.startsWith("#")) continue;
    const candidate = /^https?:\/\//i.test(line) ? line : `https://${line}`;
    try {
      const parsed = new URL(candidate);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        invalid.push(line);
        continue;
      }
      if (!parsed.hostname || !parsed.hostname.includes(".")) {
        invalid.push(line);
        continue;
      }
      parsed.hash = "";
      const href = parsed.toString();
      if (seen.has(href)) {
        duplicates += 1;
        continue;
      }
      seen.add(href);
      urls.push(href);
    } catch {
      invalid.push(line);
    }
  }
  return { urls, invalid, duplicates };
}

/** 选择模式时生成预填内容：描述 + 目标 + 阶段路线，供新建任务表单直接使用。 */
export function modeTemplate(mode: EngagementMode): { description: string; goal: string; route: string } {
  const route = mode.stages.map((stage) => `${stage.short}(${BOX_META[stage.box].short})`).join(" → ");
  return {
    description: mode.default_description,
    goal: mode.default_goal,
    route,
  };
}

/**
 * 生成注入任务描述的「作战简报」。planner 读的是描述+目标，因此把模式、阶段、
 * 约束、演进规则写进去，就能在不改后端的前提下让 agent 按模式执行。
 */
export function buildModeBrief(mode: EngagementMode): string {
  const route = mode.stages
    .map((stage, index) => `${index + 1}. ${stage.name}（${BOX_META[stage.box].label}）— ${stage.intent}`)
    .join("\n");
  const constraints = mode.constraints.map((item) => `- ${item}`).join("\n");
  const gates = mode.stages
    .map((stage) => {
      const items = stage.gates.map((gate) => `${gate.label}：${gate.criterion}`).join("；");
      return `- ${stage.name}：${items}`;
    })
    .join("\n");
  const evolutions = mode.evolutions
    .map(
      (rule) =>
        `- 当「${rule.trigger}」时，转入${rule.to_mode ? `「${modeByKey(rule.to_mode)?.name ?? rule.to_mode}」模式` : "下一阶段"}${rule.to_box ? `，盒型切换为${BOX_META[rule.to_box].label}` : ""}（${rule.rationale}）`,
    )
    .join("\n");
  const sections = [
    `【作战模式】${mode.name}（${BOX_META[mode.entry_box].label} → ${BOX_META[mode.target_box].label}，暴露强度：${EXPOSURE_META[mode.exposure].label}）`,
    `【阶段路线】\n${route}`,
    `【阶段闸门】未满足闸门不得进入下一阶段：\n${gates}`,
    `【硬约束】\n${constraints}`,
    `【交付物】${mode.deliverables.join("、")}`,
  ];
  if (mode.execution_notes?.length) {
    sections.push(`【执行纪律】\n${mode.execution_notes.map((item) => `- ${item}`).join("\n")}`);
  }
  if (evolutions) sections.push(`【演进规则】\n${evolutions}`);
  return sections.join("\n\n");
}

/** 盒型是否比之前更「白」（用于生成演进提示文案）。 */
export function boxRank(box: BoxType): number {
  switch (box) {
    case "black":
      return 0;
    case "grey":
      return 1;
    case "hybrid":
      return 2;
    case "white":
      return 3;
  }
}

export function nextStage(mode: EngagementMode, currentStageID: string): EngagementStage | null {
  const idx = stageIndex(mode, currentStageID);
  return mode.stages[idx + 1] ?? null;
}

// ── 状态机：纯函数，UI 与本地存储共用 ────────────────────────────────────────

/** 某模式的初始作战状态：第一阶段激活，其余待命。 */
export function initialEngagementState(mode: EngagementMode): TaskEngagement {
  return {
    mode: mode.key,
    box: mode.entry_box,
    current_stage: mode.stages[0]?.id ?? "",
    stages: mode.stages.map((stage, index) => ({
      stage_id: stage.id,
      status: index === 0 ? "active" : "pending",
      passed_gates: [],
    })),
    evolutions: [],
  };
}

/** 勾选/取消某阶段的一个闸门。 */
export function toggleEngagementGate(
  state: TaskEngagement,
  stageID: string,
  gateID: string,
  passed: boolean,
): TaskEngagement {
  return {
    ...state,
    stages: state.stages.map((stage) => {
      if (stage.stage_id !== stageID) return stage;
      const next = new Set(stage.passed_gates);
      if (passed) next.add(gateID);
      else next.delete(gateID);
      return { ...stage, passed_gates: [...next] };
    }),
  };
}

/** 当前阶段的所有闸门是否都已通过。 */
export function stageGatesSatisfied(mode: EngagementMode, state: TaskEngagement): boolean {
  const stage = stageByID(mode, state.current_stage);
  if (!stage) return false;
  const record = state.stages.find((item) => item.stage_id === state.current_stage);
  const passed = new Set(record?.passed_gates ?? []);
  return stage.gates.every((gate) => passed.has(gate.id));
}

/** 推进到下一阶段；已是最后阶段时返回 null（由调用方决定是否结束任务）。 */
export function advanceEngagementStage(state: TaskEngagement, mode: EngagementMode, at: number): TaskEngagement | null {
  const idx = stageIndex(mode, state.current_stage);
  const next = mode.stages[idx + 1];
  if (!next) return null;
  return {
    ...state,
    current_stage: next.id,
    stages: state.stages.map((stage) => {
      if (stage.stage_id === state.current_stage) {
        return { ...stage, status: "done", finished_at: at };
      }
      if (stage.stage_id === next.id) {
        return { ...stage, status: "active", entered_at: stage.entered_at ?? at };
      }
      return stage;
    }),
  };
}

/** 记录一次盒型/模式演进，并把阶段计划切换到新模式（若发生模式切换）。 */
export function applyEvolution(
  state: TaskEngagement,
  mode: EngagementMode,
  rule: EvolutionRule,
  at: number,
): TaskEngagement {
  const nextMode = rule.to_mode ? modeByKey(rule.to_mode) : null;
  const resolvedMode = nextMode ?? mode;
  const event: TaskEvolutionEvent = {
    id: `evo-${at}-${rule.id}`,
    trigger: rule.trigger,
    from_box: state.box,
    to_box: rule.to_box ?? state.box,
    from_mode: mode.key,
    to_mode: nextMode?.key,
    at,
    auto: rule.action === "auto",
  };
  if (!nextMode) {
    // 同模式内换盒型/换阶段：保留既有进度与闸门记录，只调整当前阶段。
    const target = rule.to_stage ?? state.current_stage;
    return {
      ...state,
      box: rule.to_box ?? state.box,
      current_stage: target,
      evolutions: [...state.evolutions, event],
      stages: state.stages.map((stage) => {
        if (stage.stage_id === target) {
          // 回退到已完成阶段（如众测重复后回到横扫）时重新激活，让用户可以再次推进。
          return { ...stage, status: "active", entered_at: stage.entered_at ?? at };
        }
        return stage;
      }),
    };
  }
  // 换模式：新模式的阶段计划接管；目标阶段之前的阶段视为已完成（沿用已完成的前置）。
  const targetIdx = Math.max(
    0,
    nextMode.stages.findIndex((stage) => stage.id === (rule.to_stage ?? nextMode.stages[0]?.id)),
  );
  return {
    ...state,
    mode: nextMode.key,
    box: rule.to_box ?? nextMode.entry_box,
    current_stage: nextMode.stages[targetIdx]?.id ?? nextMode.stages[0]?.id ?? "",
    evolutions: [...state.evolutions, event],
    stages: nextMode.stages.map((stage, index) => {
      if (index < targetIdx) {
        return {
          stage_id: stage.id,
          status: "done",
          passed_gates: stage.gates.map((gate) => gate.id),
          finished_at: at,
        };
      }
      if (index === targetIdx) {
        return { stage_id: stage.id, status: "active", passed_gates: [], entered_at: at };
      }
      return { stage_id: stage.id, status: "pending", passed_gates: [] };
    }),
  };
}
