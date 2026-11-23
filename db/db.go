// Package db is the PostgreSQL data source for ARTEX (取代旧 graph 单文件 SQLite)。
// 它打开连接、应用 schema、并 seed 内置 agent 与变量目录。
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

//go:embed schema.sql
var schemaSQL string

const schemaMigrationLockKey int64 = 7337741001

// maxOpenConns 是连接池上限，见 Open 里的说明。取值远低于 PostgreSQL 默认的
// max_connections=100，同时远高于应用自身的嵌套取连接深度（启动期的 schema
// advisory lock 会在持有一条连接的同时让 seedBuiltins 另取连接），不会自锁。
const maxOpenConns = 32

var schemaDeadlockRetryDelays = [...]time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
}

type schemaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func isPostgresDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

func applySchemaWithRetry(ctx context.Context, execer schemaExecer, sleep func(time.Duration)) error {
	for attempt := 0; ; attempt++ {
		if _, err := execer.ExecContext(ctx, schemaSQL); err != nil {
			if !isPostgresDeadlock(err) || attempt >= len(schemaDeadlockRetryDelays) {
				return err
			}
			sleep(schemaDeadlockRetryDelays[attempt])
			continue
		}
		return nil
	}
}

// withSchemaMigrationLock pins the session-level lock to one checked-out
// connection. Running pg_advisory_lock through *sql.DB is incorrect because a
// later schema or unlock call may use a different pooled PostgreSQL session.
func withSchemaMigrationLock(ctx context.Context, sqlDB *sql.DB, action func(*sql.Conn) error) (err error) {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schemaMigrationLockKey); unlockErr != nil && err == nil {
			err = fmt.Errorf("advisory unlock: %w", unlockErr)
		}
	}()
	return action(conn)
}

// coordinateWithSchemaMigration makes long, multi-table archive transactions
// mutually exclusive with startup DDL while allowing ordinary runtime queries
// to continue normally.
func coordinateWithSchemaMigration(tx *sql.Tx) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("coordinate with schema migration: %w", err)
	}
	return nil
}

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env ARTEX_PG_DSN > config file (config.json). There is no
// built-in default — it errors if neither source is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// DB wraps the shared *sql.DB. PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
type DB struct{ *sql.DB }

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	if err := ensureDatabase(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// database/sql 默认不限制连接数：池里没有空闲连接时会无条件新建，一路顶到
	// PostgreSQL 的 max_connections（默认 100）才被拒，于是高峰期的查询拿到的是
	// `FATAL: sorry, too many clients already` 这种**错误**。封顶之后超额查询改为
	// 排队等待空闲连接——同样的负载下变成变慢而不是报错，调用方不必再去区分
	// "读不到"和"没有"。maxOpenConns 要留出余量给 psql / reset-password.sh 以及
	// 可能并存的其他实例；若 max_connections 调低过，这里也要跟着往下调。
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	d := &DB{sqlDB}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	// Keep the dedicated lock connection checked out until both DDL and seeding
	// finish so concurrent application instances cannot initialize out of order.
	err = withSchemaMigrationLock(context.Background(), sqlDB, func(conn *sql.Conn) error {
		if err := applySchemaWithRetry(context.Background(), conn, time.Sleep); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if err := d.seedBuiltins(); err != nil {
			return fmt.Errorf("seed builtins: %w", err)
		}
		return nil
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // 建行时的默认交互式 shell 开关；ON CONFLICT 不覆盖用户后续手动开关
	runSeconds            *int // 建行时的单次 run 墙钟上限(秒)；nil=用种子默认(1200)，0=不限时
}

type promptVar struct{ name, desc, example, source string }

// intp 返回 v 的指针，用于给 builtinAgent 可选字段(如 runSeconds)显式取值。
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a). 内置工具不入库；这里只 seed agent + 变量目录。
// 注：planner/worker/mainagent/auto 的交互式 shell 默认由下方 interactive_shell_default_v1
// 块统一置 true（尊重后续 toggle）；这里的 interactiveShell 只给需要「建行即默认开」的新 agent。
var builtinAgents = []builtinAgent{
	{"goals", "目标拆解", "goals", "把渗透任务目标拆解成若干独立、可验证的子目标。", []promptVar{
		{"EngagementDescription", "任务描述（测试对象/背景）", "测试 example.com 站点", "exploration"},
		// Now 是全局 runtime 变量(见 server.globalPromptVars),不再在各 agent 目录里
		// 重复定义,否则 withGlobalVars 追加时会与全局项撞名。
	}, false, nil},
	{"planner", "规划", "planner", "读取态势、判定目标，只在确有未覆盖的新方向时补充探索意图（每任务一个规划循环）。", []promptVar{
		{"Goal", "任务总目标", "拿下 example.com 的管理员权限", "exploration"},
		{"AssetSummary", "资产计数/类型分布摘要(可选)", "domain:3 ip:5 site:2", "distilled"},
	}, false, nil},
	{"mainagent", "主", "main", "人机接口：观察进展，把人的意图落成 hint 或高优先级意图。", []promptVar{
		{"Goal", "当前任务目标", "拿下 example.com 的管理员权限", "exploration"},
		{"AssetSummary", "开局态势摘要(可选)", "domain:3 ip:5", "distilled"},
		{"FindingsSummary", "已确认漏洞摘要(可选)", "high:1 medium:2", "distilled"},
	}, false, nil},
	{"worker", "执行", "worker", "领取一条意图执行，把发现的事实/漏洞写回知识图谱后停止。", []promptVar{
		{"ProxyAddr", "记录代理地址(驱动 if 双文案)", "127.0.0.1:8080", "runtime"},
		{"WorkerName", "worker 自我标识(可选)", "worker-1", "runtime"},
	}, false, nil},
	// Auto:内置「平台操作」agent。不参与渗透编排循环,经对话页驱动,用工具操作平台。
	{"auto", "Auto", "assistant", "平台操作助手：用工具管理任务(建/看/暂停/给提示)与资产，并可创建/修改 skill、自定义工具、MCP。", nil, false, nil},
	// 渗透测试:内置「独立渗透」agent。经对话页驱动,一人从侦察到收尾走完整条渗透链,自己规划自己执行自己验证。默认开启交互式 shell。
	{"pentest", "渗透测试", "assistant", "独立渗透 agent：一人从侦察→找攻击面→深入利用→验证→收尾走完整条链，自己规划、自己执行、自己对抗式验证。", nil, true, intp(0)},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, COALESCE($6, 1200))
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	// Drop catalog entries for variables that were renamed, so the white-list no
	// longer advertises a name templates can't resolve (EngagementTitle→Description).
	// 'Now' 从各 agent 目录提升为全局 runtime 变量后,旧库里 goals 仍残留一条 'Now'
	// 会与全局项撞名(前端变量列表 key 重复);一并清掉。
	if _, err := d.Exec(`DELETE FROM agent_prompt_vars WHERE var_name IN ('EngagementTitle', 'CoverageGaps', 'Now')`); err != nil {
		return fmt.Errorf("cleanup renamed vars: %w", err)
	}
	// Default-on interactive_shell for the runtime agents (planner/worker/mainagent/auto)
	// ONCE — respects a later user toggle-off (guarded by a settings flag). goals(one-shot
	// decomposer) stays off. Runs after the column exists (schema applied before seed).
	if v, _, _ := d.GetSetting("interactive_shell_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET interactive_shell=true WHERE key IN ('planner','worker','mainagent','auto')`); err != nil {
			return fmt.Errorf("seed interactive_shell defaults: %w", err)
		}
		_ = d.SetSetting("interactive_shell_default_v1", "true")
	}
	// Seed the built-in browser (Playwright) MCP once — DISABLED by default (用户
	// 需要时自行启用), no proxy by default. The traffic-capture toggle injects/strips
	// the recording proxy + CA at runtime (server.Manager.syncBrowserMCPProxy).
	// Insert only if absent so we never clobber user edits (args/env/enabled/
	// visibility) on restart.
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser', 'stdio', 'npx', $1, '{}', false)
ON CONFLICT (name) DO NOTHING`,
		`["@playwright/mcp","--headless"]`); err != nil {
		return fmt.Errorf("seed browser mcp: %w", err)
	}
	// NOTE: the placeholder ScopeSentry data-source MCP (empty URL + empty X-API-Key,
	// disabled) is seeded directly in schema.sql §F so a raw `psql < schema.sql` init
	// also gets it. schema.sql is Exec'd on every startup, so it stays idempotent.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		return fmt.Errorf("seed skill visibility: %w", err)
	}
	if err := d.seedDefaultInterceptRules(); err != nil {
		return fmt.Errorf("seed intercept rules: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV2(); err != nil {
		return fmt.Errorf("seed intercept rules v2: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV3(); err != nil {
		return fmt.Errorf("seed intercept rules v3: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV4(); err != nil {
		return fmt.Errorf("seed intercept rules v4: %w", err)
	}
	if err := d.seedDefaultAssetInterceptRules(); err != nil {
		return fmt.Errorf("seed asset intercept rules: %w", err)
	}
	return nil
}

// seedDefaultAssetInterceptRules inserts the built-in asset blocklist (fuzzy
// domain matches for government / education sites) once on first startup. Gated
// by a settings flag so a user's later disable/delete is never resurrected on
// restart — same policy as the intercept-rule seed.
func (d *DB) seedDefaultAssetInterceptRules() error {
	if v, _, _ := d.GetSetting("asset_intercept_default_rules_v1"); v == "done" {
		return nil
	}
	rules := []struct {
		kind    string
		pattern string
		note    string
	}{
		{"fuzzy_domain", ".gov", "[内置] 政府网站 (.gov)"},
		{"fuzzy_domain", ".gov.cn", "[内置] 政府网站 (.gov.cn)"},
		{"fuzzy_domain", ".edu", "[内置] 教育网站 (.edu)"},
		{"fuzzy_domain", ".edu.cn", "[内置] 教育网站 (.edu.cn)"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO asset_intercept_rules(enabled, kind, pattern, note, builtin)
VALUES (true, $1, $2, $3, true)
ON CONFLICT DO NOTHING`, r.kind, r.pattern, r.note); err != nil {
			return fmt.Errorf("asset rule %q: %w", r.pattern, err)
		}
	}
	return d.SetSetting("asset_intercept_default_rules_v1", "done")
}

// builtinSkillVisibility maps a shipped skill's directory name → the built-in
// agent keys that should see it by default. The skill FILES themselves live on the
// filesystem (SkillDir, loaded by norma at runtime); DB only carries this visibility
// binding. Skills omitted here (e.g. playwright-cli, scopesentry) ship invisible by
// default — the user turns them on per-agent when needed. scopesentry additionally
// declares `mcps: ScopeSentry`, which only takes effect once it's made visible and
// that MCP is enabled/configured.
var builtinSkillVisibility = map[string][]string{
	"api-recon": {"auto", "pentest", "worker"},
}

// seedBuiltinSkillVisibility binds the shipped built-in skills to their default
// agents. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's later toggle-off is
// never resurrected on restart — matches the browser-MCP / intercept-rule seed policy.
func (d *DB) seedBuiltinSkillVisibility() error {
	for skillName, agentKeys := range builtinSkillVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
SELECT id, $2, true FROM agents WHERE key=$1
ON CONFLICT (agent_id, skill_name) DO NOTHING`, key, skillName); err != nil {
				return fmt.Errorf("skill %s → agent %s: %w", skillName, key, err)
			}
		}
	}
	return nil
}

// seedDefaultInterceptRules inserts built-in safety intercept rules once on
// first startup. The seed is gated by a settings flag so user edits (disable,
// delete, re-order) are never overwritten on subsequent restarts.
func (d *DB) seedDefaultInterceptRules() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v1"); v == "done" {
		return nil
	}
	type rule struct {
		name     string
		target   string // tool_name | tool_input
		typ      string // string | regex
		pattern  string
		action   string
		message  string
		priority int
	}
	rules := []rule{
		// ── 系统破坏性命令 (priority 100) ──────────────────────────────────
		{
			name:     "[内置] 递归强制删除 rm -rf",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
			action:   "deny",
			message:  "禁止执行递归强制删除（rm -rf / rm --recursive），可能永久损坏系统或靶机环境",
			priority: 100,
		},
		{
			name:     "[内置] 删除系统关键目录",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\brm\b[^"'\n]{0,60}["'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)`,
			action:   "deny",
			message:  "禁止删除系统关键路径",
			priority: 100,
		},
		{
			name:     "[内置] 磁盘格式化 mkfs",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bmkfs\b`,
			action:   "deny",
			message:  "禁止格式化磁盘（mkfs）",
			priority: 100,
		},
		{
			name:     "[内置] 覆写磁盘设备 dd",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "禁止使用 dd 覆写磁盘设备",
			priority: 100,
		},
		{
			name:     "[内置] Fork 炸弹",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `:\(\)\s*\{[^}]*:\|:`,
			action:   "deny",
			message:  "禁止执行 Fork 炸弹",
			priority: 100,
		},
		{
			name:     "[内置] 关机 / 重启",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b`,
			action:   "deny",
			message:  "禁止执行关机或重启命令",
			priority: 100,
		},
		{
			name:     "[内置] 杀死全部进程",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
			action:   "deny",
			message:  "禁止 kill -9 -1 或 killall -9（杀死所有进程）",
			priority: 100,
		},
		{
			name:     "[内置] 磁盘擦除 shred / wipe",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "禁止对磁盘设备执行 shred/wipe 擦除",
			priority: 100,
		},
		{
			name:     "[内置] 清空防火墙规则",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
			action:   "deny",
			message:  "禁止清空防火墙规则（iptables -F / nft flush）",
			priority: 100,
		},
		// ── 数据库破坏性操作 (priority 90) ─────────────────────────────────
		{
			name:     "[内置] SQL DROP DATABASE / TABLE / SCHEMA",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
			action:   "deny",
			message:  "禁止执行 DROP 操作，可能不可逆地销毁数据库对象",
			priority: 90,
		},
		{
			name:     "[内置] SQL TRUNCATE",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w`,
			action:   "deny",
			message:  "禁止执行 TRUNCATE，可能清空数据表所有数据",
			priority: 90,
		},
		{
			name:     "[内置] MongoDB drop / dropDatabase",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(`,
			action:   "deny",
			message:  "禁止执行 MongoDB drop 操作",
			priority: 90,
		},
		{
			name:     "[内置] Redis FLUSHALL / FLUSHDB",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:FLUSHALL|FLUSHDB)\b`,
			action:   "deny",
			message:  "禁止执行 Redis FLUSHALL / FLUSHDB，可能清空全部缓存数据",
			priority: 90,
		},
		// ── HTTP 破坏性请求 (priority 80) ──────────────────────────────────
		// Agent 发送 DELETE 请求的三种常见方式：
		//   1. curl -X DELETE / --request DELETE（Bash 工具直接执行或写入脚本）
		//   2. Python HTTP 客户端 .delete() 方法
		//   3. JS/通用脚本里的 method: 'DELETE' / method="DELETE"
		{
			name:     "[内置] curl / wget 发送 DELETE 请求",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bcurl\b[^|\n&;"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;"]{0,300}--method[=\s]+DELETE`,
			action:   "deny",
			message:  "禁止通过 curl/wget 发送 HTTP DELETE 请求，可能删除目标系统数据",
			priority: 80,
		},
		{
			name:     "[内置] Python HTTP 客户端 DELETE（requests/httpx/aiohttp）",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(`,
			action:   "deny",
			message:  "禁止使用 Python HTTP 客户端发送 DELETE 请求",
			priority: 80,
		},
		{
			name:     "[内置] 脚本中声明 HTTP DELETE 方法（JS/通用）",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)axios\.delete\s*\(|method\s*[:=]\s*['"]DELETE['"]`,
			action:   "deny",
			message:  "禁止在脚本中声明并发送 HTTP DELETE 请求",
			priority: 80,
		},
		{
			name:     "[内置] 批量清空 / 清除接口路径",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#"'\s]|$)`,
			action:   "deny",
			message:  "禁止调用批量清空或销毁类接口（/clear /wipe /flush /purge 等）",
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, false, 60, 'deny')
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v1", "done")
}

// seedDefaultInterceptRulesV2 migrates the two safety patterns that used to be
// hard-coded in guard.go (destructive shell + data-exfil pipe) into ordinary
// intercept rules. Gated by its own flag so it also lands on DBs that already ran
// v1. Unlike the old guard.go floor, these are plain [内置] rules — the user can
// disable or delete them. The exfil rule ships DISABLED by default (its
// curl/wget/nc pipe pattern mis-fires on legitimate CTF/pentest reverse-shell and
// data-transfer pipes); enable it manually when exfil gating is actually wanted.
func (d *DB) seedDefaultInterceptRulesV2() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v2"); v == "done" {
		return nil
	}
	rules := []struct {
		name     string
		pattern  string
		action   string
		message  string
		enabled  bool
		priority int
	}{
		{
			name:     "[内置] 破坏性系统命令",
			pattern:  `(?i)\b(rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|>\s*/dev/sd)`,
			action:   "deny",
			message:  "破坏性命令被拒绝（rm -rf / / mkfs / dd / fork bomb / 关机重启 / 覆写磁盘设备）",
			enabled:  true,
			priority: 100,
		},
		{
			name:     "[内置] 数据外泄管道",
			pattern:  `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`,
			action:   "deny",
			message:  "疑似数据外泄管道被拒绝（命令输出经 curl/wget/nc 外传）",
			enabled:  false,
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, $2, $3, 'tool_input', 'regex', $4, $5, $6, false, 60, 'deny')
ON CONFLICT DO NOTHING`,
			r.name, r.enabled, r.priority, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v2", "done")
}

// seedDefaultInterceptRulesV3 adds the delete-endpoint path rule. The v1 HTTP rules
// only catch the DELETE *method* (curl -X DELETE, requests.delete(, method:'DELETE'),
// and v1's path rule covers only /clear /wipe /flush /purge /truncate /drop /destroy
// /factory-reset /reset-all — so a plain `curl 'http://t/api/user/delete?id=1'` (a
// delete endpoint reached with GET/POST, which is how most web apps expose deletion)
// slipped through every built-in rule. Own flag so it also lands on DBs that already
// ran v1/v2, where editing the v1 seed would have no effect.
//
// The pattern deliberately requires a separator after the verb so /delivery,
// /details, /delta and /delegate do not match, while /deleteAll, /delete_user and
// /delete-user do. destroy is re-covered here because v1's rule does not allow a
// suffix (/destroyAll was missed).
//
// Exported as a package const only so the seeded regex is unit-testable without a DB.
const deleteEndpointPathPattern = `(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#"'\s]|$)`

func (d *DB) seedDefaultInterceptRulesV3() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v3"); v == "done" {
		return nil
	}
	const name = "[内置] 删除类接口路径"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, 80, 'tool_input', 'regex', $2, 'deny', $3, false, 60, 'deny'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
		name,
		deleteEndpointPathPattern,
		"禁止调用删除类接口（/delete /remove /unlink /erase 等），不论使用哪种 HTTP 方法——多数应用的删除接口用 GET/POST 就能触发，同样会真实删除目标数据",
	); err != nil {
		return fmt.Errorf("rule %q: %w", name, err)
	}
	return d.SetSetting("intercept_default_rules_v3", "done")
}

// ── v4: 漏洞利用"只取证、不深入"限制 ────────────────────────────────────────
//
// 三条业务约束（按 first-match-wins 的优先级从高到低实现为 deny→allow 层叠，
// 使每一类都是"白名单放行、其余全拦"的语义）：
//
//  1. SQL注入：只允许读指纹（库名/版本/当前用户）。deny(75) 拦数据提取与文件
//     读写，allow(68) 放行 database()/version()/user()/@@version/sqlmap
//     --current-db/--banner/--current-user/--dbs。
//  2. RCE：只允许执行 whoami/id/uname/hostname 这类无害身份命令（外加
//     ls/dir/tree/find 列目录）。deny(60) 拦命令注入参数里的任意其他命令，
//     allow(65) 放行"参数值恰好是白名单命令"的调用。
//  3. 敏感信息：只允许读文件名/目录名。deny(70) 拦 cat/type/Get-Content 等
//     文件内容读取，allow(55) 放行 ls/dir/tree/find -name 等列举命令。
//
// 全部低于既有内置规则（80–100），保证破坏性命令/DROP/DELETE 类拦截永远优先于
// 这里的放行规则，不会被白名单绕过。allow 规则里白名单命令必须"干净完整"——
// 值后面只允许跟旗标或终止符（引号/&/}），拼接 `;cat`、`;wget` 的载荷不会命中
// 放行、只会命中更上层的 deny。所有模式只匹配 URL/参数/字典形态的注入载荷，
// 不匹配本地多行脚本里的普通换行链，避免误伤日常命令。

// 导出为包级常量仅为了让正则可以脱离数据库做单元测试（与 v3 同一先例）。
const (
	// sqlInjectionExtractionPattern 拦 SQL 注入的数据提取与文件读写：
	// UNION…FROM、information_schema、系统目录表、SELECT…FROM、LOAD_FILE、
	// INTO OUTFILE、pg_read_file、COPY…TO PROGRAM、UTL_FILE、xp_cmdshell、
	// 以及 sqlmap 的提取类旗标（--dump/--tables/--columns/--passwords/--file-read…）。
	sqlInjectionExtractionPattern = `(?i)(?:UNION[\s\S]{0,300}\bFROM\b|\binformation_schema\b|\b(?:FROM|JOIN)\s+(?:mysql\.|performance_schema\.|pg_catalog\.|pg_tables\b|dba_\w+|all_tab\w+|user_tab\w+)\b|\bSELECT\s+(?:\*|[^;()\s]{1,64}(?:\s*,\s*[^;()\s]{1,64})*)\s+FROM\s+[\w.$"']+|\bLOAD_FILE\s*\(|\bINTO\s+(?:OUTFILE|DUMPFILE)\b|\bpg_read_(?:file|binary_file)\s*\(|\bpg_ls_dir\s*\(|\bCOPY\b[\s\S]{0,60}\bTO\s+PROGRAM\b|\b(?:UTL_FILE|UTL_HTTP|DBMS_JAVA|xp_cmdshell|sp_oacreate|sp_oamethod)\b|--(?:dump|dump-all|tables|columns|passwords|users|privileges|roles|file-read|file-write|os-shell|os-pwn|os-cmd|sql-shell|sql-query|eval)\b)`

	// fileContentReadPattern 拦"读文件内容"类命令（含 -exec cat {} 与 file://）。
	// 参数区允许旗标与中间词（head -n 5 /etc/shadow），但 150 字内必须出现
	// 路径特征（/ . \）或 {} 占位，纯 cat README（无路径特征）交给 LLM 兜底。
	fileContentReadPattern = `(?i)(?:\b(?:cat|tac|nl|more|less|head|tail|xxd|strings|od)\b(?:[^|;&\n]{0,150}[./\\]|\s*\{\})|\btype\s+(?:[A-Za-z]:\\|\w+\.\w+)|\b(?:Get-Content|Select-String|findstr)\b[^|;&\n]{0,80}[./\\]|\b(?:curl|wget)\s+file:)`

	// sqlFingerprintAllowPattern 放行 SQL 指纹读取：库名/版本/当前用户。
	sqlFingerprintAllowPattern = `(?i)(?:\b(?:database|schema|version|current_user|session_user|system_user)\s*\(|\buser\s*\(|@@version|--current-db\b|--current-user\b|--banner\b|--dbs\b)`

	// rceIdentityAllowPattern 放行 RCE 场景的无害命令。五种形态：
	// URL 分隔符注入（http://t/?id=1;whoami）、命令参数（?cmd=whoami）、
	// 字典/POST 体（{"cmd":"whoami"}、-d "cmd=whoami"）、本地替换
	// （$(whoami)、`whoami`、echo %username%）、以及 JSON 值恰好等于白名单
	// 命令（{"command":"whoami"}）。终止符统一接受可选反斜杠转义的引号
	// （\\?["']），因为 tool_input 是 JSON 串、内层引号都是 \" 转义形态。
	// 白名单命令后只允许旗标与终止符，`cmd=whoami;cat` 这类拼接不会命中
	// （会落到 deny）。
	rceIdentityAllowPattern = `(?i)(?:https?://[^"'\s]{0,600}(?:;|%3[bB]|\||%7[cC])(?:%20|\+|\s)*(?:(?:%77hoami|whoami|id|uname|%75name|hostname)\b(?:\s|%20|\+)*(?:-[a-z]+)?(?:\s|%20|\+)*|(?:ls|dir|tree|find)\b[\s%+\w./\\*:-]{0,100})(?:\\?["'#&}]|%22|%23|%27|%26)|[?&](?:cmd|exec|command|run|system|shell|ping|execute)=\s*\\?["']?(?:(?:whoami|id|uname|hostname)\b(?:\s|%20|\+)*(?:-[a-z]+)?(?:\s|%20|\+)*|(?:ls|dir|tree|find)\b[\s%+\w./\\*:-]{0,100})\\?["']?(?:&|%26|\\?["'}#%]|%22|%23)|["'](?:cmd|shell|system)\\?["']\s*:\s*\\?["'](?:(?:whoami|id|uname|hostname)\b(?:\s+-[a-z]+)?|(?:ls|dir|tree|find)\b[\s\w./\\%+:-]{0,100})\s*\\?["']|(?:-d|--data(?:-raw)?)[\s=]+\\?["'][^"']{0,60}\b(?:cmd|shell|system)=(?:(?:whoami|id|uname|hostname)\b(?:\s+-[a-z]+)?|(?:ls|dir|tree|find)\b[\s\w./\\%+:-]{0,100})\\?["']|:\s*\\?["'](?:whoami|id|uname|hostname)\s*(?:-[a-z]+)?\s*\\?["']\s*[},]|\$\(\s*(?:whoami|id|uname|hostname)\s*\)|\x60\s*(?:whoami|id|uname|hostname)\s*\x60|\becho\s+%username%)`

	// rceNonWhitelistPattern 拦命令注入载荷里的非白名单命令。三种形态：
	// URL 里的分隔符注入（;cat / %0Awget / |nc …，已知命令表）、
	// 命令注入参数传任意非白名单值（?cmd=cat…、-d "cmd=…"、{"cmd":"…"}）。
	// 白名单命令同时列在表内——它们能通过只因为 allow(65) 优先级更高。
	rceNonWhitelistPattern = `(?i)(?:https?://[^"'\s]{0,600}(?:;|%3[bB]|\||%7[cC]|%0[aA])(?:%20|\+|\s)*(?:%77hoami|whoami|id|uname|%75name|hostname|cat|tac|nl|more|less|head|tail|xxd|strings|base64|wget|curl|nc|ncat|socat|telnet|ssh|scp|ftp|bash|sh|zsh|dash|ksh|csh|powershell|pwsh|python\d?|perl|ruby|php|lua|tar|zip|unzip|gzip|xz|echo|printf|ping|nslookup|dig|whois|netstat|ifconfig|ipconfig|dir|ls|useradd|chmod|chown|mv|cp|rm|mkdir|ln|touch|kill|pkill|taskkill|tasklist|systemctl|schtasks|sed|awk|grep|findstr|cut|tr|tee|dd|nmap|sqlmap|mysql|psql|mongo|redis-cli|docker|kubectl|git|pip|npm|node|gcc|make|certutil|bitsadmin)\b|[?&](?:cmd|exec|command|run|system|shell|ping|execute)=\s*\\?["']?[^&'"#\s]{1,100}|(?:-d|--data(?:-raw)?)[\s=]+\\?["'][^"']{0,60}\b(?:cmd|shell|system)=[^"'\s]{1,100}|["'](?:cmd|shell|system)\\?["']\s*:\s*\\?["'][^"']{1,100})`

	// listingAllowPattern 放行目录/文件名浏览（只看名字，不读内容）。
	listingAllowPattern = `(?i)(?:\b(?:ls|dir|tree|Get-ChildItem)\b[^|;&\n]{0,120}|\bfind\s+[^|;&\n]{0,120}(?:-name|-iname|-maxdepth)\b)`
)

// seedDefaultInterceptRulesV4 adds the exploit-restraint rule set: SQL injection
// fingerprint-only reads, RCE identity-commands-only execution, and
// filenames-only sensitive discovery. Own flag so it also lands on DBs that
// already ran v1–v3. Idempotent by rule name, so re-running (or racing a manual
// insert) never duplicates rows.
func (d *DB) seedDefaultInterceptRulesV4() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v4"); v == "done" {
		return nil
	}
	rules := []struct {
		name     string
		pattern  string
		action   string
		message  string
		priority int
	}{
		{
			name:     "[内置] SQL注入-数据提取与文件读写",
			pattern:  sqlInjectionExtractionPattern,
			action:   "deny",
			message:  "SQL注入只允许读取数据库指纹（库名/版本/当前用户）。禁止提取表数据、读写文件或执行系统命令（UNION…FROM、information_schema、LOAD_FILE、INTO OUTFILE、xp_cmdshell、sqlmap --dump/--tables/--columns 等）",
			priority: 75,
		},
		{
			name:     "[内置] 敏感信息-读取文件内容",
			pattern:  fileContentReadPattern,
			action:   "deny",
			message:  "敏感信息探测只允许读取文件名/目录名（ls/dir/tree/find）。禁止读取文件内容（cat/tac/nl/more/less/head/tail/type/Get-Content/findstr、curl file:// 等）",
			priority: 70,
		},
		{
			name:     "[内置] SQL注入-指纹读取放行",
			pattern:  sqlFingerprintAllowPattern,
			action:   "allow",
			message:  "SQL指纹读取放行：database()/schema()/version()/user()/current_user、@@version、sqlmap --current-db/--banner/--current-user/--dbs",
			priority: 68,
		},
		{
			name:     "[内置] RCE-身份命令放行",
			pattern:  rceIdentityAllowPattern,
			action:   "allow",
			message:  "RCE身份确认放行：仅 whoami/id/uname/hostname/echo %username% 与 ls/dir/tree/find 列目录，且命令必须独立完整（不允许拼接其他命令）",
			priority: 65,
		},
		{
			name:     "[内置] RCE-非白名单命令",
			pattern:  rceNonWhitelistPattern,
			action:   "deny",
			message:  "RCE只允许执行无害身份命令（whoami/id/uname/hostname）与列目录命令。命令注入参数（cmd/exec/command/run/system/shell）传其他命令、或URL分隔符拼接任意命令，均被拒绝",
			priority: 60,
		},
		{
			name:     "[内置] 目录文件名浏览放行",
			pattern:  listingAllowPattern,
			action:   "allow",
			message:  "目录与文件名浏览放行：ls/dir/tree/Get-ChildItem/find -name（只看名字，不读内容）",
			priority: 55,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, $2, 'tool_input', 'regex', $3, $4, $5, false, 60, 'deny'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
			r.name, r.priority, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v4", "done")
}
