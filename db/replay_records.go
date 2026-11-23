package db

// 数据重放记录（Docker 版 /function/replay 的对等实现）。
//
// 每发送一次重放都留档一条：解析并规范化后的请求（method/url/headers/body）、
// 真实响应（status/headers/body）、归属任务、耗时与错误。
// 记录可被前端反复复制、重发；删除即物理删除。

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var ErrReplayNotFound = errors.New("replay record not found")

// ReplayIDRange 是重放编号过滤：From/To 同时为 0 表示不过滤；
// 只给 From = 单条编号；From+To = 闭区间（例如 12-19）。
type ReplayIDRange struct {
	From int64
	To   int64
}

// Active 报告该范围是否生效。
func (r ReplayIDRange) Active() bool { return r.From > 0 || r.To > 0 }

// ParseReplayIDRange 解析前端传入的编号过滤："12" / "12-19" / "" 三种形态。
func ParseReplayIDRange(raw string) (ReplayIDRange, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ReplayIDRange{}, nil
	}
	if idx := strings.Index(value, "-"); idx >= 0 {
		from, err1 := parseIntLoose(value[:idx])
		to, err2 := parseIntLoose(value[idx+1:])
		if err1 != nil || err2 != nil {
			return ReplayIDRange{}, fmt.Errorf("编号范围格式应为 12-19")
		}
		if from > to {
			from, to = to, from
		}
		return ReplayIDRange{From: from, To: to}, nil
	}
	id, err := parseIntLoose(value)
	if err != nil {
		return ReplayIDRange{}, fmt.Errorf("重放编号应为数字，或 12-19 这样的区间")
	}
	return ReplayIDRange{From: id, To: id}, nil
}

func parseIntLoose(raw string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
}

// ReplayRecord 是一次重放的完整留档。
type ReplayRecord struct {
	ID         int64             `json:"id"`
	TaskID     string            `json:"task_id,omitempty"`
	Format     string            `json:"format"`  // burp|curl（请求来源）
	Scheme     string            `json:"scheme"`  // http|https（实际发送使用）
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	ReqHeaders map[string]string `json:"req_headers"`
	ReqBody    string            `json:"req_body"`
	Status     int               `json:"status"`
	StatusText string            `json:"status_text"`
	RespHeaders map[string]string `json:"resp_headers"`
	RespBody   string            `json:"resp_body"`
	RespBodyTruncated bool       `json:"resp_body_truncated"`
	DurationMs int64             `json:"duration_ms"`
	RespLen    int64             `json:"resp_len"`
	Error      string            `json:"error,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

const replayCols = `id, task_id, format, scheme, method, url, req_headers, req_body,
       status, status_text, resp_headers, resp_body, resp_body_truncated,
       duration_ms, resp_len, error, created_at`

func scanReplay(row interface{ Scan(...any) error }) (ReplayRecord, error) {
	var (
		rec       ReplayRecord
		reqHdrs   []byte
		respHdrs  []byte
	)
	err := row.Scan(
		&rec.ID, &rec.TaskID, &rec.Format, &rec.Scheme, &rec.Method, &rec.URL, &reqHdrs, &rec.ReqBody,
		&rec.Status, &rec.StatusText, &respHdrs, &rec.RespBody, &rec.RespBodyTruncated,
		&rec.DurationMs, &rec.RespLen, &rec.Error, &rec.CreatedAt,
	)
	if err != nil {
		return rec, err
	}
	rec.ReqHeaders = map[string]string{}
	rec.RespHeaders = map[string]string{}
	_ = json.Unmarshal(reqHdrs, &rec.ReqHeaders)
	_ = json.Unmarshal(respHdrs, &rec.RespHeaders)
	return rec, nil
}

// CreateReplay 保存一条重放记录，返回带自增 id 的记录。
func (d *DB) CreateReplay(rec ReplayRecord) (ReplayRecord, error) {
	reqHdrs, err := json.Marshal(rec.ReqHeaders)
	if err != nil {
		return rec, err
	}
	respHdrs, err := json.Marshal(rec.RespHeaders)
	if err != nil {
		return rec, err
	}
	row := d.QueryRow(`INSERT INTO replay_records(
			task_id, format, scheme, method, url, req_headers, req_body,
			status, status_text, resp_headers, resp_body, resp_body_truncated,
			duration_ms, resp_len, error)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING `+replayCols,
		rec.TaskID, rec.Format, rec.Scheme, rec.Method, rec.URL, reqHdrs, rec.ReqBody,
		rec.Status, rec.StatusText, respHdrs, rec.RespBody, rec.RespBodyTruncated,
		rec.DurationMs, rec.RespLen, rec.Error,
	)
	return scanReplay(row)
}

// ListReplays 按任务过滤（空 = 全部）倒序分页。
// ids 非空时按重放编号过滤：单值（12）或闭区间（12-19）。
func (d *DB) ListReplays(taskID string, limit, offset int, ids ReplayIDRange) ([]ReplayRecord, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	where := make([]string, 0, 2)
	args := make([]any, 0, 4)
	if taskID != "" {
		args = append(args, taskID)
		where = append(where, fmt.Sprintf("task_id=$%d", len(args)))
	}
	if ids.Active() {
		if ids.From > 0 {
			args = append(args, ids.From)
			where = append(where, fmt.Sprintf("id >= $%d", len(args)))
		}
		if ids.To > 0 {
			args = append(args, ids.To)
			where = append(where, fmt.Sprintf("id <= $%d", len(args)))
		}
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := d.QueryRow(`SELECT count(*) FROM replay_records`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]any{}, args...), limit, offset)
	rows, err := d.Query(
		`SELECT `+replayCols+` FROM replay_records`+clause+
			fmt.Sprintf(` ORDER BY id DESC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2),
		pageArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]ReplayRecord, 0, limit)
	for rows.Next() {
		rec, sErr := scanReplay(rows)
		if sErr != nil {
			return nil, 0, sErr
		}
		out = append(out, rec)
	}
	return out, total, rows.Err()
}

// GetReplay 取单条记录。
func (d *DB) GetReplay(id int64) (ReplayRecord, error) {
	rec, err := scanReplay(d.QueryRow(`SELECT `+replayCols+` FROM replay_records WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return rec, ErrReplayNotFound
	}
	return rec, err
}

// DeleteReplay 物理删除一条记录。
func (d *DB) DeleteReplay(id int64) error {
	res, err := d.Exec(`DELETE FROM replay_records WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrReplayNotFound
	}
	return nil
}

// DeleteReplays 批量删除：
//   ids       非空 → 按这些重放编号删除
//   idRange   生效 → 按编号区间删除（From/To，任一可空）
//   两者都空   → 删除全部
// 返回实际删除行数。
func (d *DB) DeleteReplays(ids []int64, idRange ReplayIDRange) (int64, error) {
	where := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if len(ids) > 0 {
		// $1 = bigint[]，用 = ANY 避免拼 SQL
		args = append(args, ids)
		where = append(where, "id = ANY($1)")
	} else if idRange.Active() {
		if idRange.From > 0 {
			args = append(args, idRange.From)
			where = append(where, fmt.Sprintf("id >= $%d", len(args)))
		}
		if idRange.To > 0 {
			args = append(args, idRange.To)
			where = append(where, fmt.Sprintf("id <= $%d", len(args)))
		}
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	res, err := d.Exec(`DELETE FROM replay_records`+clause, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
