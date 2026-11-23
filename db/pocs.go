package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// PoC 知识库：渗透时先在本库检索，未命中再联网搜索。
//
// 一行 = 一份可复用的验证/利用素材：nuclei 模板、独立脚本、请求报文、
// Markdown 笔记或任意文本。content 存原文；agent 通过 search_poc 命中后
// 直接改造成针对当前目标的 payload，而不是重新上网找。
//
// nkey 是导入身份（nuclei:<template-id> / file:<sha256> / manual:<hash>），
// 重复导入同一份素材按 nkey upsert，不会产生重复行；手动编辑不改 nkey，
// 所以编辑后再导入同一来源仍会更新同一行。

const (
	MaxPocNameRunes        = 300
	MaxPocListItems        = 200
	DefaultPocSearchLimit  = 10
	MaxPocContentBytes     = 8 << 20 // 8 MiB
	MaxPocListFieldRunes   = 100
	pocHaystackSQL         = `(coalesce(name,'') || ' ' || coalesce(product,'') || ' ' || coalesce(vuln_type,'') || ' ' || coalesce(severity,'') || ' ' || coalesce(description,'') || ' ' || coalesce(content,'') || ' ' || array_to_string(cve,' ') || ' ' || array_to_string(tags,' ') || ' ' || array_to_string(refs,' '))`
	pocDefaultSourceManual = "manual"
)

var (
	ErrPocInvalid      = errors.New("invalid poc")
	ErrPocNameConflict = errors.New("poc identity already exists")
	ErrPocNotFound     = errors.New("poc not found")
)

// Poc is one stored PoC entry. Content is empty on list results unless the
// caller asked for it (WithContent) — list pages only need metadata.
type Poc struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	CVE         []string  `json:"cve"`
	Product     string    `json:"product"`
	VulnType    string    `json:"vuln_type"`
	Severity    string    `json:"severity"`
	Tags        []string  `json:"tags"`
	Description string    `json:"description"`
	Content     string    `json:"content"`
	Refs        []string  `json:"refs"`
	Source      string    `json:"source"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PocInput is the writable surface of a PoC. NKey is internal: importers set a
// stable identity (nuclei template id / file hash); manual creates leave it
// empty and the store derives one from name+content.
type PocInput struct {
	NKey        string
	Name        string
	CVE         []string
	Product     string
	VulnType    string
	Severity    string
	Tags        []string
	Description string
	Content     string
	Refs        []string
	Source      string
	Enabled     *bool
}

// PocFilter drives list/search. Enabled nil = all rows (UI); the agent tool
// always forces Enabled=true so disabled entries never reach the model.
type PocFilter struct {
	Query       string
	CVE         string
	Product     string
	VulnType    string
	Severity    string
	Tag         string
	Source      string
	Enabled     *bool
	Limit       int
	Offset      int
	WithContent bool
}

// PocStats is the small aggregate header for the management page.
type PocStats struct {
	Total      int            `json:"total"`
	Enabled    int            `json:"enabled"`
	WithCVE    int            `json:"with_cve"`
	BySeverity map[string]int `json:"by_severity"`
	ByVulnType map[string]int `json:"by_vuln_type"`
}

const pocCols = `id, name, cve, product, vuln_type, severity, tags, description, content, refs, source, enabled, created_at, updated_at`

const pocColsNoContent = `id, name, cve, product, vuln_type, severity, tags, description, ''::text AS content, refs, source, enabled, created_at, updated_at`

func scanPoc(row interface{ Scan(...any) error }) (*Poc, error) {
	var p Poc
	// pgx's database/sql bridge hands text[] back as the PostgreSQL array
	// literal string; pgTextArray parses it into []string.
	var cve, tags, refs pgTextArray
	err := row.Scan(&p.ID, &p.Name, &cve, &p.Product, &p.VulnType, &p.Severity,
		&tags, &p.Description, &p.Content, &refs, &p.Source, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	p.CVE = []string(cve)
	p.Tags = []string(tags)
	p.Refs = []string(refs)
	// nil slices marshal as null; normalize for the frontend.
	if p.CVE == nil {
		p.CVE = []string{}
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}
	if p.Refs == nil {
		p.Refs = []string{}
	}
	return &p, nil
}

// pgTextArray scans a PostgreSQL text[] value delivered by pgx's database/sql
// driver. It is a minimal Scanner over the array literal format:
// {"a","b,c",NULL,"d\"e"}. Our columns are NOT NULL so NULL elements are
// simply skipped rather than surfaced as a sentinel.
type pgTextArray []string

func (a *pgTextArray) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*a = nil
		return nil
	case string:
		*a = pgTextArray(parsePGTextArray(v))
		return nil
	case []byte:
		*a = pgTextArray(parsePGTextArray(string(v)))
		return nil
	case []string:
		*a = pgTextArray(v)
		return nil
	default:
		return fmt.Errorf("pgTextArray: unsupported source type %T", src)
	}
}

// parsePGTextArray decodes PostgreSQL's array output syntax, including quoted
// elements (which may contain commas), backslash escapes, and NULL elements.
func parsePGTextArray(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "{}" {
		return []string{}
	}
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return []string{s}
	}
	inner := s[1 : len(s)-1]
	out := []string{}
	var b strings.Builder
	inQuote := false
	quoted := false
	flush := func() {
		if quoted || b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
			quoted = false
		}
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if inQuote {
			if c == '\\' && i+1 < len(inner) {
				i++
				b.WriteByte(inner[i])
				continue
			}
			if c == '"' {
				inQuote = false
				continue
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '"':
			inQuote = true
			quoted = true
		case '\\':
			if i+1 < len(inner) {
				i++
				b.WriteByte(inner[i])
			}
		case ',':
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return out
}

func normalizePocList(vals []string, lower bool, maxRunes int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		v = strings.TrimSpace(v)
		v = strings.ReplaceAll(v, "\x00", "")
		if v == "" {
			continue
		}
		if maxRunes > 0 && utf8.RuneCountInString(v) > maxRunes {
			v = string([]rune(v)[:maxRunes])
		}
		key := strings.ToLower(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		if lower {
			v = key
		}
		out = append(out, v)
	}
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

func normalizePocInput(in PocInput) (PocInput, error) {
	name := strings.Join(strings.Fields(in.Name), " ")
	if name == "" {
		return in, fmt.Errorf("%w: name is required", ErrPocInvalid)
	}
	if utf8.RuneCountInString(name) > MaxPocNameRunes {
		return in, fmt.Errorf("%w: name exceeds %d characters", ErrPocInvalid, MaxPocNameRunes)
	}
	if len(in.Content) > MaxPocContentBytes {
		return in, fmt.Errorf("%w: content exceeds %d bytes", ErrPocInvalid, MaxPocContentBytes)
	}
	if !utf8.ValidString(in.Content) || !utf8.ValidString(in.Description) {
		return in, fmt.Errorf("%w: content/description is not valid UTF-8 text", ErrPocInvalid)
	}
	in.Name = strings.ReplaceAll(name, "\x00", "")
	in.CVE = normalizePocList(in.CVE, false, MaxPocListFieldRunes)
	in.Tags = normalizePocList(in.Tags, true, MaxPocListFieldRunes)
	in.Refs = normalizePocList(in.Refs, false, 4096)
	in.Product = strings.ReplaceAll(strings.TrimSpace(in.Product), "\x00", "")
	in.VulnType = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(in.VulnType)), "\x00", "")
	in.Severity = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(in.Severity)), "\x00", "")
	in.Description = strings.ReplaceAll(strings.TrimSpace(in.Description), "\x00", "")
	in.Content = strings.ReplaceAll(in.Content, "\r\n", "\n")
	// PostgreSQL text cannot store NUL (0x00); some PoC files embed one (e.g.
	// stray control bytes in a payload). Drop it rather than failing the import.
	in.Content = strings.ReplaceAll(in.Content, "\x00", "")
	in.Source = strings.ReplaceAll(strings.TrimSpace(in.Source), "\x00", "")
	if in.Source == "" {
		in.Source = pocDefaultSourceManual
	}
	if in.NKey == "" {
		in.NKey = pocManualKey(in.Name, in.Content)
	}
	return in, nil
}

// pocManualKey derives a stable identity for entries created through the API:
// same name + same content = same entry. Editing content keeps the row's nkey
// (UpdatePOC never changes it), so re-creating the edited form would be a new
// row — acceptable; the UI edits by id, not by re-create.
func pocManualKey(name, content string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.Join(strings.Fields(name), " ")) + "\x00" + content))
	return "manual:" + hex.EncodeToString(sum[:])
}

func pocEnabled(in PocInput) bool {
	if in.Enabled == nil {
		return true
	}
	return *in.Enabled
}

// CreatePOC inserts a new entry. Returns ErrPocNameConflict when the derived
// identity already exists (use UpdatePOC for edits).
func (d *DB) CreatePOC(in PocInput) (*Poc, error) {
	in, err := normalizePocInput(in)
	if err != nil {
		return nil, err
	}
	p, err := scanPoc(d.QueryRow(`
INSERT INTO pocs(nkey, name, cve, product, vuln_type, severity, tags, description, content, refs, source, enabled)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (nkey) DO NOTHING
RETURNING `+pocCols,
		in.NKey, in.Name, in.CVE, in.Product, in.VulnType, in.Severity, in.Tags,
		in.Description, in.Content, in.Refs, in.Source, pocEnabled(in)))
	if err == sql.ErrNoRows {
		return nil, ErrPocNameConflict
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// UpsertPOC inserts import results, updating the row with the same nkey in
// place. inserted=false means an existing entry was refreshed.
func (d *DB) UpsertPOC(in PocInput) (id int64, inserted bool, err error) {
	in, err = normalizePocInput(in)
	if err != nil {
		return 0, false, err
	}
	err = d.QueryRow(`
INSERT INTO pocs(nkey, name, cve, product, vuln_type, severity, tags, description, content, refs, source, enabled)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (nkey) DO UPDATE SET
    name=EXCLUDED.name, cve=EXCLUDED.cve, product=EXCLUDED.product,
    vuln_type=EXCLUDED.vuln_type, severity=EXCLUDED.severity, tags=EXCLUDED.tags,
    description=EXCLUDED.description, content=EXCLUDED.content, refs=EXCLUDED.refs,
    source=EXCLUDED.source, enabled=EXCLUDED.enabled
RETURNING id, (xmax = 0) AS inserted`,
		in.NKey, in.Name, in.CVE, in.Product, in.VulnType, in.Severity, in.Tags,
		in.Description, in.Content, in.Refs, in.Source, pocEnabled(in)).Scan(&id, &inserted)
	return id, inserted, err
}

// UpdatePOC replaces the editable fields of one entry. nkey is preserved so
// later imports from the same source keep updating this row.
func (d *DB) UpdatePOC(id int64, in PocInput) (*Poc, error) {
	cur, err := d.GetPOC(id)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, ErrPocNotFound
	}
	in, err = normalizePocInput(in)
	if err != nil {
		return nil, err
	}
	p, err := scanPoc(d.QueryRow(`
UPDATE pocs SET name=$2, cve=$3, product=$4, vuln_type=$5, severity=$6, tags=$7,
       description=$8, content=$9, refs=$10, source=$11, enabled=$12
WHERE id=$1
RETURNING `+pocCols,
		id, in.Name, in.CVE, in.Product, in.VulnType, in.Severity, in.Tags,
		in.Description, in.Content, in.Refs, in.Source, pocEnabled(in)))
	if err == sql.ErrNoRows {
		return nil, ErrPocNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// SetPOCEnabled toggles one entry without rewriting its content.
func (d *DB) SetPOCEnabled(id int64, enabled bool) (*Poc, error) {
	p, err := scanPoc(d.QueryRow(`UPDATE pocs SET enabled=$2 WHERE id=$1 RETURNING `+pocCols, id, enabled))
	if err == sql.ErrNoRows {
		return nil, ErrPocNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (d *DB) GetPOC(id int64) (*Poc, error) {
	p, err := scanPoc(d.QueryRow(`SELECT `+pocCols+` FROM pocs WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// DeletePOC removes one entry; false = not found.
func (d *DB) DeletePOC(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM pocs WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func likeContains(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return "%" + s + "%"
}

// SearchPOCs returns matching entries plus the total count before pagination.
// The query text is split into whitespace-separated tokens; every token must
// appear somewhere in the metadata or content (AND semantics), so
// "apache rce" finds Apache-related RCE PoCs. CVE/product/type/tag filters are
// applied independently.
func (d *DB) SearchPOCs(f PocFilter) ([]*Poc, int, error) {
	if f.Limit <= 0 {
		f.Limit = DefaultPocSearchLimit
	}
	if f.Limit > MaxPocListItems {
		f.Limit = MaxPocListItems
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	args := []any{}
	add := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	where := []string{}
	if f.Enabled != nil {
		where = append(where, "enabled="+add(*f.Enabled))
	}
	for _, tok := range pocQueryTokens(f.Query) {
		where = append(where, pocHaystackSQL+" ILIKE "+add(likeContains(tok))+" ESCAPE '\\'")
	}
	if strings.TrimSpace(f.CVE) != "" {
		where = append(where, "EXISTS (SELECT 1 FROM unnest(cve) c WHERE upper(c) LIKE "+add(likeContains(strings.ToUpper(strings.TrimSpace(f.CVE))))+" ESCAPE '\\')")
	}
	if strings.TrimSpace(f.Product) != "" {
		where = append(where, "product ILIKE "+add(likeContains(f.Product))+" ESCAPE '\\'")
	}
	if strings.TrimSpace(f.VulnType) != "" {
		where = append(where, "vuln_type ILIKE "+add(likeContains(f.VulnType))+" ESCAPE '\\'")
	}
	if strings.TrimSpace(f.Severity) != "" {
		where = append(where, "lower(severity)=lower("+add(strings.TrimSpace(f.Severity))+")")
	}
	if strings.TrimSpace(f.Tag) != "" {
		where = append(where, "EXISTS (SELECT 1 FROM unnest(tags) t WHERE t ILIKE "+add(likeContains(f.Tag))+" ESCAPE '\\')")
	}
	if strings.TrimSpace(f.Source) != "" {
		where = append(where, "source ILIKE "+add(likeContains(f.Source))+" ESCAPE '\\'")
	}
	whereSQL := "true"
	if len(where) > 0 {
		whereSQL = strings.Join(where, " AND ")
	}

	var total int
	if err := d.QueryRow(`SELECT count(*) FROM pocs WHERE `+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	cols := pocColsNoContent
	if f.WithContent {
		cols = pocCols
	}
	rows, err := d.Query(`SELECT `+cols+` FROM pocs WHERE `+whereSQL+
		` ORDER BY updated_at DESC, id DESC LIMIT `+add(f.Limit)+` OFFSET `+add(f.Offset), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*Poc{}
	for rows.Next() {
		p, err := scanPoc(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

func pocQueryTokens(q string) []string {
	fields := strings.Fields(q)
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		key := strings.ToLower(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// PocStats aggregates the management-page header.
func (d *DB) PocStats() (*PocStats, error) {
	s := &PocStats{BySeverity: map[string]int{}, ByVulnType: map[string]int{}}
	if err := d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE enabled), count(*) FILTER (WHERE cardinality(cve) > 0) FROM pocs`).
		Scan(&s.Total, &s.Enabled, &s.WithCVE); err != nil {
		return nil, err
	}
	if err := d.fillPocStats(s.BySeverity, `SELECT COALESCE(NULLIF(severity,''),'unknown'), count(*) FROM pocs GROUP BY 1`); err != nil {
		return nil, err
	}
	if err := d.fillPocStats(s.ByVulnType, `SELECT COALESCE(NULLIF(vuln_type,''),'unknown'), count(*) FROM pocs GROUP BY 1 ORDER BY 2 DESC LIMIT 20`); err != nil {
		return nil, err
	}
	return s, nil
}

func (d *DB) fillPocStats(dst map[string]int, q string) error {
	rows, err := d.Query(q)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		dst[k] = n
	}
	return rows.Err()
}
