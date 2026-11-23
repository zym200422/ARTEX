package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// PoC 知识库 HTTP API。检索/管理之外，导入端点支持三种素材形态：
// 上传文件（multipart）、直接提交 JSON 条目、扫描服务器上的本地目录（如
// 已克隆的 nuclei-templates / poc 仓库），全部走同一套解析器。

const (
	maxPocRequestBytes = 4 << 20
	maxPocImportBytes  = 64 << 20
	maxPocImportFile   = db.MaxPocContentBytes
)

// flexStrings accepts a JSON string ("a,b") or an array of strings, because PoC
// sources use both shapes for cve/tags/references.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*f = nil
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexStrings(anyToStrings(s))
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*f = flexStrings(arr)
	return nil
}

type pocRequest struct {
	Name        string      `json:"name"`
	CVE         flexStrings `json:"cve"`
	Product     string      `json:"product"`
	VulnType    string      `json:"vuln_type"`
	Severity    string      `json:"severity"`
	Tags        flexStrings `json:"tags"`
	Description string      `json:"description"`
	Content     string      `json:"content"`
	Refs        flexStrings `json:"refs"`
	Source      string      `json:"source"`
	Enabled     *bool       `json:"enabled"`
}

func (r pocRequest) input() db.PocInput {
	return db.PocInput{
		Name:        r.Name,
		CVE:         []string(r.CVE),
		Product:     r.Product,
		VulnType:    r.VulnType,
		Severity:    r.Severity,
		Tags:        []string(r.Tags),
		Description: r.Description,
		Content:     r.Content,
		Refs:        []string(r.Refs),
		Source:      r.Source,
		Enabled:     r.Enabled,
	}
}

func writePocError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrPocInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, db.ErrPocNameConflict):
		writeErr(w, http.StatusConflict, "同名同内容的 PoC 已存在")
	case errors.Is(err, db.ErrPocNotFound):
		writeErr(w, http.StatusNotFound, "PoC 不存在")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) listPOCs(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	f := db.PocFilter{
		Query:       strings.TrimSpace(q.Get("q")),
		CVE:         strings.TrimSpace(q.Get("cve")),
		Product:     strings.TrimSpace(q.Get("product")),
		VulnType:    strings.TrimSpace(q.Get("vuln_type")),
		Severity:    strings.TrimSpace(q.Get("severity")),
		Tag:         strings.TrimSpace(q.Get("tag")),
		Source:      strings.TrimSpace(q.Get("source")),
		WithContent: q.Get("content") == "1" || strings.EqualFold(q.Get("content"), "true"),
	}
	switch strings.ToLower(strings.TrimSpace(q.Get("enabled"))) {
	case "1", "true":
		v := true
		f.Enabled = &v
	case "0", "false":
		v := false
		f.Enabled = &v
	}
	f.Limit = pocQueryInt(q.Get("limit"), 20)
	f.Offset = pocQueryInt(q.Get("offset"), 0)
	pocs, total, err := pg.SearchPOCs(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pocs": pocs, "total": total, "limit": f.Limit, "offset": f.Offset})
}

func pocQueryInt(raw string, def int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func (s *Server) getPOC(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad poc id")
		return
	}
	p, err := pg.GetPOC(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p == nil {
		writeErr(w, http.StatusNotFound, "PoC 不存在")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) createPOC(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPocRequestBytes)
	var req pocRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	in := req.input()
	if strings.TrimSpace(in.Source) == "" {
		in.Source = "manual"
	}
	p, err := pg.CreatePOC(in)
	if err != nil {
		writePocError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) updatePOC(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad poc id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPocRequestBytes)
	var req pocRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	in := req.input()
	if strings.TrimSpace(in.Source) == "" {
		in.Source = "manual"
	}
	p, err := pg.UpdatePOC(id, in)
	if err != nil {
		writePocError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) togglePOC(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad poc id")
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil || req.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "enabled 必填")
		return
	}
	p, err := pg.SetPOCEnabled(id, *req.Enabled)
	if err != nil {
		writePocError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) deletePOC(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad poc id")
		return
	}
	deleted, err := pg.DeletePOC(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !deleted {
		writeErr(w, http.StatusNotFound, "PoC 不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) pocStats(w http.ResponseWriter, _ *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	stats, err := pg.PocStats()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// ---- import ----

type pocImportError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

type pocImportOutcome struct {
	Inserted int              `json:"inserted"`
	Updated  int              `json:"updated"`
	Failed   int              `json:"failed"`
	Errors   []pocImportError `json:"errors,omitempty"`
	Formats  map[string]int   `json:"formats,omitempty"`
}

func newPocImportOutcome() *pocImportOutcome {
	return &pocImportOutcome{Formats: map[string]int{}}
}

func (o *pocImportOutcome) fail(file string, err error) {
	o.Failed++
	if len(o.Errors) < 50 {
		o.Errors = append(o.Errors, pocImportError{File: file, Error: err.Error()})
	}
}

type pocImportItem struct {
	Name string
	Data []byte
}

func importPocItems(pg *db.DB, items []pocImportItem) *pocImportOutcome {
	out := newPocImportOutcome()
	for _, it := range items {
		res, err := parsePocFile(it.Name, it.Data)
		if err != nil {
			out.fail(it.Name, err)
			continue
		}
		out.Formats[res.Format]++
		for _, in := range res.Inputs {
			if strings.TrimSpace(in.Source) == "" {
				in.Source = res.Format
			}
			_, inserted, err := pg.UpsertPOC(in)
			if err != nil {
				out.fail(it.Name, err)
				continue
			}
			if inserted {
				out.Inserted++
			} else {
				out.Updated++
			}
		}
	}
	return out
}

// importPOCs accepts multipart file uploads (field "files" / "file"), or a JSON
// body: either a bare array of PoC objects or {"pocs": [...]}. JSON entries are
// metered through the same db store so dedup semantics are identical.
func (s *Server) importPOCs(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPocImportBytes)
	ctype := strings.ToLower(r.Header.Get("Content-Type"))

	if strings.HasPrefix(ctype, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			writeErr(w, http.StatusBadRequest, "解析上传表单失败: "+err.Error())
			return
		}
		var items []pocImportItem
		collect := func(fhs []*multipart.FileHeader) {
			for _, fh := range fhs {
				if len(items) >= pocImportMaxFiles {
					return
				}
				f, err := fh.Open()
				if err != nil {
					continue
				}
				data, err := io.ReadAll(io.LimitReader(f, maxPocImportFile+1))
				_ = f.Close()
				if err != nil {
					continue
				}
				if len(data) > maxPocImportFile {
					continue // oversized files are skipped; per-file errors are noise here
				}
				items = append(items, pocImportItem{Name: fh.Filename, Data: data})
			}
		}
		if r.MultipartForm != nil {
			collect(r.MultipartForm.File["files"])
			collect(r.MultipartForm.File["file"])
		}
		if len(items) == 0 {
			writeErr(w, http.StatusBadRequest, "没有收到文件（表单字段应为 files）")
			return
		}
		out := importPocItems(pg, items)
		writeJSON(w, http.StatusOK, out)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxPocImportBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	reqs, err := parsePocJSONRequests(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out := newPocImportOutcome()
	for _, req := range reqs {
		in := req.input()
		if strings.TrimSpace(in.Name) == "" {
			out.fail("json", fmt.Errorf("name 不能为空"))
			continue
		}
		if strings.TrimSpace(in.Source) == "" {
			in.Source = "json"
		}
		// JSON imports carry no filename; derive the stable identity from content.
		in.NKey = pocEntryKey(in.Name, in.Product, in.VulnType, in.Content)
		_, inserted, err := pg.UpsertPOC(in)
		if err != nil {
			out.fail(in.Name, err)
			continue
		}
		if inserted {
			out.Inserted++
		} else {
			out.Updated++
		}
	}
	out.Formats["json"] = len(reqs)
	writeJSON(w, http.StatusOK, out)
}

func parsePocJSONRequests(raw []byte) ([]pocRequest, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("请求正文为空")
	}
	if trimmed[0] == '[' {
		var arr []pocRequest
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var envelope struct {
		Pocs  []pocRequest `json:"pocs"`
		Items []pocRequest `json:"items"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Pocs) > 0 {
		return envelope.Pocs, nil
	}
	if len(envelope.Items) > 0 {
		return envelope.Items, nil
	}
	var single pocRequest
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, err
	}
	return []pocRequest{single}, nil
}

var pocBinaryExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".bmp": true, ".ico": true,
	".zip": true, ".gz": true, ".tar": true, ".7z": true, ".rar": true, ".bz2": true, ".xz": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".bin": true, ".class": true, ".jar": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".mp3": true, ".mp4": true, ".mov": true,
	".wasm": true, ".pyc": true, ".o": true, ".a": true, ".db": true, ".sqlite": true,
}

// importPOCDir walks a server-side directory (a cloned nuclei-templates / PoC
// repo is the common case) and imports every text file. Symlinks and hidden /
// heavy directories are skipped; the API is authenticated, so the path is
// treated as operator-provided input.
func (s *Server) importPOCDir(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Path      string   `json:"path"`
		Recursive *bool    `json:"recursive"`
		Exts      []string `json:"exts"` // optional whitelist, e.g. [".yaml",".yml"]
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	root := strings.TrimSpace(req.Path)
	if root == "" {
		writeErr(w, http.StatusBadRequest, "path 不能为空")
		return
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "路径无效: "+err.Error())
		return
	}
	info, err := os.Stat(abs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "路径不存在: "+err.Error())
		return
	}
	if !info.IsDir() {
		writeErr(w, http.StatusBadRequest, "path 必须是目录")
		return
	}
	recursive := true
	if req.Recursive != nil {
		recursive = *req.Recursive
	}
	exts := map[string]bool{}
	for _, e := range req.Exts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		exts[e] = true
	}

	out := newPocImportOutcome()
	scanned := 0
	stop := errors.New("stop")
	_ = filepath.WalkDir(abs, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if path != abs {
				base := d.Name()
				if strings.HasPrefix(base, ".") || base == "node_modules" || base == "vendor" {
					return filepath.SkipDir
				}
				if !recursive {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if scanned >= pocImportMaxFiles {
			return stop
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if strings.HasPrefix(d.Name(), ".") || pocBinaryExt[ext] {
			return nil
		}
		if len(exts) > 0 && !exts[ext] {
			return nil
		}
		st, err := d.Info()
		if err != nil || st.Size() == 0 || st.Size() > maxPocImportFile {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			out.fail(path, err)
			return nil
		}
		scanned++
		rel, _ := filepath.Rel(abs, path)
		res, err := parsePocFile(rel, data)
		if err != nil {
			out.fail(rel, err)
			return nil
		}
		out.Formats[res.Format]++
		for _, in := range res.Inputs {
			if strings.TrimSpace(in.Source) == "" {
				in.Source = res.Format
			}
			_, inserted, err := pg.UpsertPOC(in)
			if err != nil {
				out.fail(rel, err)
				continue
			}
			if inserted {
				out.Inserted++
			} else {
				out.Updated++
			}
		}
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"path":     abs,
		"scanned":  scanned,
		"inserted": out.Inserted,
		"updated":  out.Updated,
		"failed":   out.Failed,
		"errors":   out.Errors,
		"formats":  out.Formats,
	})
}
