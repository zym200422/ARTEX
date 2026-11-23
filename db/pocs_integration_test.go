package db

import (
	"os"
	"testing"
)

// TestPocStoreIntegration exercises the SQL surface (arrays, ILIKE escaping,
// upsert identity, xmax inserted flag) against a live PostgreSQL. It is opt-in:
// set ARTEX_POC_IT=1 and point ARTEX_PG_DSN at a throwaway database. Normal
// `go test ./db` runs skip it so the developer's dev DB is untouched.
func TestPocStoreIntegration(t *testing.T) {
	if os.Getenv("ARTEX_POC_IT") != "1" {
		t.Skip("set ARTEX_POC_IT=1 with a throwaway ARTEX_PG_DSN to run")
	}
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	if _, err := d.Exec(`TRUNCATE pocs`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	created, err := d.CreatePOC(PocInput{
		Name:     "Apache Log4j2 JNDI RCE",
		CVE:      []string{"CVE-2021-44228"},
		Product:  "log4j",
		VulnType: "rce",
		Severity: "critical",
		Tags:     []string{"log4j", "java"},
		Content:  "GET / HTTP/1.1\nHost: {{Hostname}}",
		Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == 0 || !created.Enabled {
		t.Fatalf("created=%+v", created)
	}
	if _, err := d.CreatePOC(PocInput{Name: created.Name, Content: created.Content}); err != ErrPocNameConflict {
		t.Fatalf("duplicate identity err=%v want conflict", err)
	}

	// Content is omitted from list results unless requested.
	list, total, err := d.SearchPOCs(PocFilter{Query: "log4j rce", Limit: 10})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if total != 1 || len(list) != 1 || list[0].Content != "" {
		t.Fatalf("list total=%d len=%d content=%q", total, len(list), list[0].Content)
	}
	withContent, _, err := d.SearchPOCs(PocFilter{Query: "log4j", WithContent: true, Limit: 10})
	if err != nil || len(withContent) != 1 || withContent[0].Content == "" {
		t.Fatalf("with content err=%v got=%+v", err, withContent)
	}
	if hits, _, err := d.SearchPOCs(PocFilter{CVE: "cve-2021-44228", Limit: 10}); err != nil || len(hits) != 1 {
		t.Fatalf("cve filter err=%v hits=%d", err, len(hits))
	}
	if hits, _, err := d.SearchPOCs(PocFilter{Tag: "java", Severity: "critical", Limit: 10}); err != nil || len(hits) != 1 {
		t.Fatalf("tag/severity filter err=%v hits=%d", err, len(hits))
	}
	// Wildcards in the query are literals, not SQL LIKE wildcards.
	if hits, _, err := d.SearchPOCs(PocFilter{Query: "50%_off", Limit: 10}); err != nil || len(hits) != 0 {
		t.Fatalf("wildcard escaping err=%v hits=%d", err, len(hits))
	}
	// Disabled entries are excluded when the filter says enabled=true.
	if _, err := d.SetPOCEnabled(created.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	yes := true
	if hits, _, err := d.SearchPOCs(PocFilter{Enabled: &yes, Limit: 10}); err != nil || len(hits) != 0 {
		t.Fatalf("enabled filter err=%v hits=%d", err, len(hits))
	}

	updated, err := d.UpdatePOC(created.ID, PocInput{
		Name: created.Name, CVE: created.CVE, Product: "log4j", VulnType: "rce", Severity: "high",
		Tags: created.Tags, Content: created.Content + "\n# updated", Enabled: &yes,
	})
	if err != nil || updated.Severity != "high" || !updated.Enabled {
		t.Fatalf("update err=%v got=%+v", err, updated)
	}

	// Upsert: same nkey updates in place, new nkey inserts.
	id1, inserted, err := d.UpsertPOC(PocInput{NKey: "it:one", Name: "IT One", Content: "a"})
	if err != nil || !inserted {
		t.Fatalf("upsert1 id=%d inserted=%v err=%v", id1, inserted, err)
	}
	id2, inserted2, err := d.UpsertPOC(PocInput{NKey: "it:one", Name: "IT One", Content: "b"})
	if err != nil || inserted2 || id2 != id1 {
		t.Fatalf("upsert2 id=%d inserted=%v err=%v", id2, inserted2, err)
	}

	stats, err := d.PocStats()
	if err != nil || stats.Total != 2 || stats.WithCVE != 1 {
		t.Fatalf("stats err=%v got=%+v", err, stats)
	}
	if _, err := d.DeletePOC(id1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, _ := d.GetPOC(id1); got != nil {
		t.Fatal("deleted poc still readable")
	}
}
