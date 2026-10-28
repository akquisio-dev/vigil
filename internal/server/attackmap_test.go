package server

import (
	"compress/gzip"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAttackMap(t *testing.T) {
	s := forensicServer(t)
	now := time.Now().UTC()
	appendAt(t, s, "a2", now.Add(-time.Hour), "ssh.failed", map[string]any{"ip": "198.51.100.7", "count": float64(30), "users": anyList("root", "admin")})
	appendAt(t, s, "a2", now.AddDate(0, 0, -2), "ssh.failed", map[string]any{"ip": "203.0.113.9", "count": float64(4), "users": anyList("oracle")})
	appendAt(t, s, "a1", now.Add(-time.Hour), "web.activity", map[string]any{"ip": "198.51.100.8", "requests": float64(9), "probes": float64(4)})
	s.startAttacks()
	waitAttacks(t, s)
	handler := func(w http.ResponseWriter, r *http.Request) { s.handleAttackMap(w, r, &session{User: "u"}) }

	type mapView struct {
		Cols      []string `json:"cols"`
		Rows      [][]any  `json:"rows"`
		Total     int      `json:"total"`
		Truncated bool     `json:"truncated"`
	}
	var v mapView
	if code := getJSON(t, handler, "/api/ui/attacks/map?days=7", nil, &v); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(v.Rows) != 3 || v.Total != 3 || v.Truncated {
		t.Fatalf("rows %d of %d, truncated %v", len(v.Rows), v.Total, v.Truncated)
	}
	col := map[string]int{}
	for i, c := range v.Cols {
		col[c] = i
	}
	for _, r := range v.Rows {
		// the columns and the rows must not drift apart
		if len(r) != len(v.Cols) {
			t.Fatalf("row with %d fields for %d columns: %v", len(r), len(v.Cols), r)
		}
		if r[col["lat"]] != nil || r[col["lon"]] != nil {
			t.Errorf("%v placed without city data", r[col["ip"]])
		}
	}
	// busiest first
	if v.Rows[0][col["ip"]] != "198.51.100.7" || v.Rows[0][col["ssh"]] != float64(30) {
		t.Errorf("first row %v", v.Rows[0])
	}
	if code := getJSON(t, handler, "/api/ui/attacks/map?days=7&agent=nope", nil, &v); code != http.StatusNotFound {
		t.Errorf("unknown agent: status %d", code)
	}

	// with the city data the rows say where the address is
	dir := filepath.Join(s.cfg.DataDir, "geo")
	os.MkdirAll(dir, 0o700)
	gz := filepath.Join(dir, "city.csv.gz")
	f, _ := os.Create(gz)
	zw := gzip.NewWriter(f)
	zw.Write([]byte("0.0.0.0,198.51.99.255,ZZ,ZZ,,,0,0\n198.51.100.0,198.51.100.255,EU,DE,Hessen,Frankfurt,50.11,8.68\n198.51.101.0,255.255.255.255,ZZ,ZZ,,,0,0\n"))
	zw.Close()
	f.Close()
	if _, _, err := buildCity(gz, cityFile(dir)); err != nil {
		t.Fatal(err)
	}
	db, err := openCity(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.geodb.city.Store(db)
	defer db.close()
	getJSON(t, handler, "/api/ui/attacks/map?days=7", nil, &v)
	placed := 0
	for _, r := range v.Rows {
		if r[col["lat"]] != nil {
			placed++
			if r[col["lat"]] != 50.11 || r[col["lon"]] != 8.68 {
				t.Errorf("%v at %v %v", r[col["ip"]], r[col["lat"]], r[col["lon"]])
			}
		}
	}
	if placed != 2 {
		t.Errorf("%d placed, want the two in 198.51.100.0/24", placed)
	}
}
