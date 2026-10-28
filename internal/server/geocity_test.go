package server

import (
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCityTable(t *testing.T) {
	dir := t.TempDir()
	csv := `0.0.0.0,0.255.255.255,ZZ,ZZ,,,0,0
1.0.0.0,1.0.0.255,OC,AU,Queensland,"South Brisbane",-27.4767,153.017
1.0.1.0,1.0.1.255,AS,CN,Fujian,Wenquan,26.0998,119.297
1.0.2.0,1.0.3.255,AS,CN,Fujian,Wenquan,26.1001,119.2968
1.0.4.0,1.255.255.255,EU,DE,Hessen,"Frankfurt am Main",50.1109,8.68213
2.0.0.0,255.255.255.255,ZZ,ZZ,,,0,0
::,2a00:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ,ZZ,,,0,0
2a01::,2a01:4f8:ffff:ffff:ffff:ffff:ffff:ffff,EU,DE,Bayern,Gunzenhausen,49.1166,10.7542
2a01:4f9::,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ,ZZ,,,0,0
`
	gz := filepath.Join(dir, "city.csv.gz")
	f, _ := os.Create(gz)
	zw := gzip.NewWriter(f)
	zw.Write([]byte(csv))
	zw.Close()
	f.Close()
	n4, n6, err := buildCity(gz, cityFile(dir))
	if err != nil {
		t.Fatal(err)
	}
	// the two Fujian ranges round to the same place and become one record
	if n4 != 5 || n6 != 3 {
		t.Errorf("records %d + %d, want 5 + 3", n4, n6)
	}
	db, err := openCity(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()
	for _, c := range []struct {
		ip       string
		lat, lon float32
		ok       bool
	}{
		{"0.1.2.3", 0, 0, false}, {"1.0.0.7", -27.48, 153.02, true}, {"1.0.3.9", 26.1, 119.3, true}, {"1.200.0.1", 50.11, 8.68, true},
		{"8.8.8.8", 0, 0, false}, {"2a01:4f8::1", 49.12, 10.75, true}, {"2001:db8::1", 0, 0, false}, {"::ffff:1.0.0.7", -27.48, 153.02, true},
	} {
		for range 2 { // the second time from the cache
			lat, lon, ok := db.lookup(netip.MustParseAddr(c.ip))
			if ok != c.ok || ok && (lat != c.lat || lon != c.lon) {
				t.Errorf("%s: %v %v %v, want %v %v %v", c.ip, lat, lon, ok, c.lat, c.lon, c.ok)
			}
		}
	}
	os.WriteFile(cityFile(dir), []byte("VGC1 broken"), 0o600)
	if _, err := openCity(dir); err == nil {
		t.Error("a broken table opened")
	}
}

// VIGIL_CITY_CSV=<dbip-city-lite-....csv.gz> go test -run TestCityLive
func TestCityLive(t *testing.T) {
	src := os.Getenv("VIGIL_CITY_CSV")
	if src == "" {
		t.Skip("VIGIL_CITY_CSV not set")
	}
	dir := t.TempDir()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	n4, n6, err := buildCity(src, cityFile(dir))
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	st, _ := os.Stat(cityFile(dir))
	t.Logf("%d + %d records, %.1f MB, built in %s, %.1f MB allocated in all", n4, n6, float64(st.Size())/(1<<20), time.Since(start).Round(time.Millisecond),
		float64(after.TotalAlloc-before.TotalAlloc)/(1<<20))
	db, err := openCity(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()
	start = time.Now()
	for _, ip := range []string{"1.1.1.1", "5.9.1.1", "159.65.92.56", "2a01:4f8::1", "8.8.8.8", "82.165.153.153", "138.2.170.75"} {
		lat, lon, ok := db.lookup(netip.MustParseAddr(ip))
		t.Logf("%s %v %v %v", ip, lat, lon, ok)
	}
	t.Logf("7 lookups in %s", time.Since(start))
}
