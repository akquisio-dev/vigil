package server

import (
	"net/netip"
	"os"
	"runtime"
	"testing"
)

// VIGIL_GEO_DIR=<dir with country.csv.gz and asn.csv.gz> go test -run TestGeoLive
func TestGeoLive(t *testing.T) {
	dir := os.Getenv("VIGIL_GEO_DIR")
	if dir == "" {
		t.Skip("VIGIL_GEO_DIR not set")
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	db, err := loadGeo(dir)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("heap %.1f MB for %d+%d country and %d+%d AS ranges, %d networks", float64(after.HeapAlloc-before.HeapAlloc)/(1<<20),
		len(db.c4Start), len(db.c6Start), len(db.a4Start), len(db.a6Start), len(db.as))
	for _, ip := range []string{"1.1.1.1", "5.9.1.1", "159.65.92.56", "2a01:4f8::1", "8.8.8.8", "10.0.0.1"} {
		cc, as := db.lookup(netip.MustParseAddr(ip))
		if as != nil {
			t.Logf("%s %s AS%d %s hosting=%v", ip, cc, as.ASN, as.Org, hostingOrg(as.Org))
		} else {
			t.Logf("%s %s", ip, cc)
		}
	}
}

func TestHostingOrg(t *testing.T) {
	yes := []string{"DigitalOcean, LLC", "Hetzner Online GmbH", "Amazon Data Services Ireland Ltd", "Google LLC", "OVH SAS", "Interserver, Inc",
		"Tencent Building, Kejizhongyi Avenue", "Alibaba US Technology Co., Ltd.", "Microsoft Corporation", "NexonHost SRL", "Contabo GmbH", "Flexential Colorado Corp. colo"}
	no := []string{"Deutsche Telekom AG", "FIBERCOM COLOMBIA S.A.S", "Politechnika Warszawska", "AMAZONIA TELECOMUNICACOES LTDA", "Google Fiber Inc.",
		"1&1 Versatel GmbH", "Comcast Cable Communications, LLC", "China Telecom", "Vodafone GmbH", "Colorado Housing and Finance Authority"}
	for _, o := range yes {
		if !hostingOrg(o) {
			t.Errorf("%s: want hosting", o)
		}
	}
	for _, o := range no {
		if hostingOrg(o) {
			t.Errorf("%s: not hosting", o)
		}
	}
}
