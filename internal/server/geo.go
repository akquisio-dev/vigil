package server

import (
	"compress/gzip"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

// Where attacking addresses come from (geoip): the server downloads the
// free DB-IP Lite databases (country and AS, CC BY 4.0) once a month and
// looks addresses up locally, so no address ever leaves the server. Pages
// that show the results link to DB-IP as the licence asks.
//
// The tables are kept compact: about 1.2 million ranges take some 15 MB.
// IPv6 ranges are compared on their upper 64 bits, which no allocation is
// finer than.

const (
	geoCountryURL     = "https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz"
	geoASNURL         = "https://download.db-ip.com/free/dbip-asn-lite-%s.csv.gz"
	geoMaxDownload    = 128 << 20
	GeoAttribution    = "IP Geolocation by DB-IP"
	GeoAttributionURL = "https://db-ip.com"
)

type geoAS struct {
	ASN uint32
	Org string
}

type geoDB struct {
	ccs []string // country codes by index

	c4Start []uint32
	c4CC    []uint16
	c6Start []uint64
	c6CC    []uint16

	as                    []geoAS
	a4Start, a4End        []uint32
	a4AS                  []uint32
	a6Start, a6End        []uint64
	a6AS                  []uint32
	countryMonth, asMonth string
}

// GeoInfo is what is known about an address.
type GeoInfo struct {
	Country string `json:"country,omitempty"`
	ASN     uint32 `json:"asn,omitempty"`
	Org     string `json:"org,omitempty"`
	// Net is "tor" (on the Tor exit list), "hosting" (the network's name is
	// one of a data centre or cloud, an estimate) or empty.
	Net string `json:"net,omitempty"`
}

type geoState struct {
	db      atomic.Pointer[geoDB]
	lastTry atomic.Int64
	err     atomic.Value // string
}

func addr4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func addr6(a netip.Addr) uint64 {
	b := a.As16()
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func (g *geoDB) lookup(a netip.Addr) (cc string, as *geoAS) {
	a = a.Unmap()
	if a.Is4() {
		x := addr4(a)
		if i := sort.Search(len(g.c4Start), func(i int) bool { return g.c4Start[i] > x }) - 1; i >= 0 {
			cc = g.ccs[g.c4CC[i]]
		}
		if i := sort.Search(len(g.a4Start), func(i int) bool { return g.a4Start[i] > x }) - 1; i >= 0 && g.a4End[i] >= x {
			as = &g.as[g.a4AS[i]]
		}
	} else {
		x := addr6(a)
		if i := sort.Search(len(g.c6Start), func(i int) bool { return g.c6Start[i] > x }) - 1; i >= 0 {
			cc = g.ccs[g.c6CC[i]]
		}
		if i := sort.Search(len(g.a6Start), func(i int) bool { return g.a6Start[i] > x }) - 1; i >= 0 && g.a6End[i] >= x {
			as = &g.as[g.a6AS[i]]
		}
	}
	if cc == "ZZ" {
		cc = ""
	}
	return cc, as
}

// geo looks an address up. Without geoip only Tor exits are known.
func (s *Server) geo(ip string) GeoInfo {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return GeoInfo{}
	}
	var gi GeoInfo
	if db := s.geodb.db.Load(); db != nil {
		cc, as := db.lookup(a)
		gi.Country = cc
		if as != nil {
			gi.ASN, gi.Org = as.ASN, as.Org
			if hostingOrg(as.Org) {
				gi.Net = "hosting"
			}
		}
	}
	if list, ok := s.intel.lookup(ip); ok && list == "tor-exit" {
		gi.Net = "tor"
	}
	return gi
}

// Network names of data centres and clouds. Attacks from them come from
// rented or hijacked machines, not from someone's home connection. It is an
// estimate: the free data has no network type, so the name decides.
var (
	// a word of the name contains one of these
	hostingParts = []string{"host", "server", "cloud", "vps", "datacenter"}
	// a word of the name is one of these
	hostingNames = map[string]bool{}
	// the name contains one of these
	hostingPhrases = []string{"data center", "data centre", "constant company", "online s.a.s", "stark industries",
		"amazon data services", "amazon technologies", "amazon.com", "google llc", "google, llc", "google cloud", "strato ag",
		"sakura internet", "global connectivity solutions", "limestone networks", "1&1 ionos", "dedicated.com",
		"latitude.sh", "volcano engine"}
)

func init() {
	for _, w := range strings.Fields("colo colocation aws ovh hetzner linode akamai vultr choopa contabo leaseweb m247 scaleway " +
		"ionos netcup psychz quadranet colocrossing frantech gcore g-core aeza selectel timeweb kamatera upcloud worldstream " +
		"serverius nforce zenlayer cloudflare fastly datacamp equinix rackspace ikoula kingsoft digitalocean alibaba tencent " +
		"huawei baidu ucloud oracle microsoft azure vdsina firstbyte ishosting tzulo censys shodan srv unmanaged bytedance") {
		hostingNames[w] = true
	}
}

func hostingOrg(org string) bool {
	o := strings.ToLower(org)
	for _, p := range hostingPhrases {
		if strings.Contains(o, p) {
			return true
		}
	}
	for _, w := range strings.FieldsFunc(o, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' }) {
		if hostingNames[w] {
			return true
		}
		for _, p := range hostingParts {
			if strings.Contains(w, p) {
				return true
			}
		}
	}
	return false
}

// refreshGeo loads the databases from disk and downloads a newer month's
// once a day at most. Called at start and every hour.
func (s *Server) refreshGeo() {
	if !s.cfg.GeoIP {
		return
	}
	dir := filepath.Join(s.cfg.DataDir, "geo")
	os.MkdirAll(dir, 0o700)
	now := time.Now().UTC()
	cur := now.Format("2006-01")
	have := s.geodb.db.Load()
	if have == nil {
		if db, err := loadGeo(dir); err == nil {
			s.geodb.db.Store(db)
			have = db
			log.Printf("geoip: country data %s, AS data %s", db.countryMonth, db.asMonth)
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Printf("geoip: %v", err)
		}
	}
	if have != nil && have.countryMonth == cur && have.asMonth == cur {
		return
	}
	if last := s.geodb.lastTry.Load(); last != 0 && now.Sub(time.Unix(last, 0)) < 24*time.Hour && have != nil {
		return
	}
	s.geodb.lastTry.Store(now.Unix())
	client := &http.Client{Timeout: 5 * time.Minute}
	prev := now.AddDate(0, 0, -now.Day()).Format("2006-01")
	got := false
	for _, f := range []struct{ name, url string }{{"country", geoCountryURL}, {"asn", geoASNURL}} {
		var err error
		for _, month := range []string{cur, prev} {
			if have != nil && month <= map[string]string{"country": have.countryMonth, "asn": have.asMonth}[f.name] {
				err = nil
				break
			}
			if err = downloadFile(client, fmt.Sprintf(f.url, month), filepath.Join(dir, f.name+".csv.gz"), month); err == nil {
				got = true
				break
			}
		}
		if err != nil {
			log.Printf("geoip %s: %s", f.name, fwdRedact(err))
			s.geodb.err.Store(f.name + ": " + fwdRedact(err))
		}
	}
	if !got {
		return
	}
	db, err := loadGeo(dir)
	if err != nil {
		log.Printf("geoip: %v", err)
		s.geodb.err.Store(err.Error())
		return
	}
	s.geodb.db.Store(db)
	s.geodb.err.Store("")
	log.Printf("geoip: country data %s, AS data %s", db.countryMonth, db.asMonth)
}

// downloadFile stores url at path (through a temporary file) and notes the
// month next to it.
func downloadFile(c *http.Client, url, path, month string) error {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "vigil/"+Version+" (+https://github.com/akquisio-dev/vigil)")
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("HTTP %d for %s", res.StatusCode, month)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(res.Body, geoMaxDownload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > geoMaxDownload {
		err = errors.New("download larger than expected")
	}
	if err == nil {
		err = checkGzip(tmp)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.WriteFile(path+".month", []byte(month), 0o600)
}

func checkGzip(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, zr)
	return err
}

func loadGeo(dir string) (*geoDB, error) {
	db := &geoDB{}
	ccIndex := map[string]uint16{}
	cc := func(c string) uint16 {
		if i, ok := ccIndex[c]; ok {
			return i
		}
		c = strings.Clone(c)
		ccIndex[c] = uint16(len(db.ccs))
		db.ccs = append(db.ccs, c)
		return ccIndex[c]
	}
	err := readGeoCSV(filepath.Join(dir, "country.csv.gz"), func(start, _ netip.Addr, rec []string) error {
		if len(rec) < 3 || len(rec[2]) != 2 {
			return nil
		}
		if start.Is4() {
			db.c4Start = append(db.c4Start, addr4(start))
			db.c4CC = append(db.c4CC, cc(rec[2]))
		} else {
			db.c6Start = append(db.c6Start, addr6(start))
			db.c6CC = append(db.c6CC, cc(rec[2]))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	asIndex := map[uint32]uint32{}
	err = readGeoCSV(filepath.Join(dir, "asn.csv.gz"), func(start, end netip.Addr, rec []string) error {
		if len(rec) < 4 {
			return nil
		}
		n, err := strconv.ParseUint(rec[2], 10, 32)
		if err != nil {
			return nil
		}
		i, ok := asIndex[uint32(n)]
		if !ok {
			i = uint32(len(db.as))
			asIndex[uint32(n)] = i
			db.as = append(db.as, geoAS{ASN: uint32(n), Org: strings.Clone(clip(rec[3], 80))})
		}
		if start.Is4() && end.Is4() {
			db.a4Start, db.a4End, db.a4AS = append(db.a4Start, addr4(start)), append(db.a4End, addr4(end)), append(db.a4AS, i)
		} else if start.Is6() && end.Is6() {
			db.a6Start, db.a6End, db.a6AS = append(db.a6Start, addr6(start)), append(db.a6End, addr6(end)), append(db.a6AS, i)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(db.c4Start) == 0 {
		return nil, errors.New("country data is empty")
	}
	// The files are sorted; make sure, since lookups depend on it.
	if !sort.SliceIsSorted(db.c4Start, func(i, j int) bool { return db.c4Start[i] < db.c4Start[j] }) ||
		!sort.SliceIsSorted(db.a4Start, func(i, j int) bool { return db.a4Start[i] < db.a4Start[j] }) ||
		!sort.SliceIsSorted(db.c6Start, func(i, j int) bool { return db.c6Start[i] < db.c6Start[j] }) ||
		!sort.SliceIsSorted(db.a6Start, func(i, j int) bool { return db.a6Start[i] < db.a6Start[j] }) {
		return nil, errors.New("data is not sorted by address")
	}
	db.c4Start, db.c4CC, db.c6Start, db.c6CC = trim(db.c4Start), trim(db.c4CC), trim(db.c6Start), trim(db.c6CC)
	db.a4Start, db.a4End, db.a4AS = trim(db.a4Start), trim(db.a4End), trim(db.a4AS)
	db.a6Start, db.a6End, db.a6AS = trim(db.a6Start), trim(db.a6End), trim(db.a6AS)
	db.as = trim(db.as)
	m, _ := os.ReadFile(filepath.Join(dir, "country.csv.gz.month"))
	db.countryMonth = strings.TrimSpace(string(m))
	m, _ = os.ReadFile(filepath.Join(dir, "asn.csv.gz.month"))
	db.asMonth = strings.TrimSpace(string(m))
	return db, nil
}

func trim[T any](s []T) []T { return append(make([]T, 0, len(s)), s...) }

func readGeoCSV(path string, fn func(start, end netip.Addr, rec []string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	r := csv.NewReader(zr)
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		if len(rec) < 3 {
			continue
		}
		start, err1 := netip.ParseAddr(rec[0])
		end, err2 := netip.ParseAddr(rec[1])
		if err1 != nil || err2 != nil {
			continue
		}
		if err := fn(start, end, rec); err != nil {
			return err
		}
	}
}

func (s *Server) geoStatus() map[string]any {
	out := map[string]any{"enabled": s.cfg.GeoIP, "attribution": GeoAttribution, "attribution_url": GeoAttributionURL}
	if db := s.geodb.db.Load(); db != nil {
		out["country_month"], out["as_month"] = db.countryMonth, db.asMonth
		out["ranges"] = len(db.c4Start) + len(db.c6Start) + len(db.a4Start) + len(db.a6Start)
	}
	if e, _ := s.geodb.err.Load().(string); e != "" {
		out["error"] = e
	}
	return out
}
