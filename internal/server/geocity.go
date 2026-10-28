package server

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Where in a country an address is, for the provinces and places of the
// attackers map: the free DB-IP city database (CC BY 4.0, about 85 MB a
// month) is turned once into city.bin, a sorted table of range starts and
// coordinates rounded to a hundredth of a degree, and looked up on disk.
// It never goes into memory: only the attacking addresses are looked up,
// with a small cache. Names of places are left out; the map has its own.

const (
	geoCityURL   = "https://download.db-ip.com/free/dbip-city-lite-%s.csv.gz"
	cityMagic    = "VGC1"
	cityHeader   = 16 // magic, IPv4 records, IPv6 records
	cityRec4     = 8  // start uint32, lat int16, lon int16
	cityRec6     = 12 // upper 64 bits of the start, lat int16, lon int16
	cityNone     = math.MaxInt16
	cityCacheMax = 50000
)

type cityDB struct {
	f      *os.File
	n4, n6 int64
	month  string

	mu    sync.Mutex
	cache map[netip.Addr][2]float32
}

// cityFile is city.bin in the geo directory.
func cityFile(dir string) string { return filepath.Join(dir, "city.bin") }

func openCity(dir string) (*cityDB, error) {
	f, err := os.Open(cityFile(dir))
	if err != nil {
		return nil, err
	}
	var hd [cityHeader]byte
	if _, err := f.ReadAt(hd[:], 0); err != nil || string(hd[:4]) != cityMagic {
		f.Close()
		return nil, errors.New("city.bin: not a city table")
	}
	db := &cityDB{f: f, n4: int64(binary.BigEndian.Uint32(hd[4:])), n6: int64(binary.BigEndian.Uint64(hd[8:])), cache: map[netip.Addr][2]float32{}}
	if st, err := f.Stat(); err != nil || st.Size() != cityHeader+db.n4*cityRec4+db.n6*cityRec6 {
		f.Close()
		return nil, errors.New("city.bin: wrong size")
	}
	m, _ := os.ReadFile(cityFile(dir) + ".month")
	db.month = strings.TrimSpace(string(m))
	return db, nil
}

func (db *cityDB) close() { db.f.Close() }

// lookup gives latitude and longitude, ok false when the address is not
// placed.
func (db *cityDB) lookup(a netip.Addr) (lat, lon float32, ok bool) {
	a = a.Unmap()
	db.mu.Lock()
	if c, hit := db.cache[a]; hit {
		db.mu.Unlock()
		return c[0], c[1], !math.IsNaN(float64(c[0]))
	}
	db.mu.Unlock()
	var buf [cityRec6]byte
	read := func(off int64, n int) bool { _, err := db.f.ReadAt(buf[:n], off); return err == nil }
	var base, n, size int64
	var key uint64
	if a.Is4() {
		base, n, size, key = cityHeader, db.n4, cityRec4, uint64(addr4(a))
	} else {
		base, n, size, key = cityHeader+db.n4*cityRec4, db.n6, cityRec6, addr6(a)
	}
	start := func(i int64) (uint64, bool) {
		if !read(base+i*size, int(size)) {
			return 0, false
		}
		if size == cityRec4 {
			return uint64(binary.BigEndian.Uint32(buf[:4])), true
		}
		return binary.BigEndian.Uint64(buf[:8]), true
	}
	// the last record that starts at or before the address
	lo, hi := int64(0), n
	for lo < hi {
		mid := (lo + hi) / 2
		s, good := start(mid)
		if !good {
			return 0, 0, false
		}
		if s <= key {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	lat, lon = float32(math.NaN()), float32(math.NaN())
	if lo > 0 {
		if _, good := start(lo - 1); good {
			p := buf[size-4 : size]
			y, x := int16(binary.BigEndian.Uint16(p)), int16(binary.BigEndian.Uint16(p[2:]))
			if y != cityNone {
				lat, lon = float32(y)/100, float32(x)/100
			}
		}
	}
	db.mu.Lock()
	if len(db.cache) >= cityCacheMax {
		clear(db.cache)
	}
	db.cache[a] = [2]float32{lat, lon}
	db.mu.Unlock()
	return lat, lon, !math.IsNaN(float64(lat))
}

// buildCity turns the downloaded CSV into city.bin, record by record, so
// memory stays flat. Neighbouring ranges at the same rounded place become
// one record.
func buildCity(csvPath, out string) (n4, n6 int64, err error) {
	tmp4, tmp6 := out+".4.tmp", out+".6.tmp"
	defer os.Remove(tmp4)
	defer os.Remove(tmp6)
	f4, err := os.Create(tmp4)
	if err != nil {
		return 0, 0, err
	}
	defer f4.Close()
	f6, err := os.Create(tmp6)
	if err != nil {
		return 0, 0, err
	}
	defer f6.Close()
	w4, w6 := bufio.NewWriterSize(f4, 1<<16), bufio.NewWriterSize(f6, 1<<16)
	var last4, last6 [2]int16
	have4, have6 := false, false
	var prev4 uint32
	var prev6 uint64
	round := func(s string, lim float64) int16 {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil || math.Abs(v) > lim {
			return cityNone
		}
		return int16(math.Round(v * 100))
	}
	err = readGeoCSV(csvPath, func(start, _ netip.Addr, rec []string) error {
		if len(rec) < 8 {
			return nil
		}
		p := [2]int16{round(rec[6], 90), round(rec[7], 180)}
		if rec[3] == "ZZ" || p[0] == cityNone || p[1] == cityNone || (rec[6] == "0" && rec[7] == "0") {
			p = [2]int16{cityNone, cityNone}
		}
		var b [cityRec6]byte
		if start.Is4() {
			x := addr4(start)
			if have4 && (x < prev4 || p == last4) {
				if x < prev4 {
					return errors.New("city data is not sorted by address")
				}
				return nil
			}
			binary.BigEndian.PutUint32(b[:], x)
			binary.BigEndian.PutUint16(b[4:], uint16(p[0]))
			binary.BigEndian.PutUint16(b[6:], uint16(p[1]))
			w4.Write(b[:cityRec4])
			prev4, last4, have4 = x, p, true
			n4++
			return nil
		}
		x := addr6(start)
		if have6 && (x < prev6 || p == last6) {
			if x < prev6 {
				return errors.New("city data is not sorted by address")
			}
			return nil
		}
		binary.BigEndian.PutUint64(b[:], x)
		binary.BigEndian.PutUint16(b[8:], uint16(p[0]))
		binary.BigEndian.PutUint16(b[10:], uint16(p[1]))
		w6.Write(b[:])
		prev6, last6, have6 = x, p, true
		n6++
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	if n4 == 0 {
		return 0, 0, errors.New("city data is empty")
	}
	if err := w4.Flush(); err != nil {
		return 0, 0, err
	}
	if err := w6.Flush(); err != nil {
		return 0, 0, err
	}
	tmp := out + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, 0, err
	}
	defer os.Remove(tmp)
	w := bufio.NewWriterSize(f, 1<<16)
	var hd [cityHeader]byte
	copy(hd[:], cityMagic)
	binary.BigEndian.PutUint32(hd[4:], uint32(n4))
	binary.BigEndian.PutUint64(hd[8:], uint64(n6))
	w.Write(hd[:])
	for _, src := range []*os.File{f4, f6} {
		if _, err := src.Seek(0, 0); err != nil {
			f.Close()
			return 0, 0, err
		}
		if _, err := w.ReadFrom(src); err != nil {
			f.Close()
			return 0, 0, err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return 0, 0, err
	}
	if err := f.Close(); err != nil {
		return 0, 0, err
	}
	return n4, n6, os.Rename(tmp, out)
}

// refreshCity loads city.bin and fetches a newer month once a day at most.
// Called from refreshGeo; the conversion takes a while, so only one runs.
func (s *Server) refreshCity(dir string, now time.Time) {
	if !s.cfg.geoCity() || !s.geodb.cityBusy.CompareAndSwap(false, true) {
		return
	}
	defer s.geodb.cityBusy.Store(false)
	have := s.geodb.city.Load()
	if have == nil {
		if db, err := openCity(dir); err == nil {
			s.geodb.city.Store(db)
			have = db
			log.Printf("geoip: city data %s", db.month)
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Printf("geoip city: %v", err)
		}
	}
	cur := now.Format("2006-01")
	if have != nil && have.month == cur {
		return
	}
	if last := s.geodb.cityTry.Load(); last != 0 && now.Sub(time.Unix(last, 0)) < 24*time.Hour {
		return
	}
	s.geodb.cityTry.Store(now.Unix())
	client := &http.Client{Timeout: 10 * time.Minute}
	gz := filepath.Join(dir, "city.csv.gz")
	defer os.Remove(gz)
	defer os.Remove(gz + ".month")
	var err error
	got := ""
	for _, month := range []string{cur, now.AddDate(0, 0, -now.Day()).Format("2006-01")} {
		if have != nil && month <= have.month {
			return
		}
		if err = downloadFile(client, fmt.Sprintf(geoCityURL, month), gz, month); err == nil {
			got = month
			break
		}
	}
	if got == "" {
		log.Printf("geoip city: %s", fwdRedact(err))
		s.geodb.err.Store("city: " + fwdRedact(err))
		return
	}
	n4, n6, err := buildCity(gz, cityFile(dir))
	if err == nil {
		err = os.WriteFile(cityFile(dir)+".month", []byte(got), 0o600)
	}
	var db *cityDB
	if err == nil {
		db, err = openCity(dir)
	}
	if err != nil {
		log.Printf("geoip city: %v", err)
		s.geodb.err.Store("city: " + err.Error())
		return
	}
	if old := s.geodb.city.Swap(db); old != nil {
		old.close()
	}
	log.Printf("geoip: city data %s, %d + %d ranges", got, n4, n6)
}

// place gives where an address is, ok false without city data.
func (s *Server) place(ip string) (lat, lon float32, ok bool) {
	db := s.geodb.city.Load()
	if db == nil {
		return 0, 0, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return 0, 0, false
	}
	return db.lookup(a)
}
