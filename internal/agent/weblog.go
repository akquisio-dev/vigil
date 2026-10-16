package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// WebLog is one access log the agent follows (agent.json "web_logs").
type WebLog struct {
	Path string `json:"path"`
	// Format: "combined" (nginx and Apache default) or "json" with the keys
	// remote_addr, request_method, request_uri, status, http_user_agent.
	Format string `json:"format,omitempty"`
	// LoginPaths are paths whose POST requests count as login attempts.
	LoginPaths []string `json:"login_paths,omitempty"`
}

type webRequest struct {
	IP, Method, URI, UA string
	Status              int
}

var combinedRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?`)

func parseWebLine(line, format string) (webRequest, bool) {
	if format == "json" {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			return webRequest{}, false
		}
		st, _ := strconv.Atoi(asText(m["status"]))
		r := webRequest{IP: asText(m["remote_addr"]), Method: asText(m["request_method"]), URI: asText(m["request_uri"]),
			UA: asText(m["http_user_agent"]), Status: st}
		return r, r.IP != "" && r.Status > 0
	}
	m := combinedRe.FindStringSubmatch(line)
	if m == nil {
		return webRequest{}, false
	}
	st, _ := strconv.Atoi(m[4])
	return webRequest{IP: m[1], Method: m[2], URI: m[3], Status: st, UA: m[5]}, true
}

func asText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

// Paths scanners look for. A hit is a probe whatever the status code.
var probeRe = regexp.MustCompile(`(?i)^/(?:[^?]*/)?(\.env|\.git/|\.svn/|\.aws/|\.ssh/|\.DS_Store|\.vscode/|wp-login\.php|wp-admin|xmlrpc\.php|wp-content/plugins|phpmyadmin|pma/|myadmin|adminer|server-status|actuator|vendor/phpunit|cgi-bin/|boaform|HNAP1|owa/|autodiscover/|solr/|manager/html|druid/|telescope|_ignition|debug/default|setup\.cgi|config\.(json|php|yml)|backup\.(zip|sql|tar)|dump\.sql|database\.sql|web\.config|\.htaccess|\.htpasswd|id_rsa|containers/json|v1\.\d+/containers)`)

var exploitRes = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"traversal", regexp.MustCompile(`(?i)\.\./|\.\.%2f|%2e%2e(/|%2f)|/etc/passwd|/proc/self/environ|c:\\windows`)},
	{"sqli", regexp.MustCompile(`(?i)union(\s|\+|/\*\*/)+(all(\s|\+))?select|'\s*or\s*'?1'?\s*=\s*'?1|\bsleep\(\s*\d+\s*\)|benchmark\(\d|information_schema|extractvalue\(|updatexml\(`)},
	{"jndi", regexp.MustCompile(`(?i)\$\{(jndi|env|sys|lower|upper|::-)`)},
	{"command", regexp.MustCompile("(?i)(;|\\||`|\\$\\()\\s*(wget|curl|cat|id|uname|whoami|nc|bash|sh|chmod|echo)\\b|\\b(wget|curl)\\s+https?://[^ ]+\\s*(;|\\|)|/bin/(ba)?sh\\b")},
	{"php", regexp.MustCompile(`(?i)php://(input|filter)|allow_url_include|auto_prepend_file|base64_decode\(|eval\(|system\(|passthru\(|shell_exec\(`)},
	{"shellshock", regexp.MustCompile(`\(\)\s*\{\s*:\s*;\s*\}\s*;`)},
	{"xss", regexp.MustCompile(`(?i)<script|%3cscript|javascript:|onerror\s*=`)},
}

var webShellRe = regexp.MustCompile(`(?i)/(shell|cmd|c99|r57|wso|alfa|b374k|webshell|bypass|backdoor|indoxploit|leaf|priv8)[0-9a-z_-]{0,10}\.(php\d?|phtml|jsp|aspx?)$`)

// webIP collects one address's requests in the current minute.
type webIP struct {
	requests, s2, s3, s4, s5 int
	probes, logins           int
	exploits                 map[string]int
	exploitOK                int
	shells                   int
	samples                  []string
	ua                       string
}

func (w *webIP) sample(s string) {
	if len(w.samples) < 5 {
		if len(s) > 200 {
			s = s[:200]
		}
		w.samples = append(w.samples, s)
	}
}

type webAgg struct {
	mu  sync.Mutex
	ips map[string]*webIP
}

func (g *webAgg) add(r webRequest, logins []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ips == nil {
		g.ips = map[string]*webIP{}
	}
	w := g.ips[r.IP]
	if w == nil {
		if len(g.ips) >= 20000 {
			return
		}
		w = &webIP{exploits: map[string]int{}}
		g.ips[r.IP] = w
	}
	w.requests++
	switch r.Status / 100 {
	case 2:
		w.s2++
	case 3:
		w.s3++
	case 4:
		w.s4++
	case 5:
		w.s5++
	}
	if w.ua == "" {
		w.ua = r.UA
	}
	path := r.URI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	decoded, err := url.QueryUnescape(r.URI)
	if err != nil {
		decoded = r.URI
	}
	ok := r.Status >= 200 && r.Status < 300
	if probeRe.MatchString(path) {
		w.probes++
		w.sample(r.Method + " " + r.URI)
	}
	for _, e := range exploitRes {
		if e.re.MatchString(decoded) || (e.kind != "xss" && e.re.MatchString(r.UA)) {
			w.exploits[e.kind]++
			if ok && e.kind != "xss" {
				w.exploitOK++
			}
			w.sample(strconv.Itoa(r.Status) + " " + r.Method + " " + r.URI)
		}
	}
	if webShellRe.MatchString(path) && ok {
		w.shells++
		w.sample("200 " + r.Method + " " + r.URI)
	}
	if r.Method == "POST" {
		for _, p := range logins {
			if path == p {
				w.logins++
			}
		}
	}
}

// flush returns one event per address that did something worth a look in
// the past minute, the busiest first, at most 30.
func (g *webAgg) flush(logPath string) []proto.Event {
	g.mu.Lock()
	ips := g.ips
	g.ips = nil
	g.mu.Unlock()
	type scored struct {
		ip    string
		w     *webIP
		score int
	}
	var list []scored
	for ip, w := range ips {
		ex := 0
		for _, n := range w.exploits {
			ex += n
		}
		if w.probes >= 3 || w.s4 >= 30 || ex > 0 || w.shells > 0 || w.logins >= 10 {
			list = append(list, scored{ip, w, w.probes + ex*5 + w.shells*50 + w.logins + w.s4/10})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].score > list[j].score })
	if len(list) > 30 {
		list = list[:30]
	}
	var out []proto.Event
	for _, s := range list {
		w := s.w
		kinds := make([]string, 0, len(w.exploits))
		for k := range w.exploits {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		ua := w.ua
		if len(ua) > 200 {
			ua = ua[:200]
		}
		out = append(out, proto.NewEvent("web.activity", map[string]any{
			"log": logPath, "ip": s.ip, "requests": w.requests, "status_2xx": w.s2, "status_3xx": w.s3, "status_4xx": w.s4, "status_5xx": w.s5,
			"probes": w.probes, "exploit_kinds": kinds, "exploits_ok": w.exploitOK, "shells": w.shells, "logins": w.logins,
			"samples": w.samples, "user_agent": ua,
		}))
	}
	return out
}

// Intervals, shortened by tests.
var (
	tailPoll = 2 * time.Second
	webFlush = time.Minute
)

// tail follows a log file across rotation (new inode) and truncation,
// starting at the saved offset or at the end on first start.
func (a *Agent) tailWebLog(ctx context.Context, wl WebLog) {
	if wl.Format == "" {
		wl.Format = "combined"
	}
	var agg webAgg
	var f *os.File
	var rd *bufio.Reader
	var ino uint64
	var off int64
	key := "web:" + wl.Path
	a.mu.Lock()
	saved := a.state.Offsets[key]
	a.mu.Unlock()
	open := func(fromStart bool) bool {
		nf, err := os.Open(wl.Path)
		if err != nil {
			return false
		}
		st, _ := nf.Stat()
		sys, _ := st.Sys().(*syscall.Stat_t)
		var newIno uint64
		if sys != nil {
			newIno = uint64(sys.Ino)
		}
		pos := st.Size()
		switch {
		case fromStart:
			pos = 0
		case saved.Inode == newIno && saved.Offset <= st.Size():
			pos = saved.Offset
		}
		nf.Seek(pos, io.SeekStart)
		if f != nil {
			f.Close()
		}
		f, rd, ino, off = nf, bufio.NewReaderSize(nf, 64<<10), newIno, pos
		return true
	}
	opened := open(false)
	poll := time.NewTicker(tailPoll)
	minute := time.NewTicker(webFlush)
	defer poll.Stop()
	defer minute.Stop()
	for {
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return
		case <-minute.C:
			for _, ev := range agg.flush(wl.Path) {
				a.emit(ev)
			}
			a.mu.Lock()
			a.state.Offsets[key] = LogOffset{Inode: ino, Offset: off}
			a.mu.Unlock()
		case <-poll.C:
			if !opened {
				opened = open(true)
				continue
			}
			for {
				line, _ := rd.ReadString('\n')
				if len(line) > 0 && strings.HasSuffix(line, "\n") {
					off += int64(len(line))
					if len(line) <= 16<<10 {
						if r, ok := parseWebLine(strings.TrimRight(line, "\r\n"), wl.Format); ok {
							agg.add(r, wl.LoginPaths)
						}
					}
					continue
				}
				if len(line) > 0 { // partial line: read it again next time
					f.Seek(off, io.SeekStart)
					rd.Reset(f)
				}
				break
			}
			if st, err := os.Stat(wl.Path); err == nil {
				sys, _ := st.Sys().(*syscall.Stat_t)
				if sys != nil && uint64(sys.Ino) != ino {
					opened = open(true) // rotated; the old file was read to its end above
				} else if st.Size() < off {
					opened = open(true) // truncated
				}
			}
		}
	}
}
