package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The shared host map: one document every account sees, edited live. It
// holds where the hosts sit, drawn objects (notes, zones, arrows, text,
// stamps, external and planned nodes), plans (layers), comments, tasks and
// a note per host. Admins edit it; every account may comment. Each change
// is a put or a delete of one entry; a batch of them gets the next
// revision, goes to every open map over a server-sent event stream and
// into map-log.jsonl, which undo, redo and "restore" read.

const (
	mapMaxEntries   = 5000 // per collection
	mapMaxText      = 4000
	mapMaxCoord     = 50000
	mapMaxSize      = 20000
	mapMaxOps       = 500 // per batch
	mapLogKeep      = 20000
	mapLogDays      = 90
	mapStreamsTotal = 100
	mapStreamsUser  = 5
)

type MapLayer struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Status  string    `json:"status"`          // draft, active, done, dropped
	Alert   bool      `json:"alert,omitempty"` // map.unplanned_link for this plan while active
	Author  string    `json:"author"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

type MapObject struct {
	ID    string  `json:"id"`
	Kind  string  `json:"kind"`            // note, zone, arrow, text, stamp, ext, planned
	Layer string  `json:"layer,omitempty"` // a plan, or "" for the map itself
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
	W     float64 `json:"w,omitempty"`
	H     float64 `json:"h,omitempty"`
	Text  string  `json:"text,omitempty"`
	Color string  `json:"color,omitempty"`
	// Style is the arrow kind (flow, planned, allow, block) or the stamp.
	Style string `json:"style,omitempty"`
	// From and To join an arrow to "host:ID", "obj:ID" or "net"; an empty
	// end is the free point (X, Y) or (X2, Y2).
	From    string            `json:"from,omitempty"`
	To      string            `json:"to,omitempty"`
	X2      float64           `json:"x2,omitempty"`
	Y2      float64           `json:"y2,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
	Author  string            `json:"author"`
	Created time.Time         `json:"created"`
	Updated time.Time         `json:"updated"`
}

type MapComment struct {
	ID string `json:"id"`
	// Target is "host:ID", "link:A|B", "obj:ID" or "pos" (at X, Y).
	Target   string    `json:"target"`
	Layer    string    `json:"layer,omitempty"`
	X        float64   `json:"x,omitempty"`
	Y        float64   `json:"y,omitempty"`
	Parent   string    `json:"parent,omitempty"`
	Text     string    `json:"text"`
	Mentions []string  `json:"mentions,omitempty"`
	Resolved bool      `json:"resolved,omitempty"`
	Author   string    `json:"author"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
}

type MapTask struct {
	ID       string    `json:"id"`
	Target   string    `json:"target,omitempty"`
	Layer    string    `json:"layer,omitempty"`
	Title    string    `json:"title"`
	Assignee string    `json:"assignee,omitempty"`
	Status   string    `json:"status"`        // open, doing, done
	Due      string    `json:"due,omitempty"` // YYYY-MM-DD
	Author   string    `json:"author"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
}

// HostNote is what a host is for and who looks after it.
type HostNote struct {
	Purpose  string    `json:"purpose,omitempty"`
	Owners   string    `json:"owners,omitempty"`
	Services string    `json:"services,omitempty"`
	Links    string    `json:"links,omitempty"`
	Author   string    `json:"author"`
	Updated  time.Time `json:"updated"`
}

type MapDoc struct {
	Rev      int64                  `json:"rev"`
	Layers   map[string]*MapLayer   `json:"layers"`
	Objects  map[string]*MapObject  `json:"objects"`
	Layout   map[string][2]float64  `json:"layout"`
	Comments map[string]*MapComment `json:"comments"`
	Tasks    map[string]*MapTask    `json:"tasks"`
	Notes    map[string]*HostNote   `json:"notes"`
}

func newMapDoc() *MapDoc {
	return &MapDoc{Layers: map[string]*MapLayer{}, Objects: map[string]*MapObject{}, Layout: map[string][2]float64{},
		Comments: map[string]*MapComment{}, Tasks: map[string]*MapTask{}, Notes: map[string]*HostNote{}}
}

// mapOp is one change: put stores V under C/ID, del removes it.
type mapOp struct {
	Op string          `json:"op"`
	C  string          `json:"c"`
	ID string          `json:"id"`
	V  json.RawMessage `json:"v,omitempty"`
}

// mapEntry is one applied change in the log. Before is null when the entry
// was new, After is null when it was removed. Undo names the revision a
// batch reverses.
type mapEntry struct {
	Rev    int64           `json:"rev"`
	TS     time.Time       `json:"ts"`
	User   string          `json:"user"`
	C      string          `json:"c"`
	ID     string          `json:"id"`
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
	Undo   int64           `json:"undo,omitempty"`
}

type mapStore struct {
	mu   sync.Mutex
	dir  string
	doc  *MapDoc
	log  []mapEntry
	logN int // lines in the log file, to know when to compact it
}

var (
	mapIDRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)
	mapRefRe    = regexp.MustCompile(`^(host|obj):[A-Za-z0-9_-]{1,40}$`)
	mapLinkRe   = regexp.MustCompile(`^link:[A-Za-z0-9_-]{1,40}\|[A-Za-z0-9_-]{1,40}$`)
	mapDateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	mapMention  = regexp.MustCompile(`@([A-Za-z0-9._-]{1,64})`)
	mapKinds    = map[string]bool{"note": true, "zone": true, "arrow": true, "text": true, "stamp": true, "ext": true, "planned": true}
	mapColors   = map[string]bool{"": true, "yellow": true, "blue": true, "green": true, "red": true, "purple": true, "grey": true, "orange": true}
	mapArrows   = map[string]bool{"": true, "flow": true, "planned": true, "allow": true, "block": true}
	mapStamps   = map[string]bool{"firewall": true, "database": true, "router": true, "cloud": true, "user": true, "service": true, "backup": true, "lock": true, "warning": true, "mail": true}
	mapStatus   = map[string]bool{"draft": true, "active": true, "done": true, "dropped": true}
	mapTaskStat = map[string]bool{"open": true, "doing": true, "done": true}
	mapMetaKeys = map[string]bool{"provider": true, "size": true, "owner": true, "status": true, "match": true, "org": true, "port": true, "url": true, "ip": true}
	mapPlanned  = map[string]bool{"": true, "planned": true, "ordered": true, "setup": true}
)

func mapFile(dir string) string    { return filepath.Join(dir, "map.json") }
func mapLogFile(dir string) string { return filepath.Join(dir, "map-log.jsonl") }

func openMapStore(dir string) (*mapStore, error) {
	m := &mapStore{dir: dir, doc: newMapDoc()}
	raw, err := os.ReadFile(mapFile(dir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		d := newMapDoc()
		if err := json.Unmarshal(raw, d); err != nil {
			return nil, fmt.Errorf("map.json: %w", err)
		}
		d.fill()
		m.doc = d
	}
	f, err := os.Open(mapLogFile(dir))
	if err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			var e mapEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				m.log = append(m.log, e)
				m.logN++
			}
		}
		f.Close()
		m.trimLog(time.Now())
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return m, nil
}

func (d *MapDoc) fill() {
	if d.Layers == nil {
		d.Layers = map[string]*MapLayer{}
	}
	if d.Objects == nil {
		d.Objects = map[string]*MapObject{}
	}
	if d.Layout == nil {
		d.Layout = map[string][2]float64{}
	}
	if d.Comments == nil {
		d.Comments = map[string]*MapComment{}
	}
	if d.Tasks == nil {
		d.Tasks = map[string]*MapTask{}
	}
	if d.Notes == nil {
		d.Notes = map[string]*HostNote{}
	}
}

func (m *mapStore) trimLog(now time.Time) {
	cut := 0
	for cut < len(m.log) && (len(m.log)-cut > mapLogKeep || now.Sub(m.log[cut].TS) > mapLogDays*24*time.Hour) {
		cut++
	}
	// never split a batch
	for cut > 0 && cut < len(m.log) && m.log[cut].Rev == m.log[cut-1].Rev {
		cut++
	}
	if cut > 0 {
		m.log = append([]mapEntry(nil), m.log[cut:]...)
	}
}

// save writes the document; the log grows by appending and is rewritten
// once it holds twice what is kept.
func (m *mapStore) save(entries []mapEntry) error {
	raw, err := json.Marshal(m.doc)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(mapFile(m.dir), raw); err != nil {
		return err
	}
	if m.logN+len(entries) > 2*mapLogKeep {
		var b bytes.Buffer
		for _, e := range m.log {
			line, _ := json.Marshal(e)
			b.Write(append(line, '\n'))
		}
		m.logN = len(m.log)
		return writeFileAtomic(mapLogFile(m.dir), b.Bytes())
	}
	f, err := os.OpenFile(mapLogFile(m.dir), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	var b bytes.Buffer
	for _, e := range entries {
		line, _ := json.Marshal(e)
		b.Write(append(line, '\n'))
	}
	m.logN += len(entries)
	_, err = f.Write(b.Bytes())
	return err
}

// get returns the stored entry as JSON, nil when there is none.
func (d *MapDoc) get(c, id string) json.RawMessage {
	var v any
	switch c {
	case "layers":
		if x := d.Layers[id]; x != nil {
			v = x
		}
	case "objects":
		if x := d.Objects[id]; x != nil {
			v = x
		}
	case "layout":
		if x, ok := d.Layout[id]; ok {
			v = x
		}
	case "comments":
		if x := d.Comments[id]; x != nil {
			v = x
		}
	case "tasks":
		if x := d.Tasks[id]; x != nil {
			v = x
		}
	case "notes":
		if x := d.Notes[id]; x != nil {
			v = x
		}
	}
	if v == nil {
		return nil
	}
	raw, _ := json.Marshal(v)
	return raw
}

func (d *MapDoc) size(c string) int {
	switch c {
	case "layers":
		return len(d.Layers)
	case "objects":
		return len(d.Objects)
	case "layout":
		return len(d.Layout)
	case "comments":
		return len(d.Comments)
	case "tasks":
		return len(d.Tasks)
	case "notes":
		return len(d.Notes)
	}
	return 0
}

// put stores raw (already checked) or removes the entry when raw is nil.
func (d *MapDoc) put(c, id string, raw json.RawMessage) {
	if raw == nil {
		switch c {
		case "layers":
			delete(d.Layers, id)
		case "objects":
			delete(d.Objects, id)
		case "layout":
			delete(d.Layout, id)
		case "comments":
			delete(d.Comments, id)
		case "tasks":
			delete(d.Tasks, id)
		case "notes":
			delete(d.Notes, id)
		}
		return
	}
	switch c {
	case "layers":
		var x MapLayer
		json.Unmarshal(raw, &x)
		d.Layers[id] = &x
	case "objects":
		var x MapObject
		json.Unmarshal(raw, &x)
		d.Objects[id] = &x
	case "layout":
		var x [2]float64
		json.Unmarshal(raw, &x)
		d.Layout[id] = x
	case "comments":
		var x MapComment
		json.Unmarshal(raw, &x)
		d.Comments[id] = &x
	case "tasks":
		var x MapTask
		json.Unmarshal(raw, &x)
		d.Tasks[id] = &x
	case "notes":
		var x HostNote
		json.Unmarshal(raw, &x)
		d.Notes[id] = &x
	}
}

func okCoord(vs ...float64) bool {
	for _, v := range vs {
		if math.IsNaN(v) || math.Abs(v) > mapMaxCoord {
			return false
		}
	}
	return true
}

func okText(s string, max int) bool { return len(s) <= max && !strings.ContainsRune(s, 0) }

func okTarget(t string) bool {
	return t == "pos" || mapRefRe.MatchString(t) || mapLinkRe.MatchString(t) || t == "net"
}

// mapActor is who changes the map: their name, whether they may edit, and
// the accounts that exist (for mentions and assignees).
type mapActor struct {
	user  string
	admin bool
	users map[string]bool
}

var errMapForbidden = errors.New("only admins edit the map")

// check validates op against the document and the actor's rights and
// returns what to store: the server sets author and times, a comment's
// mentions, and keeps who made an entry first.
func (d *MapDoc) check(op mapOp, a mapActor, now time.Time) (json.RawMessage, error) {
	if !mapIDRe.MatchString(op.ID) {
		return nil, errors.New("bad id")
	}
	old := d.get(op.C, op.ID)
	if op.Op == "del" {
		if op.C == "comments" && old != nil && !a.admin {
			if d.Comments[op.ID].Author != a.user {
				return nil, errMapForbidden
			}
			return nil, nil
		}
		if !a.admin {
			return nil, errMapForbidden
		}
		return nil, nil
	}
	if op.Op != "put" {
		return nil, errors.New("op must be put or del")
	}
	if old == nil && d.size(op.C) >= mapMaxEntries {
		return nil, errors.New("the map is full")
	}
	if op.C != "comments" && !a.admin {
		return nil, errMapForbidden
	}
	layer := func(l string) error {
		if l != "" && d.Layers[l] == nil {
			return errors.New("no such plan")
		}
		return nil
	}
	var out any
	switch op.C {
	case "layout":
		var p [2]float64
		if json.Unmarshal(op.V, &p) != nil || !okCoord(p[0], p[1]) {
			return nil, errors.New("bad position")
		}
		out = [2]float64{math.Round(p[0]), math.Round(p[1])}
	case "layers":
		var x MapLayer
		if json.Unmarshal(op.V, &x) != nil {
			return nil, errors.New("bad plan")
		}
		x.Name = strings.TrimSpace(x.Name)
		if x.Name == "" || !okText(x.Name, 80) || !mapStatus[x.Status] {
			return nil, errors.New("a plan needs a name and a status")
		}
		x.ID, x.Author, x.Created, x.Updated = op.ID, a.user, now, now
		if p := d.Layers[op.ID]; p != nil {
			x.Author, x.Created = p.Author, p.Created
		}
		out = x
	case "objects":
		var x MapObject
		if json.Unmarshal(op.V, &x) != nil {
			return nil, errors.New("bad object")
		}
		if !mapKinds[x.Kind] || layer(x.Layer) != nil || !okCoord(x.X, x.Y, x.X2, x.Y2) || x.W < 0 || x.H < 0 || x.W > mapMaxSize || x.H > mapMaxSize ||
			!okText(x.Text, mapMaxText) || !mapColors[x.Color] {
			return nil, errors.New("bad object")
		}
		switch x.Kind {
		case "arrow":
			if !mapArrows[x.Style] || (x.From != "" && x.From != "net" && !mapRefRe.MatchString(x.From)) || (x.To != "" && x.To != "net" && !mapRefRe.MatchString(x.To)) {
				return nil, errors.New("bad arrow")
			}
		case "stamp":
			if !mapStamps[x.Style] {
				return nil, errors.New("bad stamp")
			}
		default:
			if x.Style != "" || x.From != "" || x.To != "" {
				return nil, errors.New("bad object")
			}
		}
		if len(x.Meta) > len(mapMetaKeys) {
			return nil, errors.New("bad object")
		}
		for k, v := range x.Meta {
			if !mapMetaKeys[k] || !okText(v, 200) {
				return nil, errors.New("bad object")
			}
		}
		if x.Kind == "planned" && !mapPlanned[x.Meta["status"]] {
			return nil, errors.New("bad planned host")
		}
		x.ID, x.Author, x.Created, x.Updated = op.ID, a.user, now, now
		if p := d.Objects[op.ID]; p != nil {
			x.Author, x.Created = p.Author, p.Created
		}
		out = x
	case "comments":
		var x MapComment
		if json.Unmarshal(op.V, &x) != nil {
			return nil, errors.New("bad comment")
		}
		x.Text = strings.TrimSpace(x.Text)
		if x.Text == "" || !okText(x.Text, mapMaxText) || !okTarget(x.Target) || layer(x.Layer) != nil || !okCoord(x.X, x.Y) {
			return nil, errors.New("bad comment")
		}
		if x.Parent != "" && (d.Comments[x.Parent] == nil || x.Parent == op.ID) {
			return nil, errors.New("bad comment")
		}
		if p := d.Comments[op.ID]; p != nil {
			// anyone may mark a thread done; only its author or an admin changes it
			if p.Author != a.user && !a.admin && (p.Text != x.Text || p.Target != x.Target || p.X != x.X || p.Y != x.Y || p.Parent != x.Parent) {
				return nil, errMapForbidden
			}
			x.Author, x.Created = p.Author, p.Created
		} else {
			x.Author, x.Created = a.user, now
		}
		x.ID, x.Updated, x.Mentions = op.ID, now, nil
		seen := map[string]bool{}
		for _, m := range mapMention.FindAllStringSubmatch(x.Text, 20) {
			if a.users[m[1]] && !seen[m[1]] {
				seen[m[1]] = true
				x.Mentions = append(x.Mentions, m[1])
			}
		}
		out = x
	case "tasks":
		var x MapTask
		if json.Unmarshal(op.V, &x) != nil {
			return nil, errors.New("bad task")
		}
		x.Title = strings.TrimSpace(x.Title)
		if x.Title == "" || !okText(x.Title, 200) || !mapTaskStat[x.Status] || layer(x.Layer) != nil ||
			(x.Target != "" && !okTarget(x.Target)) || (x.Due != "" && !mapDateRe.MatchString(x.Due)) || (x.Assignee != "" && !a.users[x.Assignee]) {
			return nil, errors.New("bad task")
		}
		x.ID, x.Author, x.Created, x.Updated = op.ID, a.user, now, now
		if p := d.Tasks[op.ID]; p != nil {
			x.Author, x.Created = p.Author, p.Created
		}
		out = x
	case "notes":
		var x HostNote
		if json.Unmarshal(op.V, &x) != nil || !okText(x.Purpose, 1000) || !okText(x.Owners, 300) || !okText(x.Services, 1000) || !okText(x.Links, 1000) {
			return nil, errors.New("bad host note")
		}
		x.Author, x.Updated = a.user, now
		out = x
	default:
		return nil, errors.New("unknown collection")
	}
	raw, err := json.Marshal(out)
	return raw, err
}

// apply checks and applies a batch as one revision. Removing a plan
// removes what is drawn in it; removing a comment removes its replies.
func (m *mapStore) apply(ops []mapOp, a mapActor, undo int64, now time.Time) ([]mapEntry, error) {
	if len(ops) == 0 || len(ops) > mapMaxOps {
		return nil, errors.New("1 to 500 changes per batch")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rev := m.doc.Rev + 1
	var entries []mapEntry
	type staged struct {
		c, id string
		raw   json.RawMessage
	}
	var plan []staged
	// a trial copy keeps later ops of the batch seeing earlier ones
	trial := m.doc.clone()
	for _, op := range ops {
		raw, err := trial.check(op, a, now)
		if err != nil {
			return nil, err
		}
		trial.put(op.C, op.ID, raw)
		plan = append(plan, staged{op.C, op.ID, raw})
		if op.Op == "del" {
			for _, extra := range trial.cascade(op.C, op.ID) {
				trial.put(extra[0], extra[1], nil)
				plan = append(plan, staged{extra[0], extra[1], nil})
			}
		}
	}
	for _, p := range plan {
		before := m.doc.get(p.c, p.id)
		if before == nil && p.raw == nil {
			continue
		}
		m.doc.put(p.c, p.id, p.raw)
		entries = append(entries, mapEntry{Rev: rev, TS: now, User: a.user, C: p.c, ID: p.id, Before: before, After: p.raw, Undo: undo})
	}
	if len(entries) == 0 {
		return nil, nil
	}
	m.doc.Rev = rev
	m.log = append(m.log, entries...)
	m.trimLog(now)
	if err := m.save(entries); err != nil {
		log.Printf("map: %v", err)
	}
	return entries, nil
}

func (d *MapDoc) clone() *MapDoc {
	raw, _ := json.Marshal(d)
	c := newMapDoc()
	json.Unmarshal(raw, c)
	c.fill()
	return c
}

// cascade lists what goes with a removed entry: a plan's objects, tasks
// and comments, a comment's replies.
func (d *MapDoc) cascade(c, id string) [][2]string {
	var out [][2]string
	switch c {
	case "layers":
		for k, o := range d.Objects {
			if o.Layer == id {
				out = append(out, [2]string{"objects", k})
			}
		}
		for k, t := range d.Tasks {
			if t.Layer == id {
				out = append(out, [2]string{"tasks", k})
			}
		}
		for k, cm := range d.Comments {
			if cm.Layer == id {
				out = append(out, [2]string{"comments", k})
			}
		}
	case "comments":
		for k, cm := range d.Comments {
			if cm.Parent == id {
				out = append(out, [2]string{"comments", k})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][1] < out[j][1] })
	return out
}

// revert builds the ops that put every entry of a batch back to Before.
// It refuses when something in the batch changed since.
func (m *mapStore) revert(rev int64) ([]mapOp, error) {
	var ops []mapOp
	for i := len(m.log) - 1; i >= 0; i-- {
		e := m.log[i]
		if e.Rev != rev {
			continue
		}
		if !bytes.Equal(m.doc.get(e.C, e.ID), e.After) {
			return nil, errors.New("changed by someone else since")
		}
		if e.Before == nil {
			ops = append(ops, mapOp{Op: "del", C: e.C, ID: e.ID})
		} else {
			ops = append(ops, mapOp{Op: "put", C: e.C, ID: e.ID, V: e.Before})
		}
	}
	if len(ops) == 0 {
		return nil, errors.New("nothing to undo")
	}
	return ops, nil
}

// undoTarget finds the user's batch to reverse. A batch that reverses a
// plain change is an undo; one that reverses an undo is a redo and counts
// as a plain change again. Undo takes the newest of the user's batches
// that is no undo and not reversed yet; redo the newest of their undos not
// reversed yet, as long as no plain change of theirs came after it.
func (m *mapStore) undoTarget(user string, redo bool) int64 {
	target := map[int64]int64{}
	var revs []int64
	for _, e := range m.log {
		if _, ok := target[e.Rev]; !ok {
			target[e.Rev] = e.Undo
			revs = append(revs, e.Rev)
		}
	}
	isUndo := map[int64]bool{}
	reversed := map[int64]bool{}
	for _, r := range revs { // oldest first: a target is always older
		if t := target[r]; t != 0 {
			isUndo[r] = !isUndo[t]
			reversed[t] = true
		}
	}
	owner := map[int64]string{}
	for _, e := range m.log {
		owner[e.Rev] = e.User
	}
	for i := len(revs) - 1; i >= 0; i-- {
		r := revs[i]
		if owner[r] != user {
			continue
		}
		if redo {
			if isUndo[r] && !reversed[r] {
				return r
			}
			if !isUndo[r] && target[r] == 0 {
				return 0 // a new change of one's own ends what can be redone
			}
			continue
		}
		if !isUndo[r] && !reversed[r] {
			return r
		}
	}
	return 0
}

// restoreOps puts everything changed after rev back to how it was then.
func (m *mapStore) restoreOps(rev int64) ([]mapOp, error) {
	if len(m.log) == 0 || rev < m.log[0].Rev-1 || rev >= m.doc.Rev {
		return nil, errors.New("that revision is not in the history")
	}
	first := map[string]mapEntry{}
	var keys []string
	for _, e := range m.log {
		if e.Rev <= rev {
			continue
		}
		k := e.C + "\x00" + e.ID
		if _, ok := first[k]; !ok {
			first[k] = e
			keys = append(keys, k)
		}
	}
	var ops []mapOp
	for _, k := range keys {
		e := first[k]
		if bytes.Equal(m.doc.get(e.C, e.ID), e.Before) {
			continue
		}
		if e.Before == nil {
			ops = append(ops, mapOp{Op: "del", C: e.C, ID: e.ID})
		} else {
			ops = append(ops, mapOp{Op: "put", C: e.C, ID: e.ID, V: e.Before})
		}
	}
	return ops, nil
}

// ---------- live stream ----------

type mapClient struct {
	id   string
	user string
	ch   chan []byte
	done chan struct{}
	last time.Time // last cursor, for the rate limit
	once sync.Once
}

type mapHub struct {
	mu      sync.Mutex
	clients map[string]*mapClient
}

func (h *mapHub) join(user string) (*mapClient, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients == nil {
		h.clients = map[string]*mapClient{}
	}
	n := 0
	for _, c := range h.clients {
		if c.user == user {
			n++
		}
	}
	if len(h.clients) >= mapStreamsTotal || n >= mapStreamsUser {
		return nil, errors.New("too many open maps")
	}
	c := &mapClient{id: newID(8), user: user, ch: make(chan []byte, 64), done: make(chan struct{})}
	h.clients[c.id] = c
	return c, nil
}

func (h *mapHub) leave(c *mapClient) {
	h.mu.Lock()
	delete(h.clients, c.id)
	h.mu.Unlock()
	c.once.Do(func() { close(c.done) })
}

func (h *mapHub) presence() []map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []map[string]string{}
	for _, c := range h.clients {
		out = append(out, map[string]string{"conn": c.id, "user": c.user})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["user"]+out[i]["conn"] < out[j]["user"]+out[j]["conn"] })
	return out
}

// send goes to every open map; one that cannot keep up is closed and
// reconnects, reloading the document.
func (h *mapHub) send(event string, v any) {
	if h == nil {
		return
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	msg := []byte("event: " + event + "\ndata: " + string(raw) + "\n\n")
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, c := range h.clients {
		select {
		case c.ch <- msg:
		default:
			delete(h.clients, id)
			c.once.Do(func() { close(c.done) })
		}
	}
}

func (s *Server) sessionAlive(sess *session) bool {
	s.smu.Lock()
	defer s.smu.Unlock()
	for _, x := range s.sessions {
		if x == sess {
			return time.Now().Before(sess.Expires)
		}
	}
	return false
}

// handleMapStream: GET /api/ui/map/stream, server-sent events: hello (the
// connection and who is here), ops, presence, cursor and alert.
func (s *Server) handleMapStream(w http.ResponseWriter, r *http.Request, sess *session) {
	c, err := s.maphub.join(sess.User)
	if err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	defer func() {
		s.maphub.leave(c)
		s.maphub.send("presence", s.maphub.presence())
	}()
	// the server's 30 s limits are for ordinary requests
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{})
	rc.SetReadDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	s.maps.mu.Lock()
	rev := s.maps.doc.Rev
	s.maps.mu.Unlock()
	hello, _ := json.Marshal(map[string]any{"conn": c.id, "rev": rev})
	fmt.Fprintf(w, "event: hello\ndata: %s\n\n", hello)
	if rc.Flush() != nil {
		return
	}
	s.maphub.send("presence", s.maphub.presence())
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-c.done:
			return
		case msg := <-c.ch:
			if _, err := w.Write(msg); err != nil || rc.Flush() != nil {
				return
			}
		case <-ping.C:
			if !s.sessionAlive(sess) {
				return
			}
			if _, err := w.Write([]byte(": ping\n\n")); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}

// handleMapCursor: POST /api/ui/map/presence {conn, x, y, layer, sel,
// drag}: where someone points and what they hold, at most 8 times a second.
func (s *Server) handleMapCursor(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Conn  string   `json:"conn"`
		X     float64  `json:"x"`
		Y     float64  `json:"y"`
		Layer string   `json:"layer"`
		Sel   []string `json:"sel"`
		Drag  string   `json:"drag"`
		Off   bool     `json:"off"`
	}
	if !decode(r, w, &req) {
		return
	}
	s.maphub.mu.Lock()
	c := s.maphub.clients[req.Conn]
	ok := c != nil && c.user == sess.User && time.Since(c.last) >= 120*time.Millisecond
	if ok {
		c.last = time.Now()
	}
	s.maphub.mu.Unlock()
	if !ok || !okCoord(req.X, req.Y) || len(req.Sel) > 50 || (req.Layer != "" && !mapIDRe.MatchString(req.Layer)) || (req.Drag != "" && !mapIDRe.MatchString(req.Drag) && !mapRefRe.MatchString(req.Drag)) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sel := []string{}
	for _, x := range req.Sel {
		if mapIDRe.MatchString(x) || mapRefRe.MatchString(x) {
			sel = append(sel, x)
		}
	}
	s.maphub.send("cursor", map[string]any{"conn": req.Conn, "user": sess.User, "x": math.Round(req.X), "y": math.Round(req.Y),
		"layer": req.Layer, "sel": sel, "drag": req.Drag, "off": req.Off})
	w.WriteHeader(http.StatusNoContent)
}

// ---------- document API ----------

func (s *Server) mapActor(sess *session) mapActor {
	a := mapActor{user: sess.User, users: map[string]bool{}}
	if u := s.user(sess.User); u != nil {
		a.admin = roleOf(u) == "admin"
	}
	if users, err := LoadUsers(s.cfg.DataDir); err == nil {
		for name := range users {
			a.users[name] = true
		}
	}
	return a
}

// handleMap: GET /api/ui/map, the whole document, the accounts one can
// mention and whether the caller may edit.
func (s *Server) handleMap(w http.ResponseWriter, r *http.Request, sess *session) {
	a := s.mapActor(sess)
	names := make([]string, 0, len(a.users))
	for n := range a.users {
		names = append(names, n)
	}
	sort.Strings(names)
	s.maps.mu.Lock()
	raw, _ := json.Marshal(s.maps.doc)
	s.maps.mu.Unlock()
	writeJSON(w, map[string]any{"doc": json.RawMessage(raw), "edit": a.admin, "users": names, "me": sess.User})
}

func (s *Server) mapCommit(w http.ResponseWriter, sess *session, entries []mapEntry, kind string) {
	if len(entries) > 0 {
		s.maphub.send("ops", map[string]any{"rev": entries[0].Rev, "user": sess.User, "entries": entries})
		s.mapAudit(sess.User, kind, entries)
	}
	s.maps.mu.Lock()
	rev := s.maps.doc.Rev
	s.maps.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "rev": rev})
}

// mapAudit writes one admin event per account and minute and kind at
// most, so dragging boxes around does not flood the log.
func (s *Server) mapAudit(user, kind string, entries []mapEntry) {
	key := user + "|" + kind
	now := time.Now()
	s.mapAud.Lock()
	if s.mapAudAt == nil {
		s.mapAudAt = map[string]time.Time{}
	}
	if now.Sub(s.mapAudAt[key]) < time.Minute && kind == "edit" {
		s.mapAud.Unlock()
		return
	}
	s.mapAudAt[key] = now
	s.mapAud.Unlock()
	cs := map[string]int{}
	for _, e := range entries {
		cs[e.C]++
	}
	s.audit(user, "map."+kind, map[string]any{"rev": entries[0].Rev, "changes": cs})
}

// handleMapOps: POST /api/ui/map/ops {ops: [...]}.
func (s *Server) handleMapOps(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Ops []mapOp `json:"ops"`
	}
	if !decode(r, w, &req) {
		return
	}
	entries, err := s.maps.apply(req.Ops, s.mapActor(sess), 0, time.Now().UTC())
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errMapForbidden) {
			code = http.StatusForbidden
		}
		http.Error(w, err.Error(), code)
		return
	}
	s.mapCommit(w, sess, entries, "edit")
}

// handleMapUndo: POST /api/ui/map/undo {redo}: the caller's last batch.
func (s *Server) handleMapUndo(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Redo bool `json:"redo"`
	}
	if !decode(r, w, &req) {
		return
	}
	s.maps.mu.Lock()
	rev := s.maps.undoTarget(sess.User, req.Redo)
	var ops []mapOp
	err := errors.New("nothing to undo")
	if rev != 0 {
		ops, err = s.maps.revert(rev)
	}
	s.maps.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	entries, err := s.maps.apply(ops, s.mapActor(sess), rev, time.Now().UTC())
	if err != nil {
		code := http.StatusConflict
		if errors.Is(err, errMapForbidden) {
			code = http.StatusForbidden
		}
		http.Error(w, err.Error(), code)
		return
	}
	s.mapCommit(w, sess, entries, "undo")
}

// handleMapRestore: POST /api/ui/map/restore {rev} (admin): everything
// back to how it was at that revision, as one new change.
func (s *Server) handleMapRestore(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Rev int64 `json:"rev"`
	}
	if !decode(r, w, &req) {
		return
	}
	s.maps.mu.Lock()
	ops, err := s.maps.restoreOps(req.Rev)
	s.maps.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(ops) == 0 {
		s.mapCommit(w, sess, nil, "restore")
		return
	}
	entries, err := s.maps.apply(ops, s.mapActor(sess), 0, time.Now().UTC())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mapCommit(w, sess, entries, "restore")
}

// handleMapHistory: GET /api/ui/map/history?before=REV, the newest 100
// batches before REV with who, when and what.
func (s *Server) handleMapHistory(w http.ResponseWriter, r *http.Request, sess *session) {
	var before int64 = math.MaxInt64
	if v := r.URL.Query().Get("before"); v != "" {
		fmt.Sscan(v, &before)
	}
	type batch struct {
		Rev     int64      `json:"rev"`
		TS      time.Time  `json:"ts"`
		User    string     `json:"user"`
		Undo    int64      `json:"undo,omitempty"`
		Entries []mapEntry `json:"entries"`
	}
	var out []*batch
	s.maps.mu.Lock()
	for i := len(s.maps.log) - 1; i >= 0 && len(out) <= 100; i-- {
		e := s.maps.log[i]
		if e.Rev >= before {
			continue
		}
		if len(out) == 0 || out[len(out)-1].Rev != e.Rev {
			out = append(out, &batch{Rev: e.Rev, TS: e.TS, User: e.User, Undo: e.Undo})
		}
		b := out[len(out)-1]
		if len(b.Entries) < 20 {
			b.Entries = append(b.Entries, e)
		}
	}
	oldest := int64(0)
	if len(s.maps.log) > 0 {
		oldest = s.maps.log[0].Rev
	}
	s.maps.mu.Unlock()
	if len(out) > 100 {
		out = out[:100]
	}
	if out == nil {
		out = []*batch{}
	}
	writeJSON(w, map[string]any{"batches": out, "oldest": oldest})
}
