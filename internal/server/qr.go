package server

import (
	"errors"
	"strings"
)

// A small QR code encoder (ISO/IEC 18004): byte mode, error correction
// level M, versions 1 to 10. Enough for otpauth:// URIs, so new accounts
// can scan their TOTP secret instead of typing it.

type qrVersion struct {
	ec     int      // error correction codewords per block
	blocks [][2]int // {count, data codewords per block}
	align  []int
}

var qrVersions = []qrVersion{
	{}, // index 0 unused
	{10, [][2]int{{1, 16}}, nil},
	{16, [][2]int{{1, 28}}, []int{6, 18}},
	{26, [][2]int{{1, 44}}, []int{6, 22}},
	{18, [][2]int{{2, 32}}, []int{6, 26}},
	{24, [][2]int{{2, 43}}, []int{6, 30}},
	{16, [][2]int{{4, 27}}, []int{6, 34}},
	{18, [][2]int{{4, 31}}, []int{6, 22, 38}},
	{22, [][2]int{{2, 38}, {2, 39}}, []int{6, 24, 42}},
	{22, [][2]int{{3, 36}, {2, 37}}, []int{6, 26, 46}},
	{26, [][2]int{{4, 43}, {1, 44}}, []int{6, 28, 50}},
}

func (v qrVersion) dataCodewords() int {
	n := 0
	for _, b := range v.blocks {
		n += b[0] * b[1]
	}
	return n
}

// ---------- Reed-Solomon over GF(256), polynomial 0x11d ----------

var gfExp, gfLog [512]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func rsECC(data []byte, n int) []byte {
	gen := []byte{1}
	for i := 0; i < n; i++ {
		next := make([]byte, len(gen)+1)
		for j, g := range gen {
			next[j] ^= g
			next[j+1] ^= gfMul(g, gfExp[i])
		}
		gen = next
	}
	rem := make([]byte, n)
	for _, d := range data {
		f := d ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for j := 0; j < n; j++ {
			rem[j] ^= gfMul(gen[j+1], f)
		}
	}
	return rem
}

// ---------- encoding ----------

type bitBuf struct{ bits []bool }

func (b *bitBuf) put(v, n int) {
	for i := n - 1; i >= 0; i-- {
		b.bits = append(b.bits, v>>i&1 == 1)
	}
}

// QR returns the modules of a QR code for text, true meaning dark.
func QR(text string) ([][]bool, error) {
	data := []byte(text)
	ver := 0
	for v := 1; v < len(qrVersions); v++ {
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*len(data) <= 8*qrVersions[v].dataCodewords() {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("text too long for a QR code")
	}
	info := qrVersions[ver]
	capacity := info.dataCodewords()
	var bb bitBuf
	bb.put(0b0100, 4)
	if ver >= 10 {
		bb.put(len(data), 16)
	} else {
		bb.put(len(data), 8)
	}
	for _, c := range data {
		bb.put(int(c), 8)
	}
	for i := 0; i < 4 && len(bb.bits) < capacity*8; i++ {
		bb.bits = append(bb.bits, false)
	}
	for len(bb.bits)%8 != 0 {
		bb.bits = append(bb.bits, false)
	}
	codewords := make([]byte, 0, capacity)
	for i := 0; i < len(bb.bits); i += 8 {
		var c byte
		for j := 0; j < 8; j++ {
			if bb.bits[i+j] {
				c |= 1 << (7 - j)
			}
		}
		codewords = append(codewords, c)
	}
	for pad := 0; len(codewords) < capacity; pad++ {
		codewords = append(codewords, []byte{0xec, 0x11}[pad%2])
	}

	// split into blocks, add error correction, interleave
	var dataBlocks, ecBlocks [][]byte
	p := 0
	for _, g := range info.blocks {
		for i := 0; i < g[0]; i++ {
			blk := codewords[p : p+g[1]]
			p += g[1]
			dataBlocks = append(dataBlocks, blk)
			ecBlocks = append(ecBlocks, rsECC(blk, info.ec))
		}
	}
	var final []byte
	for i := 0; ; i++ {
		added := false
		for _, blk := range dataBlocks {
			if i < len(blk) {
				final = append(final, blk[i])
				added = true
			}
		}
		if !added {
			break
		}
	}
	for i := 0; i < info.ec; i++ {
		for _, blk := range ecBlocks {
			final = append(final, blk[i])
		}
	}

	size := 17 + 4*ver
	m := newMatrix(size)
	m.functionPatterns(ver)
	m.placeData(final)
	best, bestScore := -1, 0
	for mask := 0; mask < 8; mask++ {
		c := m.clone()
		c.applyMask(mask)
		c.formatBits(mask)
		if ver >= 7 {
			c.versionBits(ver)
		}
		if score := c.penalty(); best < 0 || score < bestScore {
			best, bestScore = mask, score
		}
	}
	m.applyMask(best)
	m.formatBits(best)
	if ver >= 7 {
		m.versionBits(ver)
	}
	return m.dark, nil
}

type qrMatrix struct {
	size     int
	dark     [][]bool
	reserved [][]bool
}

func newMatrix(n int) *qrMatrix {
	m := &qrMatrix{size: n, dark: make([][]bool, n), reserved: make([][]bool, n)}
	for i := range m.dark {
		m.dark[i] = make([]bool, n)
		m.reserved[i] = make([]bool, n)
	}
	return m
}

func (m *qrMatrix) clone() *qrMatrix {
	c := newMatrix(m.size)
	for i := range m.dark {
		copy(c.dark[i], m.dark[i])
		copy(c.reserved[i], m.reserved[i])
	}
	return c
}

func (m *qrMatrix) set(r, c int, dark bool) {
	m.dark[r][c] = dark
	m.reserved[r][c] = true
}

func (m *qrMatrix) functionPatterns(ver int) {
	n := m.size
	finder := func(r0, c0 int) {
		for r := -1; r <= 7; r++ {
			for c := -1; c <= 7; c++ {
				rr, cc := r0+r, c0+c
				if rr < 0 || cc < 0 || rr >= n || cc >= n {
					continue
				}
				in := r >= 0 && r <= 6 && c >= 0 && c <= 6
				dark := in && (r == 0 || r == 6 || c == 0 || c == 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4))
				m.set(rr, cc, dark)
			}
		}
	}
	finder(0, 0)
	finder(0, n-7)
	finder(n-7, 0)
	for i := 8; i < n-8; i++ {
		m.set(6, i, i%2 == 0)
		m.set(i, 6, i%2 == 0)
	}
	al := qrVersions[ver].align
	last := len(al) - 1
	for i, r := range al {
		for j, c := range al {
			if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
				continue // these would overlap a finder pattern
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					d := dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0)
					m.set(r+dr, c+dc, d)
				}
			}
		}
	}
	// format areas and the dark module
	for i := 0; i < 9; i++ {
		if !m.reserved[8][i] {
			m.set(8, i, false)
		}
		if !m.reserved[i][8] {
			m.set(i, 8, false)
		}
	}
	for i := 0; i < 8; i++ {
		m.set(8, n-1-i, false)
		m.set(n-1-i, 8, false)
	}
	m.set(n-8, 8, true)
	if ver >= 7 {
		for i := 0; i < 6; i++ {
			for j := 0; j < 3; j++ {
				m.set(i, n-11+j, false)
				m.set(n-11+j, i, false)
			}
		}
	}
}

func (m *qrMatrix) placeData(data []byte) {
	n := m.size
	bit := 0
	total := len(data) * 8
	up := true
	for col := n - 1; col > 0; col -= 2 {
		if col == 6 {
			col--
		}
		for i := 0; i < n; i++ {
			r := i
			if up {
				r = n - 1 - i
			}
			for _, c := range []int{col, col - 1} {
				if m.reserved[r][c] {
					continue
				}
				d := false
				if bit < total {
					d = data[bit/8]>>(7-bit%8)&1 == 1
				}
				m.dark[r][c] = d
				bit++
			}
		}
		up = !up
	}
}

func qrMaskBit(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return r*c%2+r*c%3 == 0
	case 6:
		return (r*c%2+r*c%3)%2 == 0
	default:
		return ((r+c)%2+r*c%3)%2 == 0
	}
}

func (m *qrMatrix) applyMask(mask int) {
	for r := 0; r < m.size; r++ {
		for c := 0; c < m.size; c++ {
			if !m.reserved[r][c] && qrMaskBit(mask, r, c) {
				m.dark[r][c] = !m.dark[r][c]
			}
		}
	}
}

func bch(value, poly, polyDeg int) int {
	v := value << polyDeg
	for i := bitLen(v) - 1; i >= polyDeg; i-- {
		if v>>i&1 == 1 {
			v ^= poly << (i - polyDeg)
		}
	}
	return value<<polyDeg | v
}

func bitLen(v int) int {
	n := 0
	for v > 0 {
		n++
		v >>= 1
	}
	return n
}

func (m *qrMatrix) formatBits(mask int) {
	// level M is 00
	f := bch(mask, 0x537, 10) ^ 0x5412
	n := m.size
	bitAt := func(i int) bool { return f>>i&1 == 1 }
	// around the top-left finder: bits 0..7 down column 8 / along row 8
	pos := [][2]int{{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {7, 8}, {8, 8}, {8, 7}, {8, 5}, {8, 4}, {8, 3}, {8, 2}, {8, 1}, {8, 0}}
	for i, p := range pos {
		m.dark[p[0]][p[1]] = bitAt(i)
	}
	for i := 0; i < 8; i++ {
		m.dark[8][n-1-i] = bitAt(i)
	}
	for i := 8; i < 15; i++ {
		m.dark[n-15+i][8] = bitAt(i)
	}
	m.dark[n-8][8] = true
}

func (m *qrMatrix) versionBits(ver int) {
	v := bch(ver, 0x1f25, 12)
	n := m.size
	for i := 0; i < 18; i++ {
		d := v>>i&1 == 1
		r, c := i/3, n-11+i%3
		m.dark[r][c] = d
		m.dark[c][r] = d
	}
}

func (m *qrMatrix) penalty() int {
	n, score := m.size, 0
	// rule 1: runs of five or more in rows and columns
	for r := 0; r < n; r++ {
		for _, horiz := range []bool{true, false} {
			run := 1
			for c := 1; c < n; c++ {
				a, b := m.dark[r][c], m.dark[r][c-1]
				if !horiz {
					a, b = m.dark[c][r], m.dark[c-1][r]
				}
				if a == b {
					run++
					continue
				}
				if run >= 5 {
					score += run - 2
				}
				run = 1
			}
			if run >= 5 {
				score += run - 2
			}
		}
	}
	// rule 2: 2x2 blocks
	for r := 0; r < n-1; r++ {
		for c := 0; c < n-1; c++ {
			d := m.dark[r][c]
			if d == m.dark[r+1][c] && d == m.dark[r][c+1] && d == m.dark[r+1][c+1] {
				score += 3
			}
		}
	}
	// rule 3: finder-like patterns
	pat := []bool{true, false, true, true, true, false, true}
	for r := 0; r < n; r++ {
		for c := 0; c+7 <= n; c++ {
			for _, horiz := range []bool{true, false} {
				ok := true
				for k := 0; k < 7 && ok; k++ {
					v := m.dark[r][c+k]
					if !horiz {
						v = m.dark[c+k][r]
					}
					ok = v == pat[k]
				}
				if ok {
					score += 40
				}
			}
		}
	}
	// rule 4: balance of dark modules
	dark := 0
	for r := 0; r < n; r++ {
		for c := 0; c < n; c++ {
			if m.dark[r][c] {
				dark++
			}
		}
	}
	pct := dark * 100 / (n * n)
	d := pct - 50
	if d < 0 {
		d = -d
	}
	return score + d/5*10
}

// QRTerminal draws a QR code with half blocks, two rows per line, black on
// white with a quiet zone, so it scans from dark terminals too.
func QRTerminal(text string) (string, error) {
	q, err := QR(text)
	if err != nil {
		return "", err
	}
	n := len(q)
	at := func(r, c int) bool { return r >= 0 && c >= 0 && r < n && c < n && q[r][c] }
	var sb strings.Builder
	for r := -2; r < n+2; r += 2 {
		sb.WriteString("\x1b[47;30m")
		for c := -2; c < n+2; c++ {
			top, bottom := at(r, c), at(r+1, c)
			switch {
			case top && bottom:
				sb.WriteString("█")
			case top:
				sb.WriteString("▀")
			case bottom:
				sb.WriteString("▄")
			default:
				sb.WriteString(" ")
			}
		}
		sb.WriteString("\x1b[0m\n")
	}
	return sb.String(), nil
}
