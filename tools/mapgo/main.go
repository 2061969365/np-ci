// Command mapgo 是 natpierce「映射模式」（端口映射）访问端的最小实现。
//
// 协议依据：F:\worker\natpierce-re\protocol\spec-mapping.md
//   - 控制面：AES-128-CBC + PKCS#7 + hex + " \r\n"（与 tools/map_client_cloud.py 一致）
//   - 打洞：0x30/0x31/0x32/ok×2（spec-mapping §4）
//   - KCP：AES-256-CFB，key = PBKDF2-HMAC-SHA1(MD5("0000017704510080"), "www.natpierce.cn", 1024, 32)
//   - 登录：KCP 上 '1'×5 → '2'，再 "3" → '4'
//   - 应用层：goproxy 8 字节头（cmd 低 4 位、bit7=direction、u16 LE 总长、u32 LE id）
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

// ---------------------------------------------------------------- 配置

const (
	csHost = "101.43.214.174"
	csPort = 58717

	ctrlKey = "ChengFengPoLang!"       // 16B，AES-128
	ctrlIV  = "17704510080\x00\x00\x00\x00\x00" // 11B + 5×0x00

	kcpSeed = "0000017704510080" // strings.Repeat("0",5) + "17704510080"
	kcpSalt = "www.natpierce.cn"
	kcpIter = 1024
	kcpLen  = 32

	maxFrame = 0x520 // goproxy read 侧上限
)

type cfg struct {
	acct, pwd, pcid, code, conpwd, pcname string
	udpPort                              int // 本地打洞端口（上报给服务器的端口）
	duration, punchTimeout               time.Duration

	mapListen, mapForward, mapNet string
	mapUDP                        bool
	conMode                       string
	hexWire                       bool
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func loadCfg() cfg {
	c := cfg{
		acct:   env("NP_ACCT", "2061969365@qq.com"),
		pwd:    env("NP_PWD", "qaz123wsx456"),
		pcid:   env("NP_PCID", "685006"),
		code:   env("NP_CODE", "91505506"),
		conpwd: env("NP_CONPWD", "qaz123wsx456"),
		// 与 Python 客户端一致：PC 名固定为 CloudMap
		pcname:  env("NP_PCNAME", "CloudMap"),
		udpPort: envInt("NP_UDP_PORT", 40100),

		duration:     time.Duration(envInt("NP_DURATION", 180)) * time.Second,
		punchTimeout: time.Duration(envInt("NP_PUNCH_TIMEOUT", 120)) * time.Second,

		mapListen:  env("MAP_LISTEN", "0.0.0.0:10000"),
		mapForward: env("MAP_FORWARD", "127.0.0.1:9999"),
		mapNet:     env("MAP_NET", ""),   // 空 = 按 cmd=5 的 Domain 猜
		mapUDP:     envInt("MAP_UDP", 1) != 0,
		conMode:    env("NP_CON_MODE", "1"), // @con 第 5 字段
		hexWire:    envInt("NP_HEX_WIRE", 1) != 0,
	}
	return c
}

var start = time.Now()

func logf(format string, args ...any) {
	log.Printf("[%7.2fs] %s", time.Since(start).Seconds(), fmt.Sprintf(format, args...))
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func hexdump(b []byte) string {
	if len(b) > 96 {
		return hex.EncodeToString(b[:96]) + fmt.Sprintf("...(共%dB)", len(b))
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------- 控制面

type ctrl struct {
	c net.Conn
	r *bufio.Reader
}

func ctrlEncrypt(plain []byte) []byte {
	block, err := aes.NewCipher([]byte(ctrlKey))
	if err != nil {
		panic(err)
	}
	n := 16 - len(plain)%16
	buf := make([]byte, len(plain)+n)
	copy(buf, plain)
	for i := len(plain); i < len(buf); i++ {
		buf[i] = byte(n)
	}
	out := make([]byte, len(buf))
	cipher.NewCBCEncrypter(block, []byte(ctrlIV)).CryptBlocks(out, buf)
	return out
}

func ctrlDecrypt(ct []byte) ([]byte, error) {
	if len(ct) == 0 || len(ct)%16 != 0 {
		return nil, errors.New("cipher len not multiple of 16")
	}
	block, err := aes.NewCipher([]byte(ctrlKey))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, []byte(ctrlIV)).CryptBlocks(out, ct)
	n := int(out[len(out)-1])
	if n < 1 || n > 16 || n > len(out) {
		return out, nil // 与 Python 一致：填充非法时原样返回
	}
	for _, b := range out[len(out)-n:] {
		if int(b) != n {
			return out, nil
		}
	}
	return out[:len(out)-n], nil
}

func dialCtrl() (*ctrl, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(csHost, strconv.Itoa(csPort)), 15*time.Second)
	if err != nil {
		return nil, err
	}
	return &ctrl{c: conn, r: bufio.NewReaderSize(conn, 1<<15)}, nil
}

func (x *ctrl) send(c cfg, plain string) error {
	ct := ctrlEncrypt([]byte(plain))
	var wire []byte
	if c.hexWire {
		wire = append([]byte(hex.EncodeToString(ct)), ' ', '\r', '\n')
	} else {
		wire = append(ct, ' ', '\r', '\n')
	}
	logf("CTRL -> %s", plain)
	_, err := x.c.Write(wire)
	return err
}

func (x *ctrl) readLine() (string, error) {
	line, err := x.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil
	}
	raw, err := hex.DecodeString(line)
	if err != nil {
		// 服务器有时直接回明文（调试用）
		return line, nil
	}
	pt, err := ctrlDecrypt(raw)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (x *ctrl) login(c cfg) (session, pubip string, err error) {
	h1 := md5.Sum([]byte(c.pwd))
	h1hex := hex.EncodeToString(h1[:])
	h2 := md5.Sum([]byte(h1hex))
	frame := fmt.Sprintf("@pc|@imcs|%s|%s|%s|%s|1.06|0|!",
		c.pcid, hex.EncodeToString(h2[:]), c.acct, c.pcname)
	if err = x.send(c, frame); err != nil {
		return "", "", err
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		x.c.SetReadDeadline(time.Now().Add(5 * time.Second))
		txt, err := x.readLine()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return "", "", err
		}
		if txt == "" {
			continue
		}
		logf("CTRL <- %s", txt)
		if strings.HasPrefix(txt, "@csok") {
			f := strings.Split(txt, "|")
			if len(f) < 4 {
				return "", "", fmt.Errorf("@csok 段数不足: %q", txt)
			}
			return f[2], f[3], nil
		}
	}
	return "", "", errors.New("登录超时：未收到 @csok")
}

// ctrlReader 把后续控制帧推入 channel（含 15s 心跳），登录完成后启动。
func ctrlReader(x *ctrl, out chan<- string) {
	lastBeat := time.Now()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for range tick.C {
		if time.Since(lastBeat) > 15*time.Second {
			if _, err := x.c.Write([]byte{0x00}); err == nil {
				logf("CTRL heartbeat 0x00")
			}
			lastBeat = time.Now()
		}
		x.c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		txt, err := x.readLine()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			logf("CTRL read end: %v", err)
			close(out)
			return
		}
		if txt == "" {
			continue
		}
		logf("CTRL <- %s", txt)
		select {
		case out <- txt:
		default:
		}
	}
}

func localIPs() []string {
	var ips []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "127.") {
			return
		}
		for _, x := range ips {
			if x == s {
				return
			}
		}
		ips = append(ips, s)
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if v4 := ipn.IP.To4(); v4 != nil {
						add(strings.TrimSpace(v4.String()))
					}
				}
			}
		}
	}
	if len(ips) == 0 {
		if u, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
			add(u.LocalAddr().(*net.UDPAddr).IP.String())
			u.Close()
		}
	}
	return ips
}

// ---------------------------------------------------------------- STUN

func stunProbe(u *net.UDPConn) (string, int, bool) {
	var txid [12]byte
	rand.Read(txid[:])
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001)
	binary.BigEndian.PutUint32(req[4:], 0x2112A442)
	copy(req[8:], txid[:])

	servers := []string{"stun.l.google.com:19302", "stun1.l.google.com:19302", "stun.cloudflare.com:3478"}
	for _, s := range servers {
		if ra, err := net.ResolveUDPAddr("udp4", s); err == nil {
			u.WriteToUDP(req, ra)
		}
	}
	buf := make([]byte, 1500)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		u.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := u.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		d := buf[:n]
		if n < 20 || binary.BigEndian.Uint16(d[0:]) != 0x0101 {
			continue
		}
		ip, port := parseXorMapped(d)
		if ip != "" {
			logf("STUN mapped = %s:%d", ip, port)
			return ip, port, true
		}
	}
	return "", 0, false
}

func parseXorMapped(d []byte) (string, int) {
	i := 20
	for i+4 <= len(d) {
		at := binary.BigEndian.Uint16(d[i:])
		al := int(binary.BigEndian.Uint16(d[i+2:]))
		if i+4+al > len(d) {
			break
		}
		v := d[i+4 : i+4+al]
		if at == 0x0020 && len(v) >= 8 && v[1] == 0x01 {
			port := int(binary.BigEndian.Uint16(v[2:4])) ^ 0x2112
			ip := net.IPv4(v[4]^0x21, v[5]^0x12, v[6]^0xa4, v[7]^0x42)
			return ip.String(), port
		}
		i += 4 + al + (4-al%4)%4
	}
	return "", 0
}

// ---------------------------------------------------------------- 打洞

func punch(u *net.UDPConn, ct *ctrl, frames <-chan string, c cfg, extIP string, extPort int, con string) (*net.UDPConn, *net.UDPAddr, error) {
	buf := make([]byte, 4096)
	var peer *net.UDPAddr
	var hints []*net.UDPAddr
	var lanU *net.UDPConn
	state := "punch"
	okCount := 0
	last2 := time.Time{}
	lastProbe := time.Now()
	busyUntil := time.Time{}
	nextCon := time.Now().Add(8 * time.Second)
	conTries := 1
	deadline := time.Now().Add(c.punchTimeout)

	logf("PUNCH start, ext=%s:%d, wait up to %v", extIP, extPort, c.punchTimeout)
	for time.Now().Before(deadline) {
		select {
		case f, ok := <-frames:
			if !ok {
				return nil, nil, errors.New("控制连接已断开")
			}
			if strings.Contains(f, "@csbusy") {
				busyUntil = time.Now().Add(15 * time.Second)
				logf("SERVER BUSY：15s 内不重发 @con（raw=%s）", f)
				continue
			}
			if strings.HasPrefix(f, "@lan") && envInt("NP_LAN_DIRECT", 0) != 0 {
				// 【实测推论】@lan 的端口就是被控端 server.newListen 的 KCP 监听端口：
				// 本机 natpierce 收到 @con 后 0.x 秒绑定 0.0.0.0:25839，随后 @lan 就带 25839。
				// 同 LAN 不需要打洞/不需要 csListen，直接对该地址做 KCP。
				if cands := parsePeerHints(f, 0); len(cands) > 0 {
					if ra, err := net.ResolveUDPAddr("udp4", cands[0]); err == nil {
						logf("LAN DIRECT → %s（跳过打洞/csListen，候选 %d 个）", ra, len(cands))
						return u, ra, nil
					}
				}
			}
			if strings.HasPrefix(f, "@lan") && lanU == nil && envInt("NP_LAN_LISTEN", 1) != 0 {
				// 局域网反向连接：访问端 natlan.LanCS(0x6c4c5a00) 用 concatstring5 拼帧
				//   0x6c4c612d 处 literal 长度 0xa = "@con|lan2|"   ← 注意是 lan2，不是 lan
				//   然后 + 全局串(0x6c957540) + ":" + 端口 + "|!"（0x6c5e4a3c 长度 2）
				// 实测 len("src") 见 F:\dsh-temp\lancs2.txt。故默认前缀用 lan2。
				if lu, port, err := listenUDPEphemeral(); err == nil {
					lanU = lu
					u = lu // 后续打洞与 KCP 都走这个 socket
					addrStr := strconv.Itoa(port)
					switch env("NP_LAN_FMT", "ip") {
					case "port":
						// 原样只带端口
					case "pub":
						addrStr = net.JoinHostPort(extIP, strconv.Itoa(port))
					default:
						addrStr = net.JoinHostPort(bestLanIP(), strconv.Itoa(port))
					}
					lvl := env("NP_LAN_LEVEL", "2")
					if v := env("NP_LAN_IP", ""); v != "" {
						addrStr = net.JoinHostPort(v, strconv.Itoa(port))
					}
					msg := fmt.Sprintf("@con|lan%s|csListen:%s|!", lvl, addrStr)
					if err := ct.send(c, msg); err != nil {
						logf("LAN csListen 上报失败: %v", err)
					} else {
						logf("LAN listen 0.0.0.0:%d, SEND %s", port, msg)
					}
					// natlan.csListen 绑好后会立刻 UDPConn.WriteToUDP 主动发一包（0x6c4c74a2），
					// 目的是把「访问端→被控端」这条路先打通，被控端随后才能回连。
					if envInt("NP_LAN_POKE", 1) != 0 {
						for _, cand := range parsePeerHints(f, 0) {
							if ra, err := net.ResolveUDPAddr("udp4", cand); err == nil {
								if _, err := lanU.WriteToUDP([]byte("cs"), ra); err == nil {
									logf("LAN poke -> %s", ra)
								}
							}
						}
					}
				} else {
					logf("LAN listen 失败: %v", err)
				}
			}
			if cands := parsePeerHints(f, extPort); len(cands) > 0 {
				for _, p := range cands {
					ra, err := net.ResolveUDPAddr("udp4", p)
					if err != nil {
						continue
					}
					dup := false
					for _, h := range hints {
						if h.String() == ra.String() {
							dup = true
						}
					}
					if !dup {
						hints = append(hints, ra)
					}
				}
				logf("PEER HINT %v", cands)
			}
		default:
		}

		// 退避重发 @con：服务端 @csbusy 时暂停，最多 6 次
		if time.Now().After(nextCon) && conTries < 6 && time.Now().After(busyUntil) {
			if err := ct.send(c, con); err == nil {
				conTries++
				logf("RESEND @con #%d", conTries)
			}
			nextCon = time.Now().Add(8 * time.Second)
		}

		// 已知对端候选但 3s 无入包：主动向所有候选发 '0' 开洞（仅公网模式；LAN 模式由对端回连）
		if state == "punch" && lanU == nil && len(hints) > 0 && time.Since(lastProbe) > 3*time.Second {
			logf("PROBE '0' x2 -> %v", hints)
			for i := 0; i < 2; i++ {
				for _, h := range hints {
					u.WriteToUDP([]byte("0"), h)
				}
				time.Sleep(150 * time.Millisecond)
			}
			peer = hints[0]
			state = "cs0"
			lastProbe = time.Now()
		}

		u.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, addr, err := u.ReadFromUDP(buf)
		if err != nil {
			if state == "wait2" && peer != nil && time.Since(last2) > 300*time.Millisecond {
				// '2' 可能丢，重发（官方同样每 300ms 重发到收到两帧 ok）
				u.WriteToUDP([]byte("2"), peer)
				last2 = time.Now()
			}
			continue
		}
		p := append([]byte(nil), buf[:n]...)
		if isSTUN(p) || addr.Port == 3478 || addr.Port == 19302 {
			logf("忽略 STUN 残留包 from %s len=%d", addr, n)
			continue
		}
		if n != 1 && string(p) != "CS" && string(p) != "ok" {
			logf("UDP <- %s len=%d %s", addr, n, hexdump(p))
		}

		switch {
		case string(p) == "CS":
			u.WriteToUDP([]byte("CC"), addr)
			logf("UDP CS from %s -> CC", addr)
			peer = addr
			if state == "punch" {
				state = "cs0"
			}
		case string(p) == "ok":
			okCount++
			logf("UDP ok #%d from %s", okCount, addr)
			peer = addr
			if okCount >= 2 {
				// 【§17 假设】被控端在发完 ok×2 后才调 PortForwarding 起 relay；
				// 若 relay 以"访问端最后一帧"为启动条件，缺这帧就会静默。
				if envInt("NP_PUNCH_TAIL", 1) != 0 {
					if _, err := u.WriteToUDP([]byte("2"), addr); err == nil {
						logf("PUNCH tail '2' -> %s（补发，触发 relay）", addr)
					}
				}
				logf("PUNCH done, peer=%s", addr)
				return u, addr, nil
			}
		case state == "punch" && string(p) == "0":
			// LAN 反向模式：对端回连先发 '0'，我们作为监听方回 '1'
			u.WriteToUDP([]byte("1"), addr)
			peer = addr
			state = "wait2"
			logf("UDP '0' from %s (对端回连) -> '1'", addr)
		case state == "punch":
			peer = addr
			logf("UDP first pkt from %s -> send '0' x5", addr)
			for i := 0; i < 5; i++ {
				u.WriteToUDP([]byte("0"), addr)
				time.Sleep(300 * time.Millisecond)
			}
			state = "cs0"
		case string(p) == "1" && (state == "cs0" || state == "wait1"):
			u.WriteToUDP([]byte("1"), addr)
			peer = addr
			state = "wait2"
			logf("UDP '1' from %s -> '1'", addr)
		case len(p) > 0 && p[0] == '2' && (state == "wait2" || state == "cs0" || state == "wait1"):
			u.WriteToUDP([]byte("2"), addr)
			peer = addr
			state = "waitok"
			logf("UDP '2' from %s (body=%q) -> '2'", addr, string(p[1:]))
		}
	}
	return nil, nil, fmt.Errorf("打洞超时（%v）", c.punchTimeout)
}

// bestLanIP 选一个非 link-local / 非回环的 IPv4，供 LAN csListen 上报。
func bestLanIP() string {
	for _, ip := range localIPs() {
		p := net.ParseIP(ip)
		if p == nil || p.To4() == nil || p.IsLoopback() || p.IsLinkLocalUnicast() {
			continue
		}
		return ip
	}
	for _, ip := range localIPs() {
		if p := net.ParseIP(ip); p != nil && p.To4() != nil && !p.IsLoopback() {
			return ip
		}
	}
	return "0.0.0.0"
}

// listenUDPEphemeral 绑定 0.0.0.0:0 并返回实际端口（LAN 反向模式 csListen 用）。
func listenUDPEphemeral() (*net.UDPConn, int, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, 0, err
	}
	return c, c.LocalAddr().(*net.UDPAddr).Port, nil
}

// rawProbe 用于判定「打洞后的链路是不是裸转发」：直接发明文，看本机 127.0.0.1:9999 的回声是否回来。
func rawProbe(u *net.UDPConn, peer *net.UDPAddr, forward string) {
	buf := make([]byte, 2048)
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("PING-MAP#%d", i+1)
		u.WriteToUDP([]byte(msg), peer)
		logf("RAWTEST -> %s %q", peer, msg)
		deadline := time.Now().Add(1200 * time.Millisecond)
		for time.Now().Before(deadline) {
			u.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, a, err := u.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			logf("RAWTEST <- %s len=%d hex=%s text=%q", a, n, hexdump(buf[:n]), string(buf[:n]))
			return
		}
	}
	logf("RAWTEST: 3 次明文探测均无回包（链路不是裸转发，或有 KCP 层）")
}
func isSTUN(b []byte) bool {
	return len(b) >= 20 && b[0] == 0x01 && b[1] == 0x01 && binary.BigEndian.Uint32(b[4:8]) == 0x2112A442
}

// drainUDP 清掉 STUN 阶段残留的回包，避免污染打洞状态机。
func drainUDP(u *net.UDPConn, d time.Duration) {
	buf := make([]byte, 2048)
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		u.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
		if _, _, err := u.ReadFromUDP(buf); err != nil {
			continue
		}
	}
}

// parsePeerHints 从 @n11/@lan 帧里抽取对端候选地址（可多个）。
//   @n11|1|<ip>|<port>|0|!              → <ip>:<port>
//   @lan|<ip;ip;...;ip>:<port>|!        → 每个 ip 配同一个 port
func parsePeerHints(txt string, extPort int) []string {
	var out []string
	parts := strings.Split(strings.TrimRight(txt, "|!"), "|")
	switch {
	case strings.HasPrefix(txt, "@n11"):
		if len(parts) >= 4 && parts[2] != "" && parts[3] != "" {
			out = append(out, net.JoinHostPort(parts[2], parts[3]))
		}
	case strings.HasPrefix(txt, "@lan"):
		if len(parts) < 2 || parts[1] == "" {
			return nil
		}
		spec, port := parts[1], ""
		if i := strings.LastIndex(spec, ":"); i >= 0 {
			port, spec = spec[i+1:], spec[:i]
		}
		if port == "" {
			port = strconv.Itoa(extPort)
		}
		for _, ip := range strings.Split(spec, ";") {
			if ip = strings.TrimSpace(ip); ip != "" {
				out = append(out, net.JoinHostPort(ip, port))
			}
		}
	}
	return out
}

func parsePeerHint(txt string, extPort int) string {
	if h := parsePeerHints(txt, extPort); len(h) > 0 {
		return h[0]
	}
	return ""
}

// firstHintAddr 把 @lan/@n11 帧的第一个候选解析成 UDPAddr，供打洞后的端口帧使用。
func firstHintAddr(f string) *net.UDPAddr {
	for _, s := range parsePeerHints(f, 0) {
		if a, err := net.ResolveUDPAddr("udp4", s); err == nil {
			return a
		}
	}
	return nil
}

// ---------------------------------------------------------------- KCP

func kcpKey() []byte {
	sum := md5.Sum([]byte(kcpSeed))
	return pbkdf2.Key(sum[:], []byte(kcpSalt), kcpIter, kcpLen, func() hash.Hash { return sha1.New() })
}

// tapConn 在 kcp 接管 UDP socket 后抓包，确认「我方有没有发出去 / 对端有没有回」。
type tapConn struct{ net.PacketConn }

func (t *tapConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := t.PacketConn.ReadFrom(p)
	if err == nil {
		logf("UDP <- %s %dB %s", a, n, hexdump(p[:min(n, 32)]))
	}
	return n, a, err
}

func (t *tapConn) WriteTo(p []byte, a net.Addr) (int, error) {
	n, err := t.PacketConn.WriteTo(p, a)
	if err == nil {
		logf("UDP -> %s %dB %s", a, n, hexdump(p[:min(n, 32)]))
	}
	return n, err
}

func kcpDial(u *net.UDPConn, peer *net.UDPAddr) (*kcp.UDPSession, error) {
	// 清掉打洞阶段残留的 deadline，否则 kcp 的 readLoop 会立刻超时
	u.SetReadDeadline(time.Time{})
	u.SetWriteDeadline(time.Time{})
	// 【重要】KCP 必须复用打洞用过的同一个 socket：NAT 只对这条五元组放行。
	// 官方 fork 的 DialWithOptions 第 9 参就是 net.PacketConn，同一语义；
	// 这里用 kcp.NewConn2(peer, block, ds, ps, pc)，pc 就是 u 本身
	// （MAP_TRACE 时外面只套一层透传的 tapConn，fd 不变）。
	if d := envInt("NP_KCP_DELAY_MS", 150); d > 0 {
		logf("KCP 复用打洞 socket %s → %s，等 %dms 让对端 newListen 就绪", u.LocalAddr(), peer, d)
		time.Sleep(time.Duration(d) * time.Millisecond)
	}

	key := kcpKey()
	logf("KCP key = %s", hex.EncodeToString(key))
	var block kcp.BlockCrypt
	var err error
	if !strings.EqualFold(env("MAP_CRYPT", "aes"), "none") {
		if block, err = kcp.NewAESBlockCrypt(key); err != nil {
			return nil, err
		}
	} else {
		logf("WARN MAP_CRYPT=none：KCP 层不加密（诊断用）")
	}
	ds, ps := 10, 3
	if v := env("MAP_FEC", ""); v != "" {
		if n, _ := fmt.Sscanf(v, "%d,%d", &ds, &ps); n != 2 {
			logf("WARN MAP_FEC=%q 解析失败，用 10,3", v)
			ds, ps = 10, 3
		}
	}
	logf("KCP fec=%d/%d crypt=%s", ds, ps, env("MAP_CRYPT", "aes"))
	var pc net.PacketConn = u
	if envInt("MAP_TRACE", 0) != 0 {
		pc = &tapConn{u}
	}
	sess, err := kcp.NewConn2(peer, block, ds, ps, pc)
	if err != nil {
		return nil, err
	}
	sess.SetStreamMode(true)
	sess.SetNoDelay(0, 40, 0, 0)
	sess.SetWindowSize(512, 1024)
	if !sess.SetMtu(1350) {
		logf("WARN SetMtu(1350) 失败，继续")
	}
	sess.SetACKNoDelay(true)
	sess.SetReadBuffer(4 << 20)
	sess.SetWriteBuffer(4 << 20)
	logf("KCP session created: conv=%d peer=%s fec=%d/%d stream=1 nodelay=(0,40,0,0) mtu=1350 win=512/1024",
		sess.GetConv(), peer.String(), ds, ps)
	return sess, nil
}

func kcpLogin(sess *kcp.UDPSession) error {
	// 先发 1 个 0 字节（MappingClientStar 的就绪信号）
	if _, err := sess.Write([]byte{0x00}); err != nil {
		return fmt.Errorf("write ready 0x00: %w", err)
	}
	logf("KCP -> 0x00")

	got2 := false
	tries := envInt("NP_LOGIN_TRIES", 100) // 默认重试 ~30s：被控端 PortForwarding→newListen 建 KCP 监听需要时间
	for i := 0; i < tries; i++ {
		if _, err := sess.Write([]byte{'1'}); err != nil {
			return fmt.Errorf("write '1': %w", err)
		}
		sess.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		b := make([]byte, 1)
		if _, err := io.ReadFull(sess, b); err == nil && b[0] == '2' {
			got2 = true
			logf("KCP login: got '2' after %d tries", i+1)
			break
		} else if err != nil {
			if i%10 == 0 {
				logf("KCP login try %d: %v", i+1, err)
			}
		} else {
			logf("KCP login try %d: 收到 %#x（期望 '2'）", i+1, b[0])
		}
	}
	if !got2 {
		return errors.New("KCP 登录失败：5 次 '1' 都没收到 '2'")
	}
	logf("KCP login: got '2'")

	if _, err := sess.Write([]byte("3")); err != nil {
		return fmt.Errorf("write \"3\": %w", err)
	}
	logf("KCP -> \"3\"")
	sess.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 1)
	if _, err := io.ReadFull(sess, b); err != nil {
		return fmt.Errorf("等 \"4\" 超时: %w", err)
	}
	if b[0] != '4' {
		return fmt.Errorf("期望 '4'(0x34)，收到 %#x", b[0])
	}
	logf("KCP login done: got '4'")
	sess.SetReadDeadline(time.Time{})
	return nil
}

// ---------------------------------------------------------------- goproxy 帧

type gpFrame struct {
	cmd  byte
	dir  bool // true = bit7 置位（本端 accept 出来的连接）
	id   uint32
	data []byte
}

func gpEncode(cmd byte, dir bool, id uint32, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = cmd & 0x1f
	if dir {
		b[0] |= 0x80
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(8+len(payload)))
	binary.LittleEndian.PutUint32(b[4:], id)
	copy(b[8:], payload)
	return b
}

func gpRead(r io.Reader) (gpFrame, error) {
	var h [8]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return gpFrame{}, err
	}
	total := int(binary.LittleEndian.Uint16(h[2:4]))
	if total < 8 || total > 65535 {
		return gpFrame{}, fmt.Errorf("非法 total_len=%d", total)
	}
	f := gpFrame{cmd: h[0] & 0x0f, dir: h[0]&0x80 != 0, id: binary.LittleEndian.Uint32(h[4:8])}
	if total > 8 {
		f.data = make([]byte, total-8)
		if _, err := io.ReadFull(r, f.data); err != nil {
			return gpFrame{}, err
		}
	}
	return f, nil
}

// Address/Listener 的 JSON 结构与 spec-mapping §5.4 对齐。
// Domain 在官方实现里被当作 network（"tcp"/"udp"）使用；Network 是冗余保险。
type gpAddress struct {
	Addr    string `json:"Addr"`
	Domain  string `json:"Domain,omitempty"`
	Network string `json:"Network,omitempty"`
}

type gpListener struct {
	Forward gpAddress `json:"Forward"`
	Listen  gpAddress `json:"Listen"`
}

// ---------------------------------------------------------------- 代理体

type connState struct {
	id      uint32
	udpAddr *net.UDPAddr
	tcpConn net.Conn
	last    time.Time
}

type proxy struct {
	mu       sync.Mutex
	sess     *kcp.UDPSession
	writeMu  sync.Mutex
	nextID   uint32
	byID     map[uint32]*connState
	byAddr   map[string]*connState
	forward  string
	netw     string
	listener net.Listener
	udpConn  *net.UDPConn
	closed   int32
}

func newProxy(sess *kcp.UDPSession, forward, netw string) *proxy {
	return &proxy{
		sess:    sess,
		nextID:  1,
		byID:    map[uint32]*connState{},
		byAddr:  map[string]*connState{},
		forward: forward,
		netw:    netw,
	}
}

func (p *proxy) send(cmd byte, dir bool, id uint32, payload []byte) error {
	b := gpEncode(cmd, dir, id, payload)
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	logf("KCP -> frame cmd=%d dir=%v id=%d len=%d %s", cmd, dir, id, len(payload), hexdump(b))
	_, err := p.sess.Write(b)
	return err
}

func (p *proxy) startListener(addr string) error {
	logf("LISTEN on %s (net=%s) forward=%s", addr, p.netw, p.forward)
	if p.netw == "udp" {
		a, err := net.ResolveUDPAddr("udp4", addr)
		if err != nil {
			return err
		}
		uc, err := net.ListenUDP("udp4", a)
		if err != nil {
			return err
		}
		p.udpConn = uc
		logf("LISTEN ready udp %s", uc.LocalAddr())
		go p.udpLoop(uc)
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.listener = ln
	logf("LISTEN ready tcp %s", ln.Addr())
	go p.tcpLoop(ln)
	return nil
}

func (p *proxy) idForAddr(a *net.UDPAddr) (*connState, bool) {
	key := a.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.byAddr[key]; ok {
		st.last = time.Now()
		return st, false
	}
	st := &connState{id: atomic.AddUint32(&p.nextID, 1), udpAddr: a, last: time.Now()}
	p.byID[st.id] = st
	p.byAddr[key] = st
	return st, true
}

func (p *proxy) udpLoop(uc *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := uc.ReadFromUDP(buf)
		if err != nil {
			logf("LISTEN udp read end: %v", err)
			return
		}
		st, isNew := p.idForAddr(addr)
		if isNew {
			payload, _ := json.Marshal(gpAddress{Addr: p.forward, Domain: p.netw, Network: p.netw})
			logf("NEW udp flow %s -> id=%d cmd=3 %s", addr, st.id, string(payload))
			if err := p.send(3, true, st.id, payload); err != nil {
				logf("cmd=3 send err: %v", err)
			}
		}
		if err := p.send(0, true, st.id, buf[:n]); err != nil {
			logf("cmd=0 send err: %v", err)
		}
	}
}

func (p *proxy) tcpLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			logf("LISTEN tcp accept end: %v", err)
			return
		}
		st := &connState{id: atomic.AddUint32(&p.nextID, 1), tcpConn: c, last: time.Now()}
		p.mu.Lock()
		p.byID[st.id] = st
		p.mu.Unlock()
		payload, _ := json.Marshal(gpAddress{Addr: p.forward, Domain: p.netw, Network: p.netw})
		logf("NEW tcp flow %s -> id=%d cmd=3 %s", c.RemoteAddr(), st.id, string(payload))
		p.send(3, true, st.id, payload)
		go func(st *connState) {
			buf := make([]byte, 32768)
			for {
				n, err := st.tcpConn.Read(buf)
				if n > 0 {
					p.send(0, true, st.id, buf[:n])
				}
				if err != nil {
					p.send(4, true, st.id, nil)
					p.dropConn(st.id)
					return
				}
			}
		}(st)
	}
}

func (p *proxy) dropConn(id uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.byID[id]; ok {
		if st.udpAddr != nil {
			delete(p.byAddr, st.udpAddr.String())
		}
		if st.tcpConn != nil {
			st.tcpConn.Close()
		}
		delete(p.byID, id)
	}
}

func (p *proxy) handle(f gpFrame) {
	switch f.cmd {
	case 0: // DATA
		p.mu.Lock()
		st := p.byID[f.id]
		p.mu.Unlock()
		if st == nil {
			logf("DATA for unknown id=%d (%dB)，忽略", f.id, len(f.data))
			return
		}
		if st.udpAddr != nil && p.udpConn != nil {
			if _, err := p.udpConn.WriteToUDP(f.data, st.udpAddr); err != nil {
				logf("udp write back err: %v", err)
			} else {
				logf("DATA id=%d -> udp %s %dB %s", f.id, st.udpAddr, len(f.data), hexdump(f.data))
			}
		} else if st.tcpConn != nil {
			st.tcpConn.Write(f.data)
			logf("DATA id=%d -> tcp %s %dB", f.id, st.tcpConn.RemoteAddr(), len(f.data))
		}
	case 1, 2: // PAUSE / RESUME
		logf("cmd=%d (pause/resume) id=%d", f.cmd, f.id)
	case 3: // NEW_CONN：本端是被 dial 侧才会收到，正常不该出现
		logf("cmd=3 收到（非预期）id=%d payload=%s", f.id, string(f.data))
	case 4: // CLOSE
		logf("CLOSE id=%d", f.id)
		p.dropConn(f.id)
	case 5: // NEW_LISTENER
		var lst gpListener
		if err := json.Unmarshal(f.data, &lst); err != nil {
			logf("cmd=5 JSON 解析失败: %v raw=%s", err, string(f.data))
			return
		}
		logf("cmd=5 Listener: forward=%+v listen=%+v", lst.Forward, lst.Listen)
		if lst.Forward.Addr != "" {
			p.forward = lst.Forward.Addr
		}
		netw := pickNet(lst.Forward.Domain, lst.Listen.Domain, p.netw)
		p.netw = netw
		addr := lst.Listen.Addr
		if addr == "" {
			addr = env("MAP_LISTEN", "0.0.0.0:10000")
		}
		addr = sanitizeListen(addr)
		if err := p.startListener(addr); err != nil {
			logf("LISTEN 失败: %v", err)
		}
	case 6: // KEEPALIVE：原样回显
		logf("KEEPALIVE id=%d", f.id)
		p.send(6, f.dir, f.id, f.data)
	case 7:
		// NOOP
	default:
		logf("未知 cmd=%d id=%d len=%d", f.cmd, f.id, len(f.data))
	}
}

// sanitizeListen 兜住服务端可能下发的 "0.0.0.0:udp" 这类非数字端口（spec-mapping §5.4 已知歧义）。
func sanitizeListen(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		if _, e := strconv.Atoi(port); e == nil {
			return addr
		}
		if host == "" {
			host = "0.0.0.0"
		}
		if _, mp, e2 := net.SplitHostPort(env("MAP_LISTEN", "0.0.0.0:10000")); e2 == nil {
			out := net.JoinHostPort(host, mp)
			logf("WARN Listen.Addr=%q 端口非数字，改用 %s", addr, out)
			return out
		}
	}
	if addr != "" {
		logf("WARN Listen.Addr=%q 无法解析，改用 MAP_LISTEN", addr)
	}
	return env("MAP_LISTEN", "0.0.0.0:10000")
}

func pickNet(cands ...string) string {	for _, c := range cands {
		switch strings.ToLower(strings.TrimSpace(c)) {
		case "udp", "udp4", "udp6":
			return "udp"
		case "tcp", "tcp4", "tcp6":
			return "tcp"
		}
	}
	if envInt("MAP_UDP", 1) != 0 {
		return "udp"
	}
	return "tcp"
}

func (p *proxy) loop() error {
	for {
		f, err := gpRead(p.sess)
		if err != nil {
			return err
		}
		logf("KCP <- frame cmd=%d dir=%v id=%d len=%d %s", f.cmd, f.dir, f.id, len(f.data), hexdump(f.data))
		p.handle(f)
	}
}

// ---------------------------------------------------------------- main

// runDirect 跳过控制面与打洞，直接对一个已知 UDP 地址建 KCP 并跑 goproxy。
// 用途：验证 KCP 线格式/加密（例如直连被控端本机 PortForwarding 端口）。
func runDirect(c cfg, addr string) {
	ra, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		log.Fatalf("NP_DIRECT 地址非法: %v", err)
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		log.Fatalf("UDP bind 失败: %v", err)
	}
	logf("DIRECT -> %s（跳过控制面/打洞）", ra)
	sess, err := kcpDial(u, ra)
	if err != nil {
		log.Fatalf("KCP 建链失败: %v", err)
	}
	defer sess.Close()
	if err := kcpLogin(sess); err != nil {
		log.Fatalf("KCP 登录失败: %v", err)
	}
	netw := pickNet(c.mapNet)
	p := newProxy(sess, c.mapForward, netw)
	logf("PROXY ready(forward=%s net=%s)，本地监听 %s", c.mapForward, netw, c.mapListen)
	if err := p.startListener(c.mapListen); err != nil {
		logf("本地监听失败: %v", err)
	}
	select {}
}

func main() {
	log.SetFlags(0)
	c := loadCfg()
	logf("mapgo start: cs=%s:%d pcid=%s udpPort=%d listen=%s forward=%s net=%q hexWire=%v",
		csHost, csPort, c.pcid, c.udpPort, c.mapListen, c.mapForward, c.mapNet, c.hexWire)

	if d := env("NP_DIRECT", ""); d != "" {
		runDirect(c, d)
		return
	}

	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: c.udpPort})
	if err != nil {
		log.Fatalf("UDP bind %d 失败: %v", c.udpPort, err)
	}
	defer u.Close()
	localPort := u.LocalAddr().(*net.UDPAddr).Port
	logf("UDP bind 0.0.0.0:%d", localPort)

	extIP, extPort, ok := stunProbe(u)
	if !ok {
		extPort = localPort
		logf("STUN 无响应，使用本地端口 %d", extPort)
	}
	drainUDP(u, 500*time.Millisecond)

	ct, err := dialCtrl()
	if err != nil {
		log.Fatalf("连接控制服务器失败: %v", err)
	}
	defer ct.c.Close()

	session, pubip, err := ct.login(c)
	if err != nil {
		log.Fatalf("登录失败: %v", err)
	}
	logf("LOGIN ok session=%s pubip=%s", session, pubip)

	ips := localIPs()
	head := extIP
	if head == "" {
		head = pubip
	}
	if head != "" {
		found := false
		for _, ip := range ips {
			if ip == head {
				found = true
			}
		}
		if !found {
			ips = append([]string{head}, ips...)
		}
	}
	ipstr := strings.Join(ips, ";") + ":" + strconv.Itoa(extPort)
	logf("REPORT %s", ipstr)

	frames := make(chan string, 64)
	go ctrlReader(ct, frames)

	con := fmt.Sprintf("@con|@zjOK|%s|%s|%s|%s|%d|%d|0||%s|!",
		session, md5hex(c.conpwd), c.conMode, c.code, extPort, extPort, ipstr)
	if err := ct.send(c, con); err != nil {
		log.Fatalf("发送 @con 失败: %v", err)
	}
	logf("SEND @con: %s", con)

	u, peer, err := punch(u, ct, frames, c, head, extPort, con)
	if err != nil {
		log.Fatalf("打洞失败: %v", err)
	}

	// 打洞完成后，服务端/被控端可能**再补发**一帧端口提示（被控端 newListen 的 KCP 监听端口
	// 是在它收到 ok 之后才 bind 的，所以必须晚于打洞才知道）。punch() 已经不再读 frames，
	// 这里接管：记录所有控制帧，并把新的 @lan/@n11 候选交给 KCP。
	hintCh := make(chan *net.UDPAddr, 8)
	go func() {
		for f := range frames {
			logf("CTRL <- %s", f)
			if a := firstHintAddr(f); a != nil {
				select {
				case hintCh <- a:
				default:
				}
			}
		}
	}()
	if ms := envInt("NP_HINT_WAIT_MS", 3000); ms > 0 {
		logf("等待打洞后的端口帧（最多 %dms）…", ms)
		select {
		case a := <-hintCh:
			logf("KCP 目标改为 %s（打洞后补发的端口提示）", a)
			peer = a
		case <-time.After(time.Duration(ms) * time.Millisecond):
			logf("无新的端口帧，继续用打洞地址 %s", peer)
		}
	}

	if envInt("MAP_RAWTEST", 0) != 0 {
		rawProbe(u, peer, c.mapForward)
	}

	sess, err := kcpDial(u, peer)
	if err != nil {
		log.Fatalf("KCP 建链失败: %v", err)
	}
	defer sess.Close()

	if err := kcpLogin(sess); err != nil {
		log.Fatalf("KCP 登录失败: %v", err)
	}

	netw := pickNet(c.mapNet)
	p := newProxy(sess, c.mapForward, netw)
	logf("PROXY ready: forward=%s net=%s（等待 cmd=5，或 %d 秒后用 MAP_LISTEN 兜底）",
		c.mapForward, netw, envInt("MAP_LISTEN_FALLBACK", 20))

	// 自测：MAP_SELFTEST=1 时自动向本地监听口发 PING-MAP，收到 PONG:PING-MAP 打印 ACCEPT OK
	if envInt("MAP_SELFTEST", 0) != 0 {
		go func() {
			_, portStr, _ := net.SplitHostPort(c.mapListen)
			port, _ := strconv.Atoi(portStr)
			dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
			c, err := net.DialUDP("udp4", nil, dst)
			if err != nil {
				logf("SELFTEST dial %s 失败: %v", dst, err)
				return
			}
			defer c.Close()
			buf := make([]byte, 2048)
			for i := 1; i <= 6; i++ {
				time.Sleep(3 * time.Second)
				msg := fmt.Sprintf("PING-MAP#%d", i)
				if _, err := c.Write([]byte(msg)); err != nil {
					logf("SELFTEST 发送失败: %v", err)
					continue
				}
				logf("SELFTEST -> %s %q", dst, msg)
				c.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
				n, err := c.Read(buf)
				if err != nil {
					logf("SELFTEST <- 超时")
					continue
				}
				logf("SELFTEST <- %q", string(buf[:n]))
				if strings.HasPrefix(string(buf[:n]), "PONG:") {
					logf("ACCEPT OK: PONG 收到，映射链路打通")
					return
				}
			}
		}()
	}

	// 兜底：若指定时间没收到 cmd=5，自己起监听（Forward 用 MAP_FORWARD）
	go func() {
		wait := time.Duration(envInt("MAP_LISTEN_FALLBACK", 20)) * time.Second
		if wait <= 0 {
			return
		}
		time.Sleep(wait)
		p.mu.Lock()
		started := p.listener != nil || p.udpConn != nil
		p.mu.Unlock()
		if !started {
			logf("WARN %v 内未收到 cmd=5，按 MAP_LISTEN=%s 自行监听", wait, c.mapListen)
			if err := p.startListener(c.mapListen); err != nil {
				logf("兜底监听失败: %v", err)
			}
		}
	}()

	go func() {
		for {
			time.Sleep(10 * time.Second)
			if err := p.send(6, true, 0, nil); err != nil {
				return
			}
		}
	}()

	err = p.loop()
	logf("frame loop 结束: %v", err)
}
