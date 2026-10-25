# -*- coding: utf-8 -*-
"""云端访问端：在 GitHub Actions 上跑，通过公网连本地官方被控端。

流程：登录 -> 发帧(上报本地IP:P) -> 解析 @n11/@lan -> 主动向对端发 CC 打通自身 NAT
      -> 收 CS 回 CC -> 1/1 -> 2/2 -> ok×2 -> 打印数据面。
"""
import hashlib, os, socket, sys, time
from Crypto.Cipher import AES

CS_HOST, CS_PORT = '101.43.214.174', 58717
KEY, IV = b'ChengFengPoLang!', b'17704510080'.ljust(16, b'\x00')
ACCT = os.environ.get('NP_ACCT', '2061969365@qq.com')
PWD = os.environ.get('NP_PWD', 'qaz123wsx456')
PCID = os.environ.get('NP_PCID', '685006')
CODE = os.environ.get('NP_CODE', '91505506')
CONPWD = os.environ.get('NP_CONPWD', 'qaz123wsx456')
PORT = int(os.environ.get('NP_UDP_PORT', '40100'))
DURATION = int(os.environ.get('NP_DURATION', '180'))
EPORT = PORT


def pad(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def unpad(b):
    n = b[-1]
    return b[:-n] if 1 <= n <= 16 and b[-n:] == bytes([n]) * n else b


def enc(s):
    return AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(s.encode())).hex().encode() + b' \r\n'


def dec(hl):
    return unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(bytes.fromhex(hl.decode()))).decode('utf-8', 'replace')


def md5h(b):
    return hashlib.md5(b).hexdigest()


def local_ips():
    ips = []
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(socket.gethostname(), None):
            if fam == socket.AF_INET and sa[0] not in ips and not sa[0].startswith('127.'):
                ips.append(sa[0])
    except Exception:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return ips


def resolve_peer(txt):
    """从 @n11 / @lan 解析对端候选地址列表。"""
    parts = txt.rstrip('|!').split('|')
    try:
        if txt.startswith('@n11'):
            ip = parts[2]
            n11_port = int(parts[3])
            cands = [(ip, EPORT)]
            if n11_port != PORT:
                cands.append((ip, n11_port))
            return cands
        if txt.startswith('@lan'):
            hostport = parts[1]
            iplist, port = hostport.rsplit(':', 1)
            return [(iplist.split(';')[0], int(port))]
    except Exception:
        pass
    return None


def stun_probe(u):
    """用 STUN 回显确认真实 NAT 出口地址（与 TCP 侧看到的 IP 可能不同）。"""
    import struct, random
    txid = bytes(random.getrandbits(8) for _ in range(12))
    req = struct.pack('!HHI', 0x0001, 0, 0x2112A442) + txid
    servers = [('stun.l.google.com', 19302), ('stun1.l.google.com', 19302),
               ('stun.cloudflare.com', 3478)]
    for host, port in servers:
        try:
            u.sendto(req, (socket.gethostbyname(host), port))
        except Exception as e:
            print('STUN send fail', host, e, flush=True)
    end = time.time() + 4
    seen = []
    while time.time() < end:
        try:
            data, addr = u.recvfrom(1024)
        except socket.timeout:
            continue
        except Exception:
            continue
        if len(data) < 20 or data[0:2] != b'\x01\x01':
            continue
        ip = port = None
        i = 20
        while i + 4 <= len(data):
            at, al = struct.unpack('!HH', data[i:i + 4])
            val = data[i + 4:i + 4 + al]
            if at == 0x0020 and len(val) >= 8:
                fam = val[1]
                if fam == 0x01:
                    p = struct.unpack('!H', val[2:4])[0] ^ 0x2112
                    a = bytes(x ^ y for x, y in zip(val[4:8], b'\x21\x12\xa4\x42'))
                    ip, port = '.'.join(str(x) for x in a), p
            i += 4 + al + ((4 - al % 4) % 4)
        if ip:
            print('PUBLIC(udp) via STUN %s:%d -> %s:%d' % (addr[0], addr[1], ip, port), flush=True)
            seen.append((ip, port))
    if not seen:
        print('PUBLIC(udp) = unknown (no STUN reply)', flush=True)
    return seen[0] if seen else None


MYPCID = b'685006'

punch_ports = []
punch_i = 0
punch_end = 0.0


def nat11_prepare(u, cands, ext_port, ip=None):
    """准备 nat11 空包齐射参数（非阻塞；收到第一包必须立刻停射）。"""
    global punch_ports, punch_i, punch_end
    bases = set([ext_port])
    for c in cands:
        bases.add(c[1])
    ports = []
    for b in sorted(bases):
        for k in range(-5, 11):
            if 1 <= b + k <= 65535 and (b + k) not in ports:
                ports.append(b + k)
    punch_ports = ports
    punch_i = 0
    punch_end = time.time() + 3
    print('NAT11 PUNCH %s ports=%d bases=%s' % (cands[0][0], len(ports), sorted(bases)), flush=True)


def _ck(b):
    import struct
    if len(b) % 2:
        b += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def icmp_ping(src, dst, seq=1):
    import struct as _st
    payload = b'PINGPONG' + _st.pack('!H', seq & 0xffff)
    icmp = _st.pack('!BBHHH', 8, 0, 0, seq, 1) + payload
    icmp = _st.pack('!BBHHH', 8, 0, _ck(icmp), seq, 1) + payload
    ip = _st.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), seq, 0, 64, 1, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + _st.pack('!H', _ck(ip)) + ip[12:]
    return ip + icmp



XKEY = b'820622'
PEER_PCID = b'685005'


def _xor(b):
    k = XKEY + PEER_PCID          # 12B: "820622" + 对端 pcid（§pcap 实测）
    n = len(k)
    return bytes(c ^ k[i % n] for i, c in enumerate(b))


def heart_msg(vpn, gw='10.6.22.1'):
    plain = bytes([0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0]) + \
            socket.inet_aton(vpn) + socket.inet_aton(gw)
    return _xor(plain)


def exit_frame(src, dst='10.6.22.1'):
    plain = bytes([0x45, 0x00, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
                   0x03, 0x02, 0x01, 0x00]) + socket.inet_aton(src) + socket.inet_aton(dst)
    return _xor(plain)


def udp_echo(src, dst, sport, dport, payload):
    import struct as _st
    udp = _st.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = _st.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0,
                  socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + _st.pack('!H', _ck(ip)) + ip[12:]
    return _xor(ip + udp)


def run_data_plane(u, dst, src, gw, secs=90, peer=None):
    """数据面：心跳 + ICMP + UDP 回声，结束时发退出帧。"""
    print('DATA LOOP dst=%s:%d src=%s gw=%s' % (dst[0], dst[1], src, gw), flush=True)
    targets = [(dst[0], dst[1])]
    for c in (peer or []):
        if c not in targets:
            targets.append(c)
    u.settimeout(0.5)
    t_end = time.time() + secs
    seq = sent = recv = 0
    next_hb = 0.0
    udp_n = 0
    while time.time() < t_end:
        try:
            if time.time() >= next_hb:
                for tg in targets:
                    u.sendto(heart_msg(src, gw), tg)
                sent += 1
                next_hb = time.time() + 2
                print('HB -> %s:%d' % (dst[0], dst[1]), flush=True)
            seq += 1
            u.sendto(_xor(icmp_ping(src, gw, seq & 0xffff)), dst)
            sent += 1
            udp_n += 1
            u.sendto(udp_echo(src, gw, 40000 + (udp_n % 1000), 9998, b'PING-UDP-%d' % udp_n), dst)
            sent += 1
        except Exception as e:
            print('send err', e, flush=True)
        try:
            raw, addr = u.recvfrom(4096)
            recv += 1
            if raw == b'820':
                if recv % 5 == 0:
                    print('HB ACK <- from %s:%d' % (addr[0], addr[1]), flush=True)
                continue
            plain = _xor(raw)
            if len(plain) >= 28 and plain[0] >> 4 == 4 and plain[9] == 1 and plain[20] == 0:
                print('ICMP REPLY <- %d bytes from %s' % (
                    len(plain), '.'.join(str(x) for x in plain[12:16])), flush=True)
            elif len(plain) >= 28 and plain[0] >> 4 == 4 and plain[9] == 17:
                print('UDP REPLY <- %d bytes payload=%r' % (len(plain), plain[28:64]), flush=True)
            elif len(plain) >= 20:
                print('DATA <- %d bytes %r' % (len(plain), plain[:24]), flush=True)
        except socket.timeout:
            pass
        except Exception as e:
            print('recv err', e, flush=True)
    for _ in range(3):
        try:
            u.sendto(exit_frame(src, gw), dst)
            time.sleep(0.06)
        except Exception as e:
            print('exit err', e, flush=True)
    print('EXIT FRAME sent x3', flush=True)
    print('DATA LOOP DONE sent=%d recv=%d' % (sent, recv), flush=True)


def main():
    global punch_ports, punch_i, punch_end
    global EPORT
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(('0.0.0.0', PORT))
    u.settimeout(0.15)
    print('UDP bind 0.0.0.0:%d' % PORT, flush=True)
    pub = stun_probe(u)
    ext_ip, ext_port = (pub[0], pub[1]) if pub else (None, PORT)
    EPORT = ext_port
    print('EXT =', ext_ip, ext_port, flush=True)

    t = socket.create_connection((CS_HOST, CS_PORT), timeout=15)
    t.settimeout(0.2)
    t.sendall(enc('@pc|@imcs|%s|%s|%s|CloudMap|1.06|0|!' % (PCID, md5h(md5h(PWD.encode()).encode()), ACCT)))
    tbuf = b''
    session = None
    pubip = None
    end = time.time() + 15
    while time.time() < end and not session:
        try:
            d = t.recv(65536)
            if not d:
                break
            tbuf += d
        except socket.timeout:
            continue
        while b'\r\n' in tbuf:
            i = tbuf.find(b'\r\n')
            line, tbuf = tbuf[:i].strip(), tbuf[i + 2:]
            if not line:
                continue
            try:
                txt = dec(line)
            except Exception:
                continue
            print('TCP <-', txt[:200], flush=True)
            if txt.startswith('@csok'):
                f = txt.split('|')
                session = f[2]
                pubip = f[3]
    if not session:
        print('LOGIN FAILED', flush=True)
        return

    ips = local_ips()
    head = ext_ip or pubip
    if head and head not in ips:
        ips = [head] + ips
    ipstr = ';'.join(ips) + ':%d' % ext_port
    print('REPORT_IPS:', ipstr, flush=True)
    frame = '@con|@zjOK|%s|%s|1|%s|%d|%d|0||%s|!' % (session, md5h(CONPWD.encode()), CODE, ext_port, ext_port, ipstr)
    print('SEND:', frame, flush=True)
    t.sendall(enc(frame))

    peer = None
    state = 'punch'
    ok_count = 0
    vpn_src = ''
    vpn_gw = ''
    ping_seq = 1
    ping_next = 0.0
    last_2 = 0.0
    swept = False
    frames_sent = 1
    last_frame = time.time()
    last_beat = time.time()
    last_nudge = 0.0
    deadline = time.time() + DURATION
    while time.time() < deadline:
        if time.time() - last_beat > 15:
            try:
                t.sendall(b'\x00')
                last_beat = time.time()
            except Exception:
                pass
        try:
            d = t.recv(65536)
            if d:
                tbuf += d
                while b'\r\n' in tbuf:
                    i = tbuf.find(b'\r\n')
                    line, tbuf = tbuf[:i].strip(), tbuf[i + 2:]
                    if not line:
                        continue
                    try:
                        txt = dec(line)
                    except Exception:
                        continue
                    print('TCP <-', txt[:200], flush=True)
                    p = resolve_peer(txt)
                    if p and not peer:
                        peer = p
                        print('PEER =', peer, flush=True)
                        nat11_prepare(u, p, ext_port)
        except socket.timeout:
            pass
        except Exception:
            pass

        if peer and state == 'punch' and not swept and os.environ.get('NP_SWEEP') == '1':
            # 暴力暖 Azure 入站过滤：向对端 IP 的整段端口各发一个 CC，
            # 让被控端可能使用的任意出网源端口都变成"我们发过"的目的端点。
            ip = peer[0][0]
            lo = int(os.environ.get('NP_SWEEP_LO', '1024'))
            hi = int(os.environ.get('NP_SWEEP_HI', '65535'))
            print('SWEEP %s:%d-%d' % (ip, lo, hi), flush=True)
            for p in range(lo, hi + 1):
                try:
                    u.sendto(b'CC', (ip, p))
                except Exception:
                    pass
            swept = True
            print('SWEEP done', flush=True)

        if state == 'punch' and frames_sent < 8 and time.time() - last_frame > 3:
            # 像官方一样反复发起（每次都会让被控端重新打一轮洞）
            try:
                t.sendall(enc(frame))
                frames_sent += 1
                last_frame = time.time()
                print('RESEND frame #%d' % frames_sent, flush=True)
            except Exception:
                pass

        if peer and state == 'punch' and time.time() < punch_end:
            # nat11 空包齐射：收到第一包就停（官方收包即 StopRecv；空包会让被控端 Go panic）
            for pp in punch_ports[punch_i:punch_i + 8]:
                try:
                    u.sendto(b'', (peer[0][0], pp))
                except Exception:
                    pass
            punch_i = (punch_i + 8) % len(punch_ports)

        try:
            data, addr = u.recvfrom(4096)
            print('RX from %s:%d len=%d' % (addr[0], addr[1], len(data)), flush=True)
        except socket.timeout:
            continue
        except ConnectionResetError:
            continue
        if data[:2] == b'CS':
            u.sendto(b'CC', addr)
            print('CS from %s:%d -> CC' % (addr[0], addr[1]), flush=True)
            if state == 'punch':
                state = 'wait1'
            peer = [addr]
            continue
        if not peer:
            continue
        print('UDP <- %s:%d len=%d %r' % (addr[0], addr[1], len(data), data[:24]), flush=True)
        if state == 'punch':
            # 收到第一包 -> 立刻停空包，进入 ClientStar 阶段1：发单字节 '0' ×5（300ms 间隔）
            state = 'cs0'
            peer = [addr]
            for _ in range(5):
                u.sendto(b'0', addr)
                time.sleep(0.3)
            print('  sent 0 x5 -> %s:%d' % (addr[0], addr[1]), flush=True)
            continue
        if data == b'1' and state in ('cs0', 'wait1'):
            u.sendto(b'1', addr)
            print('  -> 1', flush=True)
            state = 'wait2'
            peer = [addr]
            continue
        if state == 'wait2' and data[:1] == b'2':
            txt = data[1:].decode('utf-8', 'replace')
            u.sendto(b'2', addr)
            print('  -> 2 (vpn=%r)' % txt, flush=True)
            parts = txt.split('|')
            if len(parts) >= 2:
                vpn_src, vpn_gw = parts[0].strip(), parts[1].strip()
                print('VPN IP=%s GW=%s' % (vpn_src, vpn_gw), flush=True)
            state = 'waitok'
            peer = [addr]
            if vpn_src and vpn_gw:
                print('=== DATA PLANE (do not wait ok) ===', flush=True)
                run_data_plane(u, addr, vpn_src, vpn_gw, peer=peer)
                state = 'closed'
                break
            continue
        if data.isdigit() and 5 <= len(data) <= 8 and state in ('wait2', 'waitok', 'data'):
            # 被控端上报自己的识别码 -> 回我们自己的 pcid
            global PEER_PCID
            PEER_PCID = bytes(data)
            print('  -> pcid echo %r (XOR key len=%d)' % (data, len(XKEY) + len(PEER_PCID)), flush=True)
            peer = [addr]
            continue
        if data == b'ok':
            ok_count += 1
            print('  got ok #%d' % ok_count, flush=True)
            if ok_count >= 2:
                print('=== HANDSHAKE DONE, data plane open ===', flush=True)
                state = 'data'
                print('=== ENTER DATA LOOP 90s ===', flush=True)
                run_data_plane(u, peer[0], vpn_src, vpn_gw, peer=peer)
                state = 'closed'
                break
        elif state == 'data':
            # 数据面：裸 IPv4 包。解析 ICMP echo reply，其余按字节记录
            if len(data) >= 28 and data[0] >> 4 == 4 and data[9] == 1 and data[20] == 0:
                print('ICMP REPLY <- %d bytes from %s' % (
                    len(data), '.'.join(str(x) for x in data[12:16])), flush=True)
            else:
                print('DATA <- %d bytes %r' % (len(data), data[:24]), flush=True)


        if state == 'waitok' and peer and ok_count < 2 and time.time() - last_2 > 0.3:
            # ok 可能丢包：每 300ms 重发 '2'，直到收到两帧 ok
            try:
                u.sendto(b'2', peer[0])
                last_2 = time.time()
            except Exception:
                pass

        if state == 'data' and vpn_src and vpn_gw and time.time() >= ping_next:
            try:
                hb = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20, 0, 0, 64, 17, 0,
                                 socket.inet_aton(vpn_src), socket.inet_aton(vpn_gw))
                hb = hb[:10] + struct.pack('!H', _ck(hb)) + hb[12:]
                u.sendto(hb, peer[0])
                u.sendto(icmp_ping(vpn_src, vpn_gw, ping_seq), peer[0])
                print('PING -> %s:%d seq=%d' % (peer[0][0], peer[0][1], ping_seq), flush=True)
                ping_seq += 1
                ping_next = time.time() + 2
            except Exception as e:
                print('ping err', e, flush=True)
    print('END state=%s' % state, flush=True)


if __name__ == '__main__':
    main()
