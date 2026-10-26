import socket, base64, os, struct, time, sys

HOST, PORT = '127.0.0.1', 33272
ACC = os.environ.get('NP_ACCT', '2061969365@qq.com')
PWD = os.environ.get('NP_PWD', 'qaz123wsx456')
CODE = os.environ.get('NP_CODE', '28698199')

def connect():
    s = socket.create_connection((HOST, PORT), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    req = ('GET /ws HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n'
           'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n' % (HOST, PORT, key))
    s.sendall(req.encode())
    buf = b''
    while b'\r\n\r\n' not in buf:
        d = s.recv(4096)
        if not d: raise RuntimeError('closed')
        buf += d
    head, rest = buf.split(b'\r\n\r\n', 1)
    return s, rest

def send(s, text):
    p = text.encode(); h = bytearray([0x81]); n = len(p)
    if n < 126: h.append(0x80 | n)
    else: h.append(0x80 | 126); h += struct.pack('!H', n)
    mask = os.urandom(4); h += mask
    h += bytes(b ^ mask[i % 4] for i, b in enumerate(p))
    s.sendall(bytes(h))

buf = b''
def recv(s, timeout=2):
    global buf
    s.settimeout(timeout)
    try:
        d = s.recv(65536)
        if not d: return None
        buf += d
        if len(buf) < 2: return None
        b0, b1 = buf[0], buf[1]; ln = b1 & 0x7f; off = 2
        if ln == 126:
            if len(buf) < 4: return None
            ln = struct.unpack('!H', buf[2:4])[0]; off = 4
        if len(buf) < off + ln: return None
        payload = buf[off:off+ln]; buf = buf[off+ln:]
        return payload.decode('utf-8', 'replace')
    except (socket.timeout, TimeoutError):
        return None

def main():
    for attempt in range(20):
        try:
            s, _ = connect(); break
        except Exception as e:
            print('wait panel', e, flush=True); time.sleep(3)
    else:
        sys.exit('panel never came up')
    print('panel up', flush=True)
    send(s, 'login<$!$>%s<$!$>%s<$!$>0<$!$>0' % (ACC, PWD))
    t0 = time.time()
    seq = None
    while time.time() - t0 < 40:
        r = recv(s, 2)
        if not r: continue
        print('WS <-', r[:150], flush=True)
        if r.startswith('pclist<$!$>'):
            parts = r.split('<$!$>')
            for i in range(2, len(parts) - 1, 5):
                if parts[i].strip() == 'CloudSrv':
                    seq = parts[i-1].strip()
        if seq is None and 'CloudSrv' in r and r.startswith('pclist'):
            pass
    # 请求列表后连接
    send(s, 'pclist')
    time.sleep(3)
    while True:
        r = recv(s, 2)
        if not r: break
        print('WS <-', r[:200], flush=True)
    print('seq', seq, flush=True)
    if seq:
        send(s, 'conpc<$!$>%s' % seq)
        t0 = time.time()
        while time.time() - t0 < 60:
            r = recv(s, 2)
            if r: print('WS <-', r[:200], flush=True)
    time.sleep(30)

main()
