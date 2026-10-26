"""Drive the official natpierce v1.06 panel (localhost:33272) to call our server.

Fixed 2026-10-26: the cloud may return a pclist with MULTIPLE devices, e.g.
    pclist<$!$>2<$!$>runnervmdaln5<$!$><$!$><$!$>3<$!$>CloudSrv<$!$>...
The old parser only looked at parts[2] (the first device name), so as soon as
the runner's own device appeared first, the target was never found and no
conpc was ever sent. Now we scan every field for the target name and take the
immediately preceding field as its sequence number.
"""
import socket, base64, os, struct, time, sys

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HOST, PORT = '127.0.0.1', 33272
TARGET = os.environ.get('NP_TARGET') or 'CloudSrv'
ACC = os.environ.get('NP_ACCT') or '2061969365@qq.com'
PWD = os.environ.get('NP_PWD') or 'qaz123wsx456'


def connect():
    s = socket.create_connection((HOST, PORT), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    req = ('GET /ws HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n'
           'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
           'Sec-WebSocket-Version: 13\r\n\r\n' % (HOST, PORT, key))
    s.sendall(req.encode())
    buf = b''
    while b'\r\n\r\n' not in buf:
        d = s.recv(4096)
        if not d:
            raise RuntimeError('closed')
        buf += d
    head, rest = buf.split(b'\r\n\r\n', 1)
    return s, rest


def send(s, text):
    p = text.encode()
    h = bytearray([0x81])
    n = len(p)
    if n < 126:
        h.append(0x80 | n)
    else:
        h.append(0x80 | 126)
        h += struct.pack('!H', n)
    mask = os.urandom(4)
    h += mask
    h += bytes(b ^ mask[i % 4] for i, b in enumerate(p))
    s.sendall(bytes(h))


buf = b''


def recv(s, timeout=1.5):
    global buf
    s.settimeout(timeout)
    try:
        d = s.recv(65536)
        if not d:
            return None
        buf += d
    except (socket.timeout, TimeoutError):
        return None
    out = []
    while len(buf) >= 2:
        b0, b1 = buf[0], buf[1]
        ln = b1 & 0x7f
        off = 2
        if ln == 126:
            if len(buf) < 4:
                break
            ln = struct.unpack('!H', buf[2:4])[0]
            off = 4
        if len(buf) < off + ln:
            break
        out.append(buf[off:off + ln].decode('utf-8', 'replace'))
        buf = buf[off + ln:]
    return out


def find_seq(m, target):
    """Return the seq of the device named `target` anywhere in a pclist frame."""
    parts = m.split('<$!$>')
    for i, val in enumerate(parts):
        if i >= 1 and val.strip() == target:
            prev = parts[i - 1].strip()
            if prev.isdigit():
                return prev
    return None


def main():
    s = None
    for _ in range(20):
        try:
            s, _ = connect()
            break
        except Exception as e:
            print('wait panel', e, flush=True)
            time.sleep(3)
    if s is None:
        sys.exit('panel never up')
    print('panel up', flush=True)

    send(s, 'login<$!$>%s<$!$>%s<$!$>0<$!$>0' % (ACC, PWD))
    time.sleep(6)
    for m in recv(s, 2) or []:
        print('LOGIN', m[:120], flush=True)

    seq = None
    for i in range(15):
        send(s, 'pclist')
        time.sleep(1.2)
        for m in recv(s, 2) or []:
            print('LIST', m[:200], flush=True)
            if m.startswith('pclist<$!$>'):
                got = find_seq(m, TARGET)
                if got:
                    seq = got
        if seq:
            break

    print('seq', seq, flush=True)
    if not seq:
        return

    send(s, 'conpc<$!$>%s' % seq)
    t0 = time.time()
    while time.time() - t0 < 100:
        for m in recv(s, 2) or []:
            print('CON', m[:200], flush=True)
    print('done', flush=True)


main()
