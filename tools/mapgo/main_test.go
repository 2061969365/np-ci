package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestKCPKey 对齐 spec-mapping §3.1 的实测值。
func TestKCPKey(t *testing.T) {
	got := hex.EncodeToString(kcpKey())
	want := "3255c27433285d1ce9148638ee6c185ab416499cdeb1aaa71ea48eea7672d001"
	if got != want {
		t.Fatalf("kcp key = %s, want %s", got, want)
	}
}

// TestFrameHeader 覆盖 goproxy 8 字节头：cmd 低 4 位、bit7=direction、u16 LE 总长、u32 LE id。
func TestFrameHeader(t *testing.T) {
	payload := []byte(`{"Addr":"127.0.0.1:9999"}`)
	f := gpEncode(3, true, 7, payload)

	if f[0] != 0x83 {
		t.Fatalf("byte0 = %#x, want 0x83 (cmd=3|bit7)", f[0])
	}
	if f[1] != 0 {
		t.Fatalf("byte1 = %#x, want 0", f[1])
	}
	total := int(f[2]) | int(f[3])<<8
	if total != 8+len(payload) {
		t.Fatalf("total_len = %d, want %d", total, 8+len(payload))
	}
	if f[4] != 7 || f[5] != 0 || f[6] != 0 || f[7] != 0 {
		t.Fatalf("id 字段 = % x, want 07 00 00 00", f[4:8])
	}
	if !bytes.Equal(f[8:], payload) {
		t.Fatalf("payload mismatch")
	}
}

// TestFrameRoundTrip 校验解码端能按同一格式切帧。
func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := []gpFrame{
		{cmd: 5, dir: true, id: 0, data: []byte(`{"Forward":{"Addr":"127.0.0.1:9999"},"Listen":{"Addr":"0.0.0.0:10000"}}`)},
		{cmd: 0, dir: true, id: 9, data: []byte("PING-MAP")},
		{cmd: 0, dir: false, id: 9, data: []byte("PONG:PING-MAP")},
		{cmd: 4, dir: false, id: 9},
	}
	for _, f := range want {
		buf.Write(gpEncode(f.cmd, f.dir, f.id, f.data))
	}
	for i, w := range want {
		got, err := gpRead(&buf)
		if err != nil {
			t.Fatalf("#%d read: %v", i, err)
		}
		if got.cmd != w.cmd || got.dir != w.dir || got.id != w.id || !bytes.Equal(got.data, w.data) {
			t.Fatalf("#%d got %+v want %+v", i, got, w)
		}
	}
}

// TestCtrlCrypto 校验控制面 AES-128-CBC + PKCS#7 往返。
func TestCtrlCrypto(t *testing.T) {
	plain := "@pc|@imcs|685006|x|acct|CloudMap|1.06|0|!"
	ct := ctrlEncrypt([]byte(plain))
	if len(ct)%16 != 0 {
		t.Fatalf("cipher len %d 不是 16 的倍数", len(ct))
	}
	pt, err := ctrlDecrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != plain {
		t.Fatalf("roundtrip = %q", pt)
	}
}
