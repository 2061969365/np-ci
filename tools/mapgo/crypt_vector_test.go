package main

// 本文件用「已知答案测试」把 natpierce.dll 内嵌 kcp-go 的**密文线格式**钉死，
// 防止以后升级依赖时线格式悄悄漂移。所有常量都来自目标二进制本身：
//
//	initialVector   DLL VA 0x6c4df030（slice header 0x6c5453a0, len=16, cap=16）
//	                = a7 73 4f 9c 12 ac 1b 01 a4 15 f2 c1 fc 78 e6 6b
//	cryptHeaderSize 20 = 16B 随机 nonce + 4B CRC32(IEEE, 小端)
//	CRC             hash/crc32.ChecksumIEEE，覆盖 buf[20:]（DLL 0x6c42b86c，紧接着
//	                `mov [ebp+0x10], ebx` 把结果小端写进 buf[16:20]）
//	加密            kcp-go.encrypt16 0x6c41e610：CFB，IV=initialVector，**从 buf[0] 起整包**
//	                （master crypt.go:427 `tbl := buf[:16]; block.Encrypt(tbl, initialVector)`）
//	随机源          io.ReadFull(entropy, buf[:16])（DLL 里是对 rand reader 的接口调用，长度 0x10）

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"testing"

	kcp "github.com/xtaci/kcp-go/v5"
)

// dllInitialVector 是目标 DLL 中 .data 段实测的 16 字节固定 IV。
var dllInitialVector = []byte{
	0xa7, 0x73, 0x4f, 0x9c, 0x12, 0xac, 0x1b, 0x01,
	0xa4, 0x15, 0xf2, 0xc1, 0xfc, 0x78, 0xe6, 0x6b,
}

// forkSeal 按 fork 的线格式封包：nonce(16) | crc32le(4) | ciphertext(payload)。
// nonce 固定时结果完全确定，便于做 KAT。
func forkSeal(block kcp.BlockCrypt, nonce []byte, payload []byte) []byte {
	buf := make([]byte, 20+len(payload))
	copy(buf[:16], nonce)
	copy(buf[20:], payload)
	binary.LittleEndian.PutUint32(buf[16:20], crc32.ChecksumIEEE(buf[20:]))
	block.Encrypt(buf, buf)
	return buf
}

// TestForkInitialVector 校验我们用常量与 DLL 里的一致（防止抄错一个字节）。
func TestForkInitialVector(t *testing.T) {
	const want = "a7734f9c12ac1b01a415f2c1fc78e66b"
	if got := hex.EncodeToString(dllInitialVector); got != want {
		t.Fatalf("initialVector 不一致: got %s want %s", got, want)
	}
}

// TestForkCryptIsCFBWithFixedIV 证明 master 的 NewAESBlockCrypt 就是
// 「固定 IV 的 CFB，整包（含 nonce 与 CRC）都加密」，与 DLL 反汇编一致。
func TestForkCryptIsCFBWithFixedIV(t *testing.T) {
	key := kcpKey()
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		t.Fatalf("NewAESBlockCrypt: %v", err)
	}
	nonce := bytes.Repeat([]byte{0x11}, 16)
	payload := []byte("PING-MAP-from-fork-crypt-test")

	got := forkSeal(block, nonce, payload)

	// 参考实现：标准库 CFB，IV = DLL 的 initialVector，作用范围是整个包
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	want := make([]byte, 20+len(payload))
	copy(want[:16], nonce)
	copy(want[20:], payload)
	binary.LittleEndian.PutUint32(want[16:20], crc32.ChecksumIEEE(payload))
	cipher.NewCFBEncrypter(aesBlock, dllInitialVector).XORKeyStream(want, want)

	if !bytes.Equal(got, want) {
		t.Fatalf("线格式不符:\n got %s\nwant %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
	// 整包必须都被加密：nonce 位置在密文里不能还是 0x11 平文
	if bytes.Equal(got[:16], nonce) {
		t.Fatal("nonce 段未加密，说明不是整包 CFB")
	}
}

// TestForkCryptKnownAnswer 固定 key/nonce/明文 → 固定密文（KAT）。
// 期望值由本实现算出后固化；任何依赖升级/常量改动导致线格式变化都会在这里炸掉。
func TestForkCryptKnownAnswer(t *testing.T) {
	block, err := kcp.NewAESBlockCrypt(kcpKey())
	if err != nil {
		t.Fatalf("NewAESBlockCrypt: %v", err)
	}
	nonce := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	payload := []byte{0x01, 0x00, 0x00, 0x00} // KCP cmd=1(ACK), frg=0, wnd=0
	got := forkSeal(block, nonce, payload)

	// 期望值由本实现算出后固化（已用 pycryptodome CFB-128 独立复核：
	//   AES.new(key, MODE_CFB, iv=initialVector, segment_size=128).encrypt(nonce||crc32le||payload)）
	const want = "89974982562f3c1c5eb002b100db53f4c440e4a885288eb6"
	if want == "" {
		t.Logf("KAT ciphertext = %s", hex.EncodeToString(got))
		return
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("KAT 不符:\n got %s\nwant %s", hex.EncodeToString(got), want)
	}
}

// TestForkCryptDecryptRoundTrip 解密 + CRC 校验（对应 DLL packetInput 0x6c42c1e5 处的
// ChecksumIEEE 比对），并验证篡改一个字节会被 CRC 抓到。
func TestForkCryptDecryptRoundTrip(t *testing.T) {
	block, err := kcp.NewAESBlockCrypt(kcpKey())
	if err != nil {
		t.Fatalf("NewAESBlockCrypt: %v", err)
	}
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	payload := []byte("hello-natpierce-mapping")

	sealed := forkSeal(block, nonce, payload)

	plain := make([]byte, len(sealed))
	block.Decrypt(plain, sealed)
	if !bytes.Equal(plain, append(append([]byte{}, nonce...), append(make([]byte, 4), payload...)...)) {
		// 头部 4 字节是 CRC，单独比较
		if !bytes.Equal(plain[:16], nonce) || !bytes.Equal(plain[20:], payload) {
			t.Fatalf("解密结果不符: %s", hex.EncodeToString(plain))
		}
	}
	if got, want := binary.LittleEndian.Uint32(plain[16:20]), crc32.ChecksumIEEE(plain[20:]); got != want {
		t.Fatalf("CRC 不符: got %#x want %#x", got, want)
	}
	if !bytes.Equal(plain[20:], payload) {
		t.Fatalf("payload 不符: %q", plain[20:])
	}

	// 篡改密文 → 解密后再算 CRC 必须对不上（DLL packetInput 就是靠这个丢包）
	sealed[len(sealed)-1] ^= 0xff
	bad := make([]byte, len(sealed))
	block.Decrypt(bad, sealed)
	if binary.LittleEndian.Uint32(bad[16:20]) == crc32.ChecksumIEEE(bad[20:]) {
		t.Fatal("篡改后 CRC 仍然匹配，校验逻辑不成立")
	}
}
