package expr

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// NFTA_CT_EXPECT_TIMEOUT 的字节序是本机序，不是网络序。
//
// 实测（内核 7.2.6，x86_64）：`nft add ct expectation … timeout 1m` 下发的属性体是
// 60 ea 00 00，即 60000 的本机序；同一块里的 dport 反而是 be16。用 BigEndian 编解码
// 不会报错——库自己进出一致，只有内核和 nft 会看见一个 0x60EA0000 毫秒的超时。
func TestCtExpectTimeoutByteOrder(t *testing.T) {
	const ms = 60000

	e := &CtExpect{L4Proto: 6, DPort: 21, Timeout: ms, Size: 5}
	b, err := e.marshalData(2)
	if err != nil {
		t.Fatal(err)
	}
	if want := binary.NativeEndian.AppendUint32(nil, ms); !bytes.Contains(b, want) {
		t.Fatalf("timeout 不是本机序：找 % x，实际 % x", want, b)
	}
	if bad := binary.BigEndian.AppendUint32(nil, ms); bytes.Contains(b, bad) {
		t.Fatalf("timeout 用了网络序：% x", b)
	}

	// 反向：内核回读给的字节（属性头 08 00 04 00 + 本机序 60000）要解回 60000。
	kernel := binary.NativeEndian.AppendUint32([]byte{0x08, 0x00, 0x04, 0x00}, ms)
	got := &CtExpect{}
	if err := got.unmarshal(2, kernel); err != nil {
		t.Fatal(err)
	}
	if got.Timeout != ms {
		t.Fatalf("unmarshal timeout = %d，期望 %d", got.Timeout, ms)
	}
}
