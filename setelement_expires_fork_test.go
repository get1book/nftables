// Copyright 2024 The nftables Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TestMarshalSetElementExpires 钉住 NFTA_SET_ELEM_EXPIRATION 的编码。
//
// 内核按大端 u64 毫秒读它（与读侧的 NFTA_SET_ELEM_TIMEOUT 同一套）。写错字节序不会报错，
// 只会让 nft 显示出一个离谱的剩余时间，所以这里直接断言字节。
func TestMarshalSetElementExpires(t *testing.T) {
	s := &Set{HasTimeout: true}

	b, err := (&Conn{}).marshalSetElement(s, &SetElement{
		Key:     []byte{1, 2, 3, 4},
		Timeout: 7 * time.Second,
		Expires: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("marshalSetElement: %v", err)
	}

	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		t.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	var timeout, expires uint64
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_TIMEOUT:
			timeout = ad.Uint64()
		case unix.NFTA_SET_ELEM_EXPIRATION:
			expires = ad.Uint64()
		}
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}
	if timeout != 7000 {
		t.Errorf("timeout = %d ms, want 7000", timeout)
	}
	if expires != 5000 {
		t.Errorf("expires = %d ms, want 5000", expires)
	}

	// 没给 expires 时不能凭空补一个 0（内核要求它和 timeout 同时出现，发个 0 会把元素
	// 的剩余时间直接抹掉）。
	b, err = (&Conn{}).marshalSetElement(s, &SetElement{Key: []byte{1, 2, 3, 4}, Timeout: 7 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ad, err = netlink.NewAttributeDecoder(b)
	if err != nil {
		t.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		if ad.Type() == unix.NFTA_SET_ELEM_EXPIRATION {
			t.Errorf("未指定 expires 时不应下发 NFTA_SET_ELEM_EXPIRATION")
		}
	}
}
