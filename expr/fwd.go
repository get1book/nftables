// Copyright 2024 Google LLC. All Rights Reserved.
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

// Fwd（`fwd to <dev>`）表达式。上游 google/nftables 没有这个类型，
// 由本 fork 为 nfapi 补上。

package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Fwd 对应 `fwd to <dev>`（netdev 族的转发出口）或 `fwd <family> to <addr>`。
//
// 内核侧它是**语句**，但 netlink 形态就是一个名为 "fwd" 的表达式，
// 所以库侧按 expr 下发即可。
//
// 真机对照（nftables 1.1.7，`fwd to lo`）：
//
//	[ immediate reg 1 0x00000001 ]   ← lo 的 ifindex
//	[ fwd sreg_dev 1 ]
//
// 设备名只存在于 CLI，内核只认 ifindex，所以调用方要先自己发 immediate。
type Fwd struct {
	// Register 是存放出口设备 **ifindex** 的寄存器（NFTA_FWD_SREG_DEV，必填）。
	Register uint32
	// AddrRegister / Nfproto 是 `fwd ip to 1.2.3.4` 形态：地址寄存器 +
	// 该地址的 L3 族（NFPROTO_IPV4=2 / NFPROTO_IPV6=10）。
	AddrRegister uint32
	Nfproto      uint32
}

// nf_tables fwd 表达式的属性号（enum nft_fwd_attributes）。
const (
	NFTA_FWD_SREG_DEV  = 1
	NFTA_FWD_SREG_ADDR = 2
	NFTA_FWD_NFPROTO   = 3
)

func (e *Fwd) marshal(fam byte) ([]byte, error) {
	exprData, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("fwd\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (e *Fwd) marshalData(fam byte) ([]byte, error) {
	// 属性顺序照 nftables 的 netlink_gen_fwd_stmt：
	// SREG_DEV 恒发，地址形态再补 SREG_ADDR，最后是 NFPROTO（family 非空才发）。
	attrs := []netlink.Attribute{
		{Type: NFTA_FWD_SREG_DEV, Data: binaryutil.BigEndian.PutUint32(e.Register)},
	}
	if e.AddrRegister != 0 {
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_FWD_SREG_ADDR,
			Data: binaryutil.BigEndian.PutUint32(e.AddrRegister),
		})
		if e.Nfproto != 0 {
			attrs = append(attrs, netlink.Attribute{
				Type: NFTA_FWD_NFPROTO,
				Data: binaryutil.BigEndian.PutUint32(e.Nfproto),
			})
		}
	}
	return netlink.MarshalAttributes(attrs)
}

func (e *Fwd) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case NFTA_FWD_SREG_DEV:
			e.Register = ad.Uint32()
		case NFTA_FWD_SREG_ADDR:
			e.AddrRegister = ad.Uint32()
		case NFTA_FWD_NFPROTO:
			e.Nfproto = ad.Uint32()
		}
	}
	return ad.Err()
}
