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

// OSF（passive OS fingerprint）表达式。上游 google/nftables 没有这个类型，
// 由本 fork 为 nfapi 补上。

package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// OSF 对应 `osf [ttl loose|skip] [name|version] "<值>"`：把指纹比对结果取到
// 寄存器，再由紧随的 cmp 完成比较（与 ct / meta 同构）。
//
// 真机对照（nftables 1.1.7）：
//
//	osf name "Linux"          → osf dreg 1 + cmp eq <16 字节 "Linux">
//	osf ttl loose name "Linux"→ 同上，但 TTL=1
//	osf version "2.6.x"       → 同上，但 FLAGS 带 NFT_OSF_F_VERSION
type OSF struct {
	// Register 是结果寄存器（NFTA_OSF_DREG）。
	Register uint32
	// TTL：0 = 不带（nft 语法里 osf_ttl 缺省为 NF_OSF_TTL_TRUE）、
	// 1 = `ttl loose`（NF_OSF_TTL_LESS）、2 = `ttl skip`（NF_OSF_TTL_NOCHECK）。
	TTL uint8
	// Flags：NFT_OSF_F_VERSION 置位表示 `version <值>`，否则是 `name <值>`。
	Flags uint32
}

// nf_tables osf 表达式的属性号（enum nft_osf_attributes）。
const (
	NFTA_OSF_DREG  = 1
	NFTA_OSF_TTL   = 2
	NFTA_OSF_FLAGS = 3
)

// NFT_OSF_F_VERSION：取值是版本号（`osf version "2.6.x"`）而不是名字。
const NFT_OSF_F_VERSION = 1

// OSF 的 ttl 取值（与 nft 的 osf_ttl_int_to_str 一一对应）。
const (
	// OSFTTLNone 是语法里省略 `ttl ...` 时的值（NF_OSF_TTL_TRUE）。
	OSFTTLNone uint8 = 0
	// OSFTTLLoose 对应 `osf ttl loose`（NF_OSF_TTL_LESS）。
	OSFTTLLoose uint8 = 1
	// OSFTTLSkip 对应 `osf ttl skip`（NF_OSF_TTL_NOCHECK）。
	OSFTTLSkip uint8 = 2
)

func (e *OSF) marshal(fam byte) ([]byte, error) {
	exprData, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("osf\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (e *OSF) marshalData(fam byte) ([]byte, error) {
	// 顺序照 nftables 的 netlink_gen_osf：DREG → TTL(u8) → FLAGS(u32)。
	//
	// 但**发不发** FLAGS 必须看值——strace 抓到 nft 的真实字节：
	//
	//	osf name "Linux"    → \x14\x00\x02\x80 [DREG=1][TTL=0]        共 20 字节
	//	osf version "2.6.x" → \x1c\x00\x02\x80 [DREG=1][TTL=0][FLAGS=1] 共 28 字节
	//
	// 即 nft 在 flags 为 0 时**根本不发**该属性。多发一个 FLAGS=0 会被内核
	// 拒绝（真机：NFT_MSG_NEWRULE: netlink receive: invalid argument）——
	// 内核看到 NFTA_OSF_FLAGS 就要求它带 NFT_OSF_F_VERSION。
	// TTL 则恒发（哪怕 0）。
	attrs := []netlink.Attribute{
		{Type: NFTA_OSF_DREG, Data: binaryutil.BigEndian.PutUint32(e.Register)},
		{Type: NFTA_OSF_TTL, Data: []byte{e.TTL}},
	}
	if e.Flags != 0 {
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_OSF_FLAGS,
			Data: binaryutil.BigEndian.PutUint32(e.Flags),
		})
	}
	return netlink.MarshalAttributes(attrs)
}

func (e *OSF) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case NFTA_OSF_DREG:
			e.Register = ad.Uint32()
		case NFTA_OSF_TTL:
			e.TTL = ad.Uint8()
		case NFTA_OSF_FLAGS:
			e.Flags = ad.Uint32()
		}
	}
	return ad.Err()
}
