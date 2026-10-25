// Copyright 2018 Google LLC. All Rights Reserved.
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

package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	// NFTA_TPROXY_FAMILY defines attribute for a table family
	NFTA_TPROXY_FAMILY = 0x01
	// NFTA_TPROXY_REG_ADDR defines attribute for a register carrying redirection address value
	NFTA_TPROXY_REG_ADDR = 0x02
	// NFTA_TPROXY_REG_PORT defines attribute for a register carrying redirection port value
	NFTA_TPROXY_REG_PORT = 0x03
)

// TProxy defines struct with parameters for the transparent proxy
type TProxy struct {
	Family      byte
	TableFamily byte
	RegAddr     uint32
	RegPort     uint32
}

func (e *TProxy) marshal(fam byte) ([]byte, error) {
	data, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("tproxy\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *TProxy) marshalData(fam byte) ([]byte, error) {
	attrs := []netlink.Attribute{
		{Type: NFTA_TPROXY_FAMILY, Data: binaryutil.BigEndian.PutUint32(uint32(e.Family))},
	}

	// REG_PORT 只在真有端口时发。上游无条件发（零值也发一条 REG_PORT=0），
	// 而寄存器 0 是 NFT_REG_VERDICT：内核 nft_parse_register_load 拒它，
	// `tproxy to 10.0.0.1`（只有地址）整条回 EINVAL（2026-10-23 实测）。
	// nft 自己的 netlink_gen_tproxy_stmt（nftables 1.1.7 src/netlink_linearize.c:1406）
	// 就是「有 port 才置 REG_PORT」，这里对齐。REG_ADDR 上游已有同款条件。
	if e.RegPort != 0 {
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_TPROXY_REG_PORT,
			Data: binaryutil.BigEndian.PutUint32(e.RegPort),
		})
	}

	if e.RegAddr != 0 {
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_TPROXY_REG_ADDR,
			Data: binaryutil.BigEndian.PutUint32(e.RegAddr),
		})
	}

	return netlink.MarshalAttributes(attrs)
}

func (e *TProxy) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case NFTA_TPROXY_FAMILY:
			// 内核这个属性是 u32（NLA_U32），读成 Uint8 会直接报
			// "attribute 1 is not a uint8; length: 4"，整条链回读失败。
			e.Family = byte(ad.Uint32())
		case NFTA_TPROXY_REG_PORT:
			e.RegPort = ad.Uint32()
		case NFTA_TPROXY_REG_ADDR:
			e.RegAddr = ad.Uint32()
		}
	}
	return ad.Err()
}
