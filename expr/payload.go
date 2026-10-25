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

type PayloadBase uint32
type PayloadCsumType uint32
type PayloadOperationType uint32

// Possible PayloadBase values.
const (
	PayloadBaseLLHeader        PayloadBase = unix.NFT_PAYLOAD_LL_HEADER
	PayloadBaseNetworkHeader   PayloadBase = unix.NFT_PAYLOAD_NETWORK_HEADER
	PayloadBaseTransportHeader PayloadBase = unix.NFT_PAYLOAD_TRANSPORT_HEADER
	// 下面两个是**隧道内层**的基址，只在 expr.Inner 包裹里用：
	//   PayloadBaseInnerHeader（3）= 内层任意头（nft 打印成 inner header）
	//   PayloadBaseTunHeader（4）  = 隧道头本身（nft 打印成 tunnel header）
	// 实测 `vxlan vni` 的内层载荷就是 `@ tunnel header + 4`。
	PayloadBaseInnerHeader PayloadBase = unix.NFT_PAYLOAD_INNER_HEADER
	PayloadBaseTunHeader   PayloadBase = unix.NFT_PAYLOAD_TUN_HEADER
)

// Possible PayloadCsumType values.
const (
	CsumTypeNone PayloadCsumType = unix.NFT_PAYLOAD_CSUM_NONE
	CsumTypeInet PayloadCsumType = unix.NFT_PAYLOAD_CSUM_INET
)

// Possible PayloadOperationType values.
const (
	PayloadLoad PayloadOperationType = iota
	PayloadWrite
)

type Payload struct {
	OperationType  PayloadOperationType
	DestRegister   uint32
	SourceRegister uint32
	Base           PayloadBase
	Offset         uint32
	Len            uint32
	CsumType       PayloadCsumType
	CsumOffset     uint32
	CsumFlags      uint32
}

func (e *Payload) marshal(fam byte) ([]byte, error) {
	data, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("payload\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Payload) marshalData(fam byte) ([]byte, error) {
	var attrs []netlink.Attribute

	if e.OperationType == PayloadWrite {
		attrs = []netlink.Attribute{
			{Type: unix.NFTA_PAYLOAD_SREG, Data: binaryutil.BigEndian.PutUint32(e.SourceRegister)},
		}
	} else {
		attrs = []netlink.Attribute{
			{Type: unix.NFTA_PAYLOAD_DREG, Data: binaryutil.BigEndian.PutUint32(e.DestRegister)},
		}
	}

	attrs = append(attrs,
		netlink.Attribute{Type: unix.NFTA_PAYLOAD_BASE, Data: binaryutil.BigEndian.PutUint32(uint32(e.Base))},
		netlink.Attribute{Type: unix.NFTA_PAYLOAD_OFFSET, Data: binaryutil.BigEndian.PutUint32(e.Offset)},
		netlink.Attribute{Type: unix.NFTA_PAYLOAD_LEN, Data: binaryutil.BigEndian.PutUint32(e.Len)},
	)

	// CsumFlags 不能嵌在 CsumType>0 里：nft 对 udp 写（sport/dport/checksum set）
	// 发的是 csum_type=0 + csum_flags=1（NFT_PAYLOAD_L4CSUM_PSEUDOHDR），嵌套会让
	// udp 改写丢掉校验和调整语义（实测内核 csum_flags 0x0 vs nft 0x1，2026-10-17）。
	if e.CsumType > 0 {
		attrs = append(attrs,
			netlink.Attribute{Type: unix.NFTA_PAYLOAD_CSUM_TYPE, Data: binaryutil.BigEndian.PutUint32(uint32(e.CsumType))},
			netlink.Attribute{Type: unix.NFTA_PAYLOAD_CSUM_OFFSET, Data: binaryutil.BigEndian.PutUint32(uint32(e.CsumOffset))},
		)
	}
	if e.CsumFlags > 0 {
		attrs = append(attrs,
			netlink.Attribute{Type: unix.NFTA_PAYLOAD_CSUM_FLAGS, Data: binaryutil.BigEndian.PutUint32(e.CsumFlags)},
		)
	}

	return netlink.MarshalAttributes(attrs)
}

func (e *Payload) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_PAYLOAD_DREG:
			e.DestRegister = ad.Uint32()
		case unix.NFTA_PAYLOAD_SREG:
			e.SourceRegister = ad.Uint32()
			e.OperationType = PayloadWrite
		case unix.NFTA_PAYLOAD_BASE:
			e.Base = PayloadBase(ad.Uint32())
		case unix.NFTA_PAYLOAD_OFFSET:
			e.Offset = ad.Uint32()
		case unix.NFTA_PAYLOAD_LEN:
			e.Len = ad.Uint32()
		case unix.NFTA_PAYLOAD_CSUM_TYPE:
			e.CsumType = PayloadCsumType(ad.Uint32())
		case unix.NFTA_PAYLOAD_CSUM_OFFSET:
			e.CsumOffset = ad.Uint32()
		case unix.NFTA_PAYLOAD_CSUM_FLAGS:
			e.CsumFlags = ad.Uint32()
		}
	}
	return ad.Err()
}
