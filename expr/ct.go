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

// CtKey specifies which piece of conntrack information should be loaded. See
// also https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation
type CtKey uint32

// Possible CtKey values.
// Retrieved from https://git.netfilter.org/libnftnl/tree/include/linux/netfilter/nf_tables.h#n1121
const (
	CtKeySTATE      CtKey = unix.NFT_CT_STATE
	CtKeyDIRECTION  CtKey = unix.NFT_CT_DIRECTION
	CtKeySTATUS     CtKey = unix.NFT_CT_STATUS
	CtKeyMARK       CtKey = unix.NFT_CT_MARK
	CtKeySECMARK    CtKey = unix.NFT_CT_SECMARK
	CtKeyEXPIRATION CtKey = unix.NFT_CT_EXPIRATION
	CtKeyHELPER     CtKey = unix.NFT_CT_HELPER
	CtKeyL3PROTOCOL CtKey = unix.NFT_CT_L3PROTOCOL
	CtKeySRC        CtKey = unix.NFT_CT_SRC
	CtKeyDST        CtKey = unix.NFT_CT_DST
	CtKeyPROTOCOL   CtKey = unix.NFT_CT_PROTOCOL
	CtKeyPROTOSRC   CtKey = unix.NFT_CT_PROTO_SRC
	CtKeyPROTODST   CtKey = unix.NFT_CT_PROTO_DST
	CtKeyLABELS     CtKey = unix.NFT_CT_LABELS
	CtKeyPKTS       CtKey = unix.NFT_CT_PKTS
	CtKeyBYTES      CtKey = unix.NFT_CT_BYTES
	CtKeyAVGPKT     CtKey = unix.NFT_CT_AVGPKT
	CtKeyZONE       CtKey = unix.NFT_CT_ZONE
	CtKeyEVENTMASK  CtKey = unix.NFT_CT_EVENTMASK

	// These values seem to be missing from the unix package
	CtKeySRCIP  CtKey = 19
	CtKeyDSTIP  CtKey = 20
	CtKeySRCIP6 CtKey = 21
	CtKeyDSTIP6 CtKey = 22
	CtKeyID     CtKey = 23

	// https://sources.debian.org/src//nftables/0.9.8-3/src/ct.c/?hl=39#L39
	CtStateBitINVALID     uint32 = 1
	CtStateBitESTABLISHED uint32 = 2
	CtStateBitRELATED     uint32 = 4
	CtStateBitNEW         uint32 = 8
	CtStateBitUNTRACKED   uint32 = 64
)

// Missing ct timeout consts
// https://git.netfilter.org/libnftnl/tree/include/linux/netfilter/nf_tables.h?id=be0bae0ad31b0adb506f96de083f52a2bd0d4fbf#n1592
const (
	NFTA_CT_TIMEOUT_L3PROTO = 0x01
	NFTA_CT_TIMEOUT_L4PROTO = 0x02
	NFTA_CT_TIMEOUT_DATA    = 0x03
)

type CtStatePolicyTimeout map[uint16]uint32

const (
	// https://git.netfilter.org/libnftnl/tree/src/obj/ct_timeout.c?id=116e95aa7b6358c917de8c69f6f173874030b46b#n24
	CtStateTCPSYNSENT = iota
	CtStateTCPSYNRECV
	CtStateTCPESTABLISHED
	CtStateTCPFINWAIT
	CtStateTCPCLOSEWAIT
	CtStateTCPLASTACK
	CtStateTCPTIMEWAIT
	CtStateTCPCLOSE
	CtStateTCPSYNSENT2
	CtStateTCPRETRANS
	CtStateTCPUNACK
)

// https://git.netfilter.org/libnftnl/tree/src/obj/ct_timeout.c?id=116e95aa7b6358c917de8c69f6f173874030b46b#n38
//
// 这张表是「读回时拿来跟内核值比、相同就不显示」的基准，所以必须等于内核建对象时
// 实际填进去的默认值，否则界面上会冒出一堆用户没设过的项。两个值实测校正过
// （内核 7.2.6：nft add ct timeout ip T x { protocol tcp; } 之后 nft list 显示
// policy = { }，而内核回读给的 established 是 432000 = sysctl 的 5 天）：
// established 43200→432000、udp replied 180→120。
var CtStateTCPTimeoutDefaults CtStatePolicyTimeout = map[uint16]uint32{
	CtStateTCPSYNSENT:     120,
	CtStateTCPSYNRECV:     60,
	CtStateTCPESTABLISHED: 432000,
	CtStateTCPFINWAIT:     120,
	CtStateTCPCLOSEWAIT:   60,
	CtStateTCPLASTACK:     30,
	CtStateTCPTIMEWAIT:    120,
	CtStateTCPCLOSE:       10,
	CtStateTCPSYNSENT2:    120,
	CtStateTCPRETRANS:     300,
	CtStateTCPUNACK:       300,
}

const (
	// https://git.netfilter.org/libnftnl/tree/src/obj/ct_timeout.c?id=116e95aa7b6358c917de8c69f6f173874030b46b#n57
	CtStateUDPUNREPLIED = iota
	CtStateUDPREPLIED
)

const (
	// https://git.netfilter.org/libnftnl/tree/src/expr/ct.c?id=116e95aa7b6358c917de8c69f6f173874030b46b#n31
	CtDirOriginal = iota
	CtDirReply
)

// https://git.netfilter.org/libnftnl/tree/src/obj/ct_timeout.c?id=116e95aa7b6358c917de8c69f6f173874030b46b#n57
var CtStateUDPTimeoutDefaults CtStatePolicyTimeout = map[uint16]uint32{
	CtStateUDPUNREPLIED: 30,
	// 180 是 libnftnl 源码里的值，但内核填的是 sysctl 的
	// nf_conntrack_udp_timeout_stream = 120（实测：新建的 udp ct timeout 里就是 120）。
	CtStateUDPREPLIED: 120,
}

// Ct defines type for NFT connection tracking
type Ct struct {
	Register       uint32
	SourceRegister bool
	Key            CtKey
	Direction      uint32
	OptDirection   bool
}

func (e *Ct) marshal(fam byte) ([]byte, error) {
	exprData, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("ct\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (e *Ct) marshalData(fam byte) ([]byte, error) {
	var regData []byte
	exprData, err := netlink.MarshalAttributes(
		[]netlink.Attribute{
			{Type: unix.NFTA_CT_KEY, Data: binaryutil.BigEndian.PutUint32(uint32(e.Key))},
		},
	)
	if err != nil {
		return nil, err
	}
	if e.SourceRegister {
		regData, err = netlink.MarshalAttributes(
			[]netlink.Attribute{
				{Type: unix.NFTA_CT_SREG, Data: binaryutil.BigEndian.PutUint32(e.Register)},
			},
		)
	} else {
		regData, err = netlink.MarshalAttributes(
			[]netlink.Attribute{
				{Type: unix.NFTA_CT_DREG, Data: binaryutil.BigEndian.PutUint32(e.Register)},
			},
		)
	}
	if err != nil {
		return nil, err
	}
	exprData = append(exprData, regData...)

	switch e.Key {
	case CtKeyPKTS, CtKeyBYTES, CtKeyAVGPKT, CtKeyL3PROTOCOL, CtKeyPROTOCOL:
		if !e.OptDirection {
			break
		}

		fallthrough
	case CtKeySRC, CtKeyDST, CtKeyPROTOSRC, CtKeyPROTODST, CtKeySRCIP, CtKeyDSTIP, CtKeySRCIP6, CtKeyDSTIP6:
		regData, err = netlink.MarshalAttributes(
			[]netlink.Attribute{
				{Type: unix.NFTA_CT_DIRECTION, Data: []byte{uint8(e.Direction)}},
			},
		)
		if err != nil {
			return nil, err
		}
		exprData = append(exprData, regData...)
	}

	return exprData, nil
}

func (e *Ct) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian

	var hasDirection bool
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_CT_KEY:
			e.Key = CtKey(ad.Uint32())
		case unix.NFTA_CT_DREG:
			e.Register = ad.Uint32()
		case unix.NFTA_CT_DIRECTION:
			e.Direction = uint32(ad.Uint8())
			hasDirection = true
		case unix.NFTA_CT_SREG:
			e.SourceRegister = true
			e.Register = ad.Uint32()
		}
	}

	switch e.Key {
	case CtKeyPKTS, CtKeyBYTES, CtKeyAVGPKT, CtKeyL3PROTOCOL, CtKeyPROTOCOL:
		e.OptDirection = hasDirection
	}

	return ad.Err()
}

type CtHelper struct {
	Name    string
	L3Proto uint16
	L4Proto uint8
}

func (c *CtHelper) marshal(fam byte) ([]byte, error) {
	exprData, err := c.marshalData(fam)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("cthelper\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (c *CtHelper) marshalData(fam byte) ([]byte, error) {
	exprData := []netlink.Attribute{
		{Type: unix.NFTA_CT_HELPER_NAME, Data: []byte(c.Name)},
	}

	if c.L3Proto != 0 {
		exprData = append(exprData, netlink.Attribute{
			Type: unix.NFTA_CT_HELPER_L3PROTO, Data: binaryutil.BigEndian.PutUint16(c.L3Proto),
		})
	}
	if c.L4Proto != 0 {
		exprData = append(exprData, netlink.Attribute{
			Type: unix.NFTA_CT_HELPER_L4PROTO, Data: []byte{c.L4Proto},
		})
	}

	return netlink.MarshalAttributes(exprData)
}

func (c *CtHelper) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_CT_HELPER_NAME:
			c.Name = ad.String()
		case unix.NFTA_CT_HELPER_L3PROTO:
			c.L3Proto = ad.Uint16()
		case unix.NFTA_CT_HELPER_L4PROTO:
			c.L4Proto = ad.Uint8()
		}
	}
	return ad.Err()
}

// From https://git.netfilter.org/libnftnl/tree/include/linux/netfilter/nf_tables.h?id=be0bae0ad31b0adb506f96de083f52a2bd0d4fbf#n1601
// Currently not available in sys/unix
const (
	NFTA_CT_EXPECT_L3PROTO = 0x01
	NFTA_CT_EXPECT_L4PROTO = 0x02
	NFTA_CT_EXPECT_DPORT   = 0x03
	NFTA_CT_EXPECT_TIMEOUT = 0x04
	NFTA_CT_EXPECT_SIZE    = 0x05
)

type CtExpect struct {
	L3Proto uint16
	L4Proto uint8
	DPort   uint16
	Timeout uint32
	Size    uint8
}

func (c *CtExpect) marshal(fam byte) ([]byte, error) {
	exprData, err := c.marshalData(fam)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("ctexpect\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (c *CtExpect) marshalData(fam byte) ([]byte, error) {
	// all elements except l3proto must be defined
	// per https://git.netfilter.org/nftables/tree/doc/stateful-objects.txt?id=db70959a5ccf2952b218f51c3d529e186a5a43bb#n119
	// from man page: l3proto is derived from the table family by default
	exprData := []netlink.Attribute{
		{Type: NFTA_CT_EXPECT_L4PROTO, Data: []byte{c.L4Proto}},
		{Type: NFTA_CT_EXPECT_DPORT, Data: binaryutil.BigEndian.PutUint16(c.DPort)},
		// timeout 是本机字节序，别照抄上面那行的 BigEndian：实测 nft 下发
		// `add ct expectation … timeout 1m` 的属性体是 60 ea 00 00（= 60000 的本机序）。
		// 用 BigEndian 不会报错，只会让内核存下一个 0x60EA0000 毫秒（约 18 天）的超时。
		{Type: NFTA_CT_EXPECT_TIMEOUT, Data: binaryutil.NativeEndian.PutUint32(c.Timeout)},
		{Type: NFTA_CT_EXPECT_SIZE, Data: []byte{c.Size}},
	}

	if c.L3Proto != 0 {
		attr := netlink.Attribute{Type: NFTA_CT_EXPECT_L3PROTO, Data: binaryutil.BigEndian.PutUint16(c.L3Proto)}
		exprData = append(exprData, attr)
	}
	return netlink.MarshalAttributes(exprData)
}

func (c *CtExpect) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case NFTA_CT_EXPECT_L3PROTO:
			c.L3Proto = ad.Uint16()
		case NFTA_CT_EXPECT_L4PROTO:
			c.L4Proto = ad.Uint8()
		case NFTA_CT_EXPECT_DPORT:
			c.DPort = ad.Uint16()
		case NFTA_CT_EXPECT_TIMEOUT:
			// 见 marshalData：这一块的整数字段里只有 timeout 是本机序。
			ad.ByteOrder = binary.NativeEndian
			c.Timeout = ad.Uint32()
			ad.ByteOrder = binary.BigEndian
		case NFTA_CT_EXPECT_SIZE:
			c.Size = ad.Uint8()
		}
	}
	return ad.Err()
}

type CtTimeout struct {
	L3Proto uint16
	L4Proto uint8
	Policy  CtStatePolicyTimeout
}

func (c *CtTimeout) marshal(fam byte) ([]byte, error) {
	exprData, err := c.marshalData(fam)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("cttimeout\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

// policyOrDefault 返回「该 l4proto 的默认策略 + c.Policy 覆盖」的新 map。
//
// 必须复制：CtState*TimeoutDefaults 是包级共享的 map，直接把它赋给局部变量再写入
// 会永久污染默认值——同一进程里此后创建的每个 ct timeout 对象都会带上这一次的值。
func (c *CtTimeout) policyOrDefault() CtStatePolicyTimeout {
	defaults := CtStateTCPTimeoutDefaults
	if c.L4Proto == unix.IPPROTO_UDP {
		defaults = CtStateUDPTimeoutDefaults
	}
	policy := make(CtStatePolicyTimeout, len(defaults)+len(c.Policy))
	for k, v := range defaults {
		policy[k] = v
	}
	for k, v := range c.Policy {
		policy[k] = v
	}
	return policy
}

func (c *CtTimeout) marshalData(fam byte) ([]byte, error) {
	// 只发调用方显式指定的状态：没发的那几项由内核按**建对象当时的 sysctl 默认值**填满
	// （实测：空 policy 建出来的对象 established = 432000 = nf_conntrack_tcp_timeout_established），
	// nft 也是这么发的（policy = { close_wait: 7 } 就只发这一项）。
	//
	// 这里早先是把 CtState*TimeoutDefaults 整表发下去，等于把 established 从系统的
	// 5 天静默改成常量表里的 12h——「只填要改的状态，其余沿用内核默认」就成了假话。
	policy := c.Policy

	var policyAttrs []netlink.Attribute
	for k, v := range policy {
		policyAttrs = append(policyAttrs, netlink.Attribute{Type: k + 1, Data: binaryutil.BigEndian.PutUint32(v)})
	}
	policyData, err := netlink.MarshalAttributes(policyAttrs)
	if err != nil {
		return nil, err
	}

	exprData := []netlink.Attribute{
		{Type: NFTA_CT_TIMEOUT_L3PROTO, Data: binaryutil.BigEndian.PutUint16(c.L3Proto)},
		{Type: NFTA_CT_TIMEOUT_L4PROTO, Data: []byte{c.L4Proto}},
		{Type: unix.NLA_F_NESTED | NFTA_CT_TIMEOUT_DATA, Data: policyData},
	}

	return netlink.MarshalAttributes(exprData)
}

func (c *CtTimeout) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case NFTA_CT_TIMEOUT_L3PROTO:
			c.L3Proto = ad.Uint16()
		case NFTA_CT_TIMEOUT_L4PROTO:
			c.L4Proto = ad.Uint8()
		case NFTA_CT_TIMEOUT_DATA:
			decoder, err := netlink.NewAttributeDecoder(ad.Bytes())
			decoder.ByteOrder = binary.BigEndian
			if err != nil {
				return err
			}
			// 先按默认策略铺一份，再用内核回读的值覆盖（policyOrDefault 会复制，
			// 不会写到包级默认表上）。
			c.Policy = c.policyOrDefault()
			for decoder.Next() {
				c.Policy[decoder.Type()-1] = decoder.Uint32()
			}
		}
	}
	return ad.Err()
}
