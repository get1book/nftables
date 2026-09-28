// Tunnel（netdev 隧道元数据）表达式。上游 google/nftables 没有这个类型，
// 由本 fork 为 nfapi 补上。

package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TunnelKey 是 `tunnel <key>` 取哪个隧道字段（enum nft_tunnel_keys）。
type TunnelKey uint32

const (
	// TunnelKeyPath 对应 `tunnel path exists|missing`：datatype 是 boolean，
	// **1 字节主机序**（src/tunnel.c 的 tunnel_templates）。
	TunnelKeyPath TunnelKey = 0 // NFT_TUNNEL_PATH
	// TunnelKeyID 对应 `tunnel id <值>`：datatype 是 integer，
	// **4 字节主机序**（实测 `tunnel id 10` → `cmp eq 0x0000000a`）。
	TunnelKeyID TunnelKey = 1 // NFT_TUNNEL_ID
)

// nf_tables tunnel 表达式的属性号（enum nft_tunnel_attributes）：
// UNSPEC=0 / KEY=1 / DREG=2 / MODE=3。
// 系统包 golang.org/x/sys 未导出这几个，按内核 uapi 本地定义（与 OSF 同做法）。
const (
	NFTA_TUNNEL_KEY  = 1
	NFTA_TUNNEL_DREG = 2
	NFTA_TUNNEL_MODE = 3
)

// Tunnel 把隧道元数据取到寄存器，比较交给紧随的 cmp
// （与 ct / meta / osf 同构，本身不带取值）。
//
// 真机对照（nftables 1.1.7，`sudo nft -c --debug=netlink`）：
//
//	tunnel id 10        → [ tunnel load id => reg 1 ] + cmp eq 0x0000000a
//	tunnel path exists  → [ tunnel load path => reg 1 ] + cmp eq 0x01
//	tunnel path missing → [ tunnel load path => reg 1 ] + cmp eq 0x00
//
// 只在 netdev 族有意义；链类型没有特殊要求，普通
// `type filter hook ingress device X` 即可（tests/py/netdev/tunnel.t 就是这么写的）。
type Tunnel struct {
	// Register 是结果寄存器（NFTA_TUNNEL_DREG）。
	Register uint32
	// Key 是要取的隧道字段（NFTA_TUNNEL_KEY）。
	Key TunnelKey
}

func (e *Tunnel) marshal(fam byte) ([]byte, error) {
	exprData, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("tunnel\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (e *Tunnel) marshalData(fam byte) ([]byte, error) {
	// 顺序照 nftables src/netlink_linearize.c:344 —— DREG 先、KEY 后。
	//
	// MODE（NFTA_TUNNEL_MODE）只在 **tunnel 对象**上才设，表达式形态 nft 不发，
	// 这里也不发：多发一个 MODE=0 是否安全没有实测依据，宁缺勿猜。
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: NFTA_TUNNEL_DREG, Data: binaryutil.BigEndian.PutUint32(e.Register)},
		{Type: NFTA_TUNNEL_KEY, Data: binaryutil.BigEndian.PutUint32(uint32(e.Key))},
	})
}

func (e *Tunnel) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case NFTA_TUNNEL_DREG:
			e.Register = ad.Uint32()
		case NFTA_TUNNEL_KEY:
			e.Key = TunnelKey(ad.Uint32())
		}
	}
	return ad.Err()
}
