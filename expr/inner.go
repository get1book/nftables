// Inner（隧道内层载荷）表达式。上游 google/nftables 没有这个类型，
// 由本 fork 为 nfapi 补上。

package expr

import (
	"encoding/binary"
	"errors"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/internal/parseexprfunc"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// errInnerNoExpr：inner 必须包裹一个内层表达式，缺了内核会回 EINVAL，
// 与其发一条注定被拒的消息，不如在序列化阶段就报错。
var errInnerNoExpr = errors.New("expr: Inner 缺少被包裹的内层表达式")

// Inner 的隧道类型（enum nft_inner_type）。
//
// ⚠️ 内核 uapi 只显式定义了 VXLAN / GENEVE 两个，gre/gretap 是
// nftables src/proto.c 用 `NFT_INNER_GENEVE + 1` / `+ 2` 推出的：
//
//	proto_gre    → .type = NFT_INNER_GENEVE + 1   (= 3)
//	proto_gretap → .type = NFT_INNER_GENEVE + 2   (= 4)
const (
	InnerVXLAN  uint32 = 1 // NFT_INNER_VXLAN
	InnerGENEVE uint32 = 2 // NFT_INNER_GENEVE
	InnerGRE    uint32 = 3 // NFT_INNER_GENEVE + 1
	InnerGRETAP uint32 = 4 // NFT_INNER_GENEVE + 2
)

// Inner 的标志位（enum nft_inner_flags）：说明内层有哪些头可用。
//
// 实测各隧道头的组合：
//
//	vxlan  → HDRSIZE|LL|NH|TH = 0xf
//	geneve → HDRSIZE|LL|NH|TH = 0xf
//	gre    → NH|TH            = 0xc
//	gretap → LL|NH|TH         = 0xe
const (
	InnerHdrsize uint32 = 1 << 0 // NFT_INNER_HDRSIZE
	InnerLL      uint32 = 1 << 1 // NFT_INNER_LL
	InnerNH      uint32 = 1 << 2 // NFT_INNER_NH
	InnerTH      uint32 = 1 << 3 // NFT_INNER_TH
)

// nf_tables inner 表达式的属性号（enum nft_inner_attributes）：
// UNSPEC=0 / NUM=1 / TYPE=2 / FLAGS=3 / HDRSIZE=4 / EXPR=5。
// 系统包 golang.org/x/sys 未导出这几个，按内核 uapi 本地定义（与 OSF/Tunnel 同做法）。
const (
	// NFTA_INNER_NUM 是**内层表达式个数**。内核 nft_inner_init 会
	// `ntohl(nla_get_be32(tb[NFTA_INNER_NUM]))` 直接取用，缺了它取到空指针、
	// 规则必被拒（实测：漏发 NUM 时内核回 NEWRULE EINVAL）。
	// nftables 的 netlink_gen_inner 没显式设它（由 libnftnl 补齐），
	// 我们直接发内核要的属性，所以必须显式带上。
	NFTA_INNER_NUM     = 1
	NFTA_INNER_TYPE    = 2
	NFTA_INNER_FLAGS   = 3
	NFTA_INNER_HDRSIZE = 4
	NFTA_INNER_EXPR    = 5
)

// innerNumExprs 是 NFTA_INNER_NUM 的取值。
//
// ⚠️ 实测（strace 抓 nft 1.1.7 发出的字节）是 **0** 而不是 1：
//
//	inner\0 [NUM=0][TYPE=1][FLAGS=15][HDRSIZE=8][EXPR=[payload base=4 off=4 len=3]]
//
// 它是「内层表达式在数组里的起始下标」（从 0 起），不是个数。
// 发成 1 内核会回 EOPNOTSUPP（真机复现）。
const innerNumExprs = 0

// Inner 把一个**内层**表达式包进隧道头上下文里。
//
// 内核形态（实测 nftables 1.1.7 `sudo nft -c --debug=netlink`）：
//
//	[ inner type 1 hdrsize 8 flags f [ payload load 3b @ tunnel header + 4 => reg 1 ] ]
//
// 即 inner 自身只带 type/flags/hdrsize，真正的取数在它包裹的
// **单个** Expr 里（实测只会是 payload 或 meta 两种，见
// nftables src/netlink_linearize.c:211 netlink_gen_inner_expr 的 switch）。
//
// ⚠️ 内层表达式用 tunnel/inner 两种 base：
// Expr 里若用 PayloadBaseTunHeader，说明取的是隧道头字段（如 vxlan vni @ +4）；
// 用 PayloadBaseNetworkHeader/TransportHeader 则是内层报文（如 `vxlan ip saddr`）。
type Inner struct {
	// Type 是隧道类型（见 InnerVXLAN 等）。
	Type uint32
	// Flags 是 InnerHdrsize|InnerLL|InnerNH|InnerTH 的位或。
	Flags uint32
	// Hdrsize 是隧道头的字节长度（vxlan/geneve=8，gre/gretap=4）。
	Hdrsize uint32
	// Expr 是被包裹的内层表达式（payload / meta）。
	Expr Any
}

func (e *Inner) marshal(fam byte) ([]byte, error) {
	exprData, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("inner\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (e *Inner) marshalData(fam byte) ([]byte, error) {
	if e.Expr == nil {
		return nil, errInnerNoExpr
	}
	// 先序列化内层表达式（完整的 expr 属性对：NAME + DATA）。
	innerBytes, err := Marshal(fam, e.Expr)
	if err != nil {
		return nil, err
	}
	// 顺序与取值照 strace 抓到的 nft 真实字节：
	//   NUM(0) → TYPE → FLAGS → HDRSIZE → EXPR(嵌套)
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: NFTA_INNER_NUM, Data: binaryutil.BigEndian.PutUint32(innerNumExprs)},
		{Type: NFTA_INNER_TYPE, Data: binaryutil.BigEndian.PutUint32(e.Type)},
		{Type: NFTA_INNER_FLAGS, Data: binaryutil.BigEndian.PutUint32(e.Flags)},
		{Type: NFTA_INNER_HDRSIZE, Data: binaryutil.BigEndian.PutUint32(e.Hdrsize)},
		{Type: unix.NLA_F_NESTED | NFTA_INNER_EXPR, Data: innerBytes},
	})
}

func (e *Inner) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case NFTA_INNER_TYPE:
			e.Type = ad.Uint32()
		case NFTA_INNER_FLAGS:
			e.Flags = ad.Uint32()
		case NFTA_INNER_HDRSIZE:
			e.Hdrsize = ad.Uint32()
		case NFTA_INNER_EXPR:
			// 内层是**单个**表达式（nft 的 netlink_gen_inner_expr 只处理
			// payload 与 meta 两种）。取第一个即可。
			exprs, err := parseexprfunc.ParseExprBytesFunc(fam, ad)
			if err != nil {
				return err
			}
			if len(exprs) > 0 {
				if a, ok := exprs[0].(Any); ok {
					e.Expr = a
				}
			}
		}
	}
	return ad.Err()
}
