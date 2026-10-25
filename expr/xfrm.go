package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// NFTA_XFRM_*（内核 uapi nf_tables.h:1798-1802；x/sys/unix 未收录，就地定义）。
const (
	nftaXfrmDreg  = 1
	nftaXfrmKey   = 2
	nftaXfrmDir   = 3
	nftaXfrmSpnum = 4
)

// Xfrm 是 ipsec 状态匹配表达式（`ipsec in reqid 1`）。
// Key 取 enum nft_xfrm_keys：reqid=5、spi=6。reqid 是 HE 模板（主机序）、
// spi 是 BE 模板（大端）——nft src/xfrm.c:44-45 XFRM_TEMPLATE_HE/BE，实测
// cmp 字节：reqid 1 → 01 00 00 00、spi 0x100 → 00 00 01 00。
type Xfrm struct {
	Dreg  uint32
	Key   uint32
	Dir   uint8 // 0=in 1=out
	Spnum uint32
}

func (e *Xfrm) marshal(fam byte) ([]byte, error) {
	data, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("xfrm\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Xfrm) marshalData(fam byte) ([]byte, error) {
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nftaXfrmDreg, Data: binaryutil.BigEndian.PutUint32(e.Dreg)},
		{Type: nftaXfrmKey, Data: binaryutil.BigEndian.PutUint32(e.Key)},
		{Type: nftaXfrmDir, Data: []byte{e.Dir}},
		{Type: nftaXfrmSpnum, Data: binaryutil.BigEndian.PutUint32(e.Spnum)},
	})
}

func (e *Xfrm) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case nftaXfrmDreg:
			e.Dreg = ad.Uint32()
		case nftaXfrmKey:
			e.Key = ad.Uint32()
		case nftaXfrmDir:
			e.Dir = ad.Uint8()
		case nftaXfrmSpnum:
			e.Spnum = ad.Uint32()
		}
	}
	return ad.Err()
}
