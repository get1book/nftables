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

package nftables

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// keyTypeofIPSaddr is a real KEY_TYPEOF payload for `typeof ip saddr`, captured
// from nft 1.1.7: EXPR_PAYLOAD=7, PAYLOAD_DESC=0x0c, PAYLOAD_TYPE=0x0b.
var keyTypeofIPSaddr = []byte{
	0x00, 0x04, 0x07, 0x00, 0x00, 0x00, // TYPEOF_EXPR = EXPR_PAYLOAD (7)
	0x01, 0x0c, // TYPEOF_DATA (nested), len 12
	0x00, 0x04, 0x0c, 0x00, 0x00, 0x00, // PAYLOAD_DESC = 12
	0x01, 0x04, 0x0b, 0x00, 0x00, 0x00, // PAYLOAD_TYPE = 11
}

// rawUserdata extracts the NFTA_SET_USERDATA attribute from a queued message.
func rawUserdata(t *testing.T, msg netlinkMessage) []byte {
	t.Helper()
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		t.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		if ad.Type() == unix.NFTA_SET_USERDATA {
			return ad.Bytes()
		}
	}
	return nil // no userdata attribute at all
}

func newTestConn(t *testing.T) *Conn {
	t.Helper()
	c, err := New(WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) { return req, nil }))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestAddSetZeroValuesByteCompat ensures the new fork fields default to writing
// no extra TLVs, i.e. behaviour stays byte-for-byte identical to upstream.
func TestAddSetZeroValuesByteCompat(t *testing.T) {
	t.Parallel()
	c := newTestConn(t)
	set := &Set{
		Name:    "plain",
		ID:      1,
		Table:   &Table{Name: "t", Family: TableFamilyIPv4},
		KeyType: TypeIPAddr,
	}
	if err := c.AddSet(set, nil); err != nil {
		t.Fatal(err)
	}
	ud := rawUserdata(t, c.messages[len(c.messages)-1])
	if ud != nil {
		t.Errorf("zero-value Set wrote NFTA_SET_USERDATA (% x), want no attribute at all", ud)
	}
	for _, typ := range []userdata.Type{
		userdata.NFTNL_UDATA_SET_KEYBYTEORDER,
		userdata.NFTNL_UDATA_SET_DATABYTEORDER,
		userdata.NFTNL_UDATA_SET_KEY_TYPEOF,
	} {
		if v := userdata.Get(ud, typ); v != nil {
			t.Errorf("zero-value Set wrote udata type %d (% x), want none", typ, v)
		}
	}
}

// TestAddSetKeyTypeofAndDataByteOrder checks KEY_TYPEOF passthrough plus the
// value-side DATABYTEORDER TLV.
func TestAddSetKeyTypeofAndDataByteOrder(t *testing.T) {
	t.Parallel()
	c := newTestConn(t)
	set := &Set{
		Name:                 "stype",
		ID:                   1,
		Table:                &Table{Name: "t", Family: TableFamilyIPv4},
		KeyType:              TypeIPAddr,
		IsMap:                true,
		DataType:             TypeIFName,
		DataByteOrder:        binaryutil.NativeEndian,
		KeyTypeofExpr:        keyTypeofIPSaddr,
		KeyByteOrderExplicit: true,
	}
	if err := c.AddSet(set, nil); err != nil {
		t.Fatal(err)
	}
	ud := rawUserdata(t, c.messages[len(c.messages)-1])

	if got := userdata.Get(ud, userdata.NFTNL_UDATA_SET_KEY_TYPEOF); !bytes.Equal(got, keyTypeofIPSaddr) {
		t.Errorf("KEY_TYPEOF = % x, want % x", got, keyTypeofIPSaddr)
	}
	if v, ok := userdata.GetUint32(ud, userdata.NFTNL_UDATA_SET_DATABYTEORDER); !ok || v != 1 {
		t.Errorf("DATABYTEORDER = %d (ok=%v), want 1", v, ok)
	}
	// ipv4_addr is network order -> 2.
	if v, ok := userdata.GetUint32(ud, userdata.NFTNL_UDATA_SET_KEYBYTEORDER); !ok || v != 2 {
		t.Errorf("KEYBYTEORDER = %d (ok=%v), want 2", v, ok)
	}

	// Read side must recover the same values.
	nset, err := setsFromMsg(netlink.Message{Header: c.messages[len(c.messages)-1].Header, Data: c.messages[len(c.messages)-1].Data})
	if err != nil {
		t.Fatalf("setsFromMsg: %v", err)
	}
	if !bytes.Equal(nset.KeyTypeofExpr, keyTypeofIPSaddr) {
		t.Errorf("round-trip KeyTypeofExpr = % x, want % x", nset.KeyTypeofExpr, keyTypeofIPSaddr)
	}
	if nset.DataByteOrder != binaryutil.NativeEndian {
		t.Errorf("round-trip DataByteOrder = %v, want NativeEndian", nset.DataByteOrder)
	}
	if nset.KeyByteOrder != binaryutil.BigEndian {
		t.Errorf("round-trip KeyByteOrder = %v, want BigEndian", nset.KeyByteOrder)
	}
}

// TestAddSetKeyByteOrderExplicit pins the datatype-derived KEYBYTEORDER values:
// concat -> 0, host order -> 1, network order -> 2 (no Anonymous/Constant/Interval
// special case).
func TestAddSetKeyByteOrderExplicit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		set  Set
		want uint32
	}{
		{
			name: "host order (mark) -> 1",
			set: Set{
				Name: "smark", ID: 1,
				Table:                &Table{Name: "t", Family: TableFamilyIPv4},
				KeyType:              TypeMark,
				KeyByteOrder:         binaryutil.NativeEndian,
				KeyByteOrderExplicit: true,
				Constant:             true, // must NOT force 2 when explicit
			},
			want: 1,
		},
		{
			name: "network order (ipv4) -> 2",
			set: Set{
				Name: "sip", ID: 2,
				Table:   &Table{Name: "t", Family: TableFamilyIPv4},
				KeyType: TypeIPAddr, KeyByteOrderExplicit: true,
			},
			want: 2,
		},
		{
			name: "concat -> 0",
			set: Set{
				Name: "scat", ID: 3,
				Table:                &Table{Name: "t", Family: TableFamilyIPv4},
				KeyType:              MustConcatSetType(TypeIPAddr, TypeInetService),
				Concatenation:        true,
				KeyByteOrderExplicit: true,
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestConn(t)
			if err := c.AddSet(&tt.set, nil); err != nil {
				t.Fatal(err)
			}
			ud := rawUserdata(t, c.messages[len(c.messages)-1])
			if v, ok := userdata.GetUint32(ud, userdata.NFTNL_UDATA_SET_KEYBYTEORDER); !ok || v != tt.want {
				t.Errorf("KEYBYTEORDER = %d (ok=%v), want %d", v, ok, tt.want)
			}
		})
	}
}

// TestAddSetKeyTypeofTooLarge ensures oversized payloads fail loudly instead of
// silently truncating the single-byte udata length.
func TestAddSetKeyTypeofTooLarge(t *testing.T) {
	t.Parallel()
	c := newTestConn(t)
	set := &Set{
		Name:          "big",
		ID:            1,
		Table:         &Table{Name: "t", Family: TableFamilyIPv4},
		KeyType:       TypeIPAddr,
		KeyTypeofExpr: make([]byte, 256),
	}
	if err := c.AddSet(set, nil); err == nil {
		t.Fatal("AddSet() with 256-byte KeyTypeofExpr: got nil error, want error")
	}
}
