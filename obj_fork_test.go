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
	"encoding/binary"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
)

// rawObjUserdata extracts the NFTA_OBJ_USERDATA attribute from a queued message.
func rawObjUserdata(t *testing.T, msg netlinkMessage) []byte {
	t.Helper()
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		t.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		if ad.Type() == nftaObjUserData {
			return ad.Bytes()
		}
	}
	return nil
}

// TestAddObjZeroValuesByteCompat pins that a NamedObj without UserData writes no
// NFTA_OBJ_USERDATA attribute, i.e. stays byte-for-byte identical to upstream.
func TestAddObjZeroValuesByteCompat(t *testing.T) {
	t.Parallel()
	c := newTestConn(t)
	c.AddObj(&NamedObj{
		Table: &Table{Name: "filter", Family: TableFamilyIPv4},
		Name:  "cnt_plain",
		Type:  ObjTypeCounter,
		Obj:   &expr.Counter{},
	})
	if ud := rawObjUserdata(t, c.messages[len(c.messages)-1]); ud != nil {
		t.Errorf("NamedObj without UserData wrote NFTA_OBJ_USERDATA (% x), want no attribute at all", ud)
	}
}

// TestAddObjUserDataRoundTrip covers both directions of the fork patch: AddObj
// must serialize the comment TLV, and objFromMsg must read it back (the upstream
// code returned early on NFTA_OBJ_DATA and dropped it).
func TestAddObjUserDataRoundTrip(t *testing.T) {
	t.Parallel()
	const want = "count both http and https packets"
	c := newTestConn(t)
	c.AddObj(&NamedObj{
		Table:    &Table{Name: "filter", Family: TableFamilyIPv4},
		Name:     "cnt_http",
		Type:     ObjTypeCounter,
		Obj:      &expr.Counter{Packets: 3, Bytes: 180},
		UserData: userdata.AppendString(nil, userdata.NFTNL_UDATA_OBJ_COMMENT, want),
	})
	msg := c.messages[len(c.messages)-1]

	if got, _ := userdata.GetString(rawObjUserdata(t, msg), userdata.NFTNL_UDATA_OBJ_COMMENT); got != want {
		t.Fatalf("write side: NFTA_OBJ_USERDATA comment = %q, want %q", got, want)
	}

	got, err := objFromMsg(netlink.Message{Header: msg.Header, Data: msg.Data}, false)
	if err != nil {
		t.Fatalf("objFromMsg: %v", err)
	}
	named, ok := got.(*NamedObj)
	if !ok {
		t.Fatalf("objFromMsg returned %T, want *NamedObj", got)
	}
	if named.Name != "cnt_http" || named.Type != ObjTypeCounter {
		t.Errorf("read side: got name=%q type=%v, want cnt_http/counter", named.Name, named.Type)
	}
	if comment, ok := userdata.GetString(named.UserData, userdata.NFTNL_UDATA_OBJ_COMMENT); !ok || comment != want {
		t.Errorf("read side: comment = %q (ok=%v), want %q", comment, ok, want)
	}
	cnt, ok := named.Obj.(*expr.Counter)
	if !ok {
		t.Fatalf("read side: Obj is %T, want *expr.Counter", named.Obj)
	}
	if cnt.Bytes != 180 || cnt.Packets != 3 {
		t.Errorf("read side: counter = %+v, want bytes=180 packets=3", cnt)
	}
}

// TestObjFromMsgLegacyStillWorks guards the collection-then-return refactor:
// the legacy typed path must still return CounterObj/QuotaObj.
func TestObjFromMsgLegacyStillWorks(t *testing.T) {
	t.Parallel()
	c := newTestConn(t)
	c.AddObj(&NamedObj{
		Table: &Table{Name: "filter", Family: TableFamilyIPv4},
		Name:  "cnt_legacy",
		Type:  ObjTypeCounter,
		Obj:   &expr.Counter{Bytes: 42},
	})
	msg := c.messages[len(c.messages)-1]

	got, err := objFromMsg(netlink.Message{Header: msg.Header, Data: msg.Data}, true)
	if err != nil {
		t.Fatalf("objFromMsg(legacy): %v", err)
	}
	if _, ok := got.(*CounterObj); !ok {
		t.Fatalf("legacy path returned %T, want *CounterObj", got)
	}
}
