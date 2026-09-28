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
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// 本文件锁定「对象映射」（object map）的 wire format。
//
// 对照物是 nft 1.1.7 在本机内核 7.2.6 上真实发出的报文（strace 抓取）：
//
//	nft add map ip objcap ports { type inet_service : counter ; }
//	  NFTA_SET_FLAGS(3)    = 0x40   <- NFT_SET_OBJECT（注意：没有 NFT_SET_MAP）
//	  NFTA_SET_KEY_TYPE(4) = 13     <- inet_service
//	  NFTA_SET_KEY_LEN(5)  = 2
//	  NFTA_SET_OBJ_TYPE(15)= 1      <- NFT_OBJECT_COUNTER
//	  没有 NFTA_SET_DATA_TYPE / NFTA_SET_DATA_LEN
//
//	nft add element ip objcap ports6 { 5160 : "voipq" }
//	  NFTA_SET_ELEM_KEY(1, nested) = 5160
//	  NFTA_SET_ELEM_OBJREF(9)      = "voipq"   <- NLA_STRING，替代 ELEM_DATA

// TestAddSetObjectMap 检查建表报文：只有 NFT_SET_OBJECT，没有 DATA_TYPE / DATA_LEN。
func TestAddSetObjectMap(t *testing.T) {
	t.Parallel()
	c := newTestConn(t)
	key, err := parseSetDatatype(13) // inet_service
	if err != nil {
		t.Fatal(err)
	}
	set := &Set{
		Name:    "ports",
		ID:      1,
		Table:   &Table{Name: "objcap", Family: TableFamilyIPv4},
		KeyType: key,
		IsMap:   true,
		ObjType: ObjTypeCounter,
	}
	if err := c.AddSet(set, nil); err != nil {
		t.Fatal(err)
	}
	msg := c.messages[len(c.messages)-1]

	ad, err := netlink.NewAttributeDecoder(msg.Data[4:]) // 跳过 nfgenmsg
	if err != nil {
		t.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	var (
		flags                            uint32
		objType                          uint32
		haveObjType, haveDataType, hasDL bool
	)
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_FLAGS:
			flags = ad.Uint32()
		case unix.NFTA_SET_OBJ_TYPE:
			haveObjType, objType = true, ad.Uint32()
		case unix.NFTA_SET_DATA_TYPE:
			haveDataType = true
		case unix.NFTA_SET_DATA_LEN:
			hasDL = true
		}
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}

	if flags&unix.NFT_SET_OBJECT == 0 {
		t.Errorf("flags = %#x, 缺少 NFT_SET_OBJECT", flags)
	}
	// nft 不置 NFT_SET_MAP：对象映射的语义由 NFT_SET_OBJECT 单独表达。
	if flags&unix.NFT_SET_MAP != 0 {
		t.Errorf("flags = %#x, 对象映射不应带 NFT_SET_MAP", flags)
	}
	if !haveObjType || objType != uint32(ObjTypeCounter) {
		t.Errorf("NFTA_SET_OBJ_TYPE = %d (present=%v), want %d", objType, haveObjType, ObjTypeCounter)
	}
	if haveDataType || hasDL {
		t.Errorf("对象映射不应发 DATA_TYPE/DATA_LEN (dataType=%v dataLen=%v)", haveDataType, hasDL)
	}

	// 回读侧要能还原 obj type，nft list 才能显示 type inet_service : counter。
	got, err := setsFromMsg(netlink.Message{Header: msg.Header, Data: msg.Data})
	if err != nil {
		t.Fatal(err)
	}
	if got.ObjType != ObjTypeCounter {
		t.Errorf("回读 ObjType = %d, want %d", got.ObjType, ObjTypeCounter)
	}
	if got.IsMap {
		t.Error("回读 IsMap 应为 false：对象映射不带 NFT_SET_MAP")
	}
}

// TestSetElementObjRef 检查元素报文：值槽位是 NFTA_SET_ELEM_OBJREF 而不是 ELEM_DATA。
func TestSetElementObjRef(t *testing.T) {
	t.Parallel()
	c := newTestConn(t)
	set := &Set{Table: &Table{Name: "objcap", Family: TableFamilyIPv4}, Name: "ports6", ObjType: ObjTypeQuota}
	// 5160 = 0x1428，与 nft 抓包中的 inet_service 键一致。
	raw, err := c.marshalSetElement(set, &SetElement{Key: []byte{20, 40}, ObjRef: "voipq"})
	if err != nil {
		t.Fatal(err)
	}

	ad, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		t.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	var objRef string
	var haveData bool
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_OBJREF:
			objRef = strings.TrimRight(string(ad.Bytes()), "\x00")
		case unix.NFTA_SET_ELEM_DATA:
			haveData = true
		}
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}
	if objRef != "voipq" {
		t.Errorf("NFTA_SET_ELEM_OBJREF = %q, want %q", objRef, "voipq")
	}
	if haveData {
		t.Error("对象映射元素不应带 NFTA_SET_ELEM_DATA")
	}

	// 回读必须还原出对象名与键。
	var el SetElement
	if err := el.decode(byte(TableFamilyIPv4))(raw); err != nil {
		t.Fatal(err)
	}
	if el.ObjRef != "voipq" {
		t.Errorf("回读 ObjRef = %q, want %q", el.ObjRef, "voipq")
	}
	if !bytes.Equal(el.Key, []byte{20, 40}) {
		t.Errorf("回读 Key = % x, want 14 28", el.Key)
	}
}
