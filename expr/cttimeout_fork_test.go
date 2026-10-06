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
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TestCtTimeoutDoesNotMutateDefaults pins the fork fix: policyOrDefault must COPY
// CtStateTCPTimeoutDefaults / CtStateUDPTimeoutDefaults. Both marshalData and
// unmarshal used to alias the package-level map and then write into it, so one
// object with a custom policy permanently changed the defaults for every later
// object in the same process.
func TestCtTimeoutDoesNotMutateDefaults(t *testing.T) {
	const wantEstablished = uint32(432000)
	const wantCloseWait = uint32(60)
	if got := CtStateTCPTimeoutDefaults[CtStateTCPESTABLISHED]; got != wantEstablished {
		t.Fatalf("precondition: default established = %d, want %d", got, wantEstablished)
	}

	c := &CtTimeout{
		L4Proto: unix.IPPROTO_TCP,
		Policy:  CtStatePolicyTimeout{CtStateTCPESTABLISHED: 300, CtStateTCPCLOSEWAIT: 1},
	}
	if _, err := c.marshalData(unix.AF_INET); err != nil {
		t.Fatalf("marshalData: %v", err)
	}
	if got := CtStateTCPTimeoutDefaults[CtStateTCPESTABLISHED]; got != wantEstablished {
		t.Errorf("marshalData mutated the shared default: established = %d, want %d", got, wantEstablished)
	}
	if got := CtStateTCPTimeoutDefaults[CtStateTCPCLOSEWAIT]; got != wantCloseWait {
		t.Errorf("marshalData mutated the shared default: close_wait = %d, want %d", got, wantCloseWait)
	}
	// c.Policy 只覆盖指定的两项，其余来自默认。
	merged := c.policyOrDefault()
	if len(merged) != len(CtStateTCPTimeoutDefaults) || merged[CtStateTCPCLOSEWAIT] != 1 {
		t.Errorf("policyOrDefault() = %v, want the 11 defaults with close_wait overridden to 1", merged)
	}

	// 读侧同理：unmarshal 用内核回读的值填充，但不能改到包级默认表。
	read := &CtTimeout{}
	if err := read.unmarshal(unix.AF_INET, ctTimeoutWireData(t)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := CtStateTCPTimeoutDefaults[CtStateTCPESTABLISHED]; got != wantEstablished {
		t.Errorf("unmarshal mutated the shared default: established = %d, want %d", got, wantEstablished)
	}
	if got := read.Policy[CtStateTCPESTABLISHED]; got != 7 {
		t.Errorf("unmarshal Policy[established] = %d, want 7 (from the wire)", got)
	}
	if got := read.Policy[CtStateTCPCLOSEWAIT]; got != wantCloseWait {
		t.Errorf("unmarshal Policy[close_wait] = %d, want the default %d", got, wantCloseWait)
	}

	// 第二个对象不能继承第一个的自定义值。
	second := &CtTimeout{L4Proto: unix.IPPROTO_TCP}
	if got := second.policyOrDefault()[CtStateTCPESTABLISHED]; got != wantEstablished {
		t.Errorf("second object inherited a previous override: established = %d, want %d", got, wantEstablished)
	}
	// UDP 走另一张默认表。
	if got := (&CtTimeout{L4Proto: unix.IPPROTO_UDP}).policyOrDefault()[CtStateUDPUNREPLIED]; got != 30 {
		t.Errorf("UDP default unreplied = %d, want 30", got)
	}
}

// ctTimeoutWireData 造一段只含 established=7 的 ct timeout 报文（对象 blob 的形态）。
func ctTimeoutWireData(t *testing.T) []byte {
	t.Helper()
	policy, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: CtStateTCPESTABLISHED + 1, Data: binaryutil.BigEndian.PutUint32(7)},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: NFTA_CT_TIMEOUT_L3PROTO, Data: binaryutil.BigEndian.PutUint16(unix.AF_INET)},
		{Type: NFTA_CT_TIMEOUT_L4PROTO, Data: []byte{unix.IPPROTO_TCP}},
		{Type: unix.NLA_F_NESTED | NFTA_CT_TIMEOUT_DATA, Data: policy},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
