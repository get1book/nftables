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

type QueueAttribute uint16

type QueueFlag uint16

// Possible QueueAttribute values
const (
	QueueNum   QueueAttribute = unix.NFTA_QUEUE_NUM
	QueueTotal QueueAttribute = unix.NFTA_QUEUE_TOTAL
	QueueFlags QueueAttribute = unix.NFTA_QUEUE_FLAGS

	QueueFlagBypass QueueFlag = unix.NFT_QUEUE_FLAG_BYPASS
	QueueFlagFanout QueueFlag = unix.NFT_QUEUE_FLAG_CPU_FANOUT
	QueueFlagMask   QueueFlag = unix.NFT_QUEUE_FLAG_MASK
)

type Queue struct {
	Num   uint16
	Total uint16
	Flag  QueueFlag
	// SregQnum 非 0 表示队列号来自**寄存器**（`queue to <键> map { … }`）。
	// 内核属性是 NFTA_QUEUE_SREG_QNUM（u32 寄存器号），与 NUM/TOTAL **互斥**：
	// 上游库只会发 NUM/TOTAL/FLAGS，表达不了这种形态，所以此前一律走 tier2 降级。
	// 真机（nft 1.1.7 `--debug=netlink`，内核 7.2.6）：
	//   `queue to tcp dport map { 80 : 1 }` → [lookup reg 1 … dreg 1][queue sreg_qnum 1]
	//   `queue flags bypass to …`            → [queue sreg_qnum 1 bypass]
	// 寄存器里是 **16 位主机序**的队列号（nft 的 stmt_evaluate_queue 用
	// integer_type / 16 bits / BYTEORDER_HOST_ENDIAN）。
	SregQnum uint32
}

func (e *Queue) marshal(fam byte) ([]byte, error) {
	data, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("queue\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Queue) marshalData(fam byte) ([]byte, error) {
	// 队列号来自寄存器时只发 SREG_QNUM（+ FLAGS）：内核的 nft_queue_init 走的是
	// 「要么 NUM/TOTAL，要么 SREG_QNUM」两条互斥分支，同时带会被拒/语义不明。
	// nft 自己也是这么发的（真机 `queue sreg_qnum 1 bypass`）。
	if e.SregQnum != 0 {
		attrs := []netlink.Attribute{
			{Type: unix.NFTA_QUEUE_SREG_QNUM, Data: binaryutil.BigEndian.PutUint32(e.SregQnum)},
		}
		if e.Flag != 0 {
			attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_QUEUE_FLAGS,
				Data: binaryutil.BigEndian.PutUint16(uint16(e.Flag))})
		}
		return netlink.MarshalAttributes(attrs)
	}
	if e.Total == 0 {
		e.Total = 1 // The total default value is 1
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_QUEUE_NUM, Data: binaryutil.BigEndian.PutUint16(e.Num)},
		{Type: unix.NFTA_QUEUE_TOTAL, Data: binaryutil.BigEndian.PutUint16(e.Total)},
		{Type: unix.NFTA_QUEUE_FLAGS, Data: binaryutil.BigEndian.PutUint16(uint16(e.Flag))},
	})
}

func (e *Queue) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_QUEUE_NUM:
			e.Num = ad.Uint16()
		case unix.NFTA_QUEUE_TOTAL:
			e.Total = ad.Uint16()
		case unix.NFTA_QUEUE_FLAGS:
			e.Flag = QueueFlag(ad.Uint16())
		case unix.NFTA_QUEUE_SREG_QNUM:
			// `queue to <键> map {…}`：内核只发这一个寄存器属性，没有 NUM/TOTAL。
			// 不读它的话回读拿到 Num=0，渲染成 `queue to 0` 并把前面的查表子句丢掉。
			e.SregQnum = ad.Uint32()
		}
	}
	return ad.Err()
}
