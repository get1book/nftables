# FORK：google/nftables 的 nfapi 衍生分支

本仓库是 [`github.com/google/nftables`](https://github.com/google/nftables) 的一个 fork，
由 **nfapi** 项目维护，用于暴露 nft 私有的 userdata TLV：集合侧闭合
「nftables 库三处缺口」（具名 `typeof` 集合 / map 值显示 `""` / 匿名主机序集合显示 `""`），
有状态对象侧补上 `NFTA_OBJ_USERDATA`（counter / quota 的 `comment`）。

## 上游与基线

- 上游：`github.com/google/nftables`（**Apache License 2.0**）
- 本 fork 起始 commit：`f9b52ed2ba65`（对应上游版本
  `v0.3.1-0.20260430172505-f9b52ed2ba65`）
- 本 fork 当前 HEAD：`5d76844`，其上是一批未提交改动：集合/对象 userdata、
  表达式回读补齐（含新增 `xfrm`）、`objref` 集合形态解码、`ErrRuleNotFound` 哨兵（见下）。
  除哨兵与 `payload` 的校验和写侧调整外，其余都是纯新增字段或把 `unmarshal` 从
  `not yet implemented` 补成实现，未改动既有行为。

## 为什么需要这个 fork

`google/nftables` 的 `Set` 结构体不暴露 nft 私有的 UDATA TLV。nfapi 要创建
`typeof` 集合、让 `map` 值 / 匿名主机序集合在 `nft list` 下正确显示，必须能写出
`KEY_TYPEOF` / `DATA_TYPEOF` / `DATABYTEORDER` / `KEYBYTEORDER`。上游不接受这类底层改动，
故在此做**最小 fork**（透传字段，不引入任何表达式语义）。

## 改了什么

分两块：集合（`set.go` + `userdata/userdata.go`）与有状态对象（`obj.go` + `userdata/userdata.go`）。
两块都**零值不写任何新 TLV，与上游逐字节兼容，可回滚**。

### 集合

1. `Set` 新增四个字段：
   - `KeyTypeofExpr []byte` —— 透传 `KEY_TYPEOF` 二进制 payload（由 nfapi 编码）。
   - `DataTypeofExpr []byte` —— 透传 `DATA_TYPEOF` 二进制 payload（`map` 值侧 typeof，
     与 `KeyTypeofExpr` 对称，由 nfapi 编码；仅 `IsMap` 有意义）。
   - `DataByteOrder binaryutil.ByteOrder` —— 仅 `IsMap` 时写 `DATABYTEORDER`。
   - `KeyByteOrderExplicit bool` —— 为 `true` 时按 datatype 写 `KEYBYTEORDER`
     （concat→0 / 主机序→1 / 网络序→2），不再走上游
     `Anonymous||Constant||Interval` 短路。
2. `AddSet` 透传写入以上 TLV（含 `KeyTypeofExpr` / `DataTypeofExpr` > 255 字节的报错守卫，
   规避 `userdata.Append` 单字节长度的静默截断）。
3. `setsFromMsg` 回填以上字段（用于往返测试）。
4. 新增 `set_fork_test.go`（沿用上游 Apache-2.0 与 Google 版权头）。

`userdata` 包的集合侧常量表**未改动**（fork 复用已有
`NFTNL_UDATA_SET_KEY_TYPEOF` / `NFTNL_UDATA_SET_DATABYTEORDER` 等）。

### 对象映射（object map）

`map ... { type inet_service : counter }` 的“值”不是数据类型，而是**指向具名对象的引用**，
内核用两个属性表达，上游两者都没有：

10. `Set` 新增 `ObjType ObjType`，非零时：置 `NFT_SET_OBJECT`（0x40，**不置** `NFT_SET_MAP`，
    与 nft 实测一致）、写 `NFTA_SET_OBJ_TYPE`(15)，且**不发** `NFTA_SET_DATA_TYPE` / `NFTA_SET_DATA_LEN`。
11. `setsFromMsg` 回读 `NFTA_SET_OBJ_TYPE`。
12. `SetElement` 新增 `ObjRef string`：非空时写 `NFTA_SET_ELEM_OBJREF`(9)（NLA_STRING，对象名）
    代替 `NFTA_SET_ELEM_DATA`；`decode` 回读时剥掉结尾 NUL。
13. 新增 `objmap_fork_test.go`，把上述报文逐属性钉死（对照 nft 1.1.7 + 内核 7.2.6 的 strace 抓包）。

注意 `NFT_SET_OBJECT` / `NFTA_SET_OBJ_TYPE` / `NFTA_SET_ELEM_OBJREF` 三个常量
`golang.org/x/sys`（v0.47.0 起）已经导出，不需要手工补。

### 有状态对象（counter / quota）

`nft add counter ... { comment "..." }` 的备注和集合一样不走 `NFTA_OBJ_DATA`，
而是放在 `NFTA_OBJ_USERDATA` 的 TLV 里（type 0）。上游 `NamedObj` 既没有该字段、
回读时也不解析，nftweb 就无法显示或写入对象备注，因此按同一思路补齐：

5. `NamedObj` 新增 `UserData []byte`，承载 `NFTA_OBJ_USERDATA` 原始 TLV。
6. `AddObj` 在 `UserData` 非空时写出该属性（空值不写，与上游逐字节一致）。
7. `objFromMsg` 改成「循环收集、末尾统一返回」：内核把 `USERDATA` 排在 `DATA` 之后，
   上游在 `DATA` 分支直接 `return`，会把它整个丢掉。
8. `userdata` 包新增 `NFTNL_UDATA_OBJ_COMMENT`（=0，对齐 libnftnl 的
   `nftnl_udata_obj_types`），读写 comment 复用。
9. 新增 `obj_fork_test.go`（写入 TLV / 回读往返 / 零值不写属性 / legacy 路径不回归）。

10. `expr.CtTimeout` 的 `marshalData` / `unmarshal` 原来是把包级共享的
    `CtStateTCPTimeoutDefaults` / `CtStateUDPTimeoutDefaults` **直接赋给局部变量再写入**，
    等于原地修改共享的默认策略表：同一个进程里建过一个带自定义 policy 的 `ct timeout`
    之后，此后每个对象都会带上那次的值。改成 `policyOrDefault()` 复制一份再覆盖，
    并新增 `expr/cttimeout_fork_test.go` 钉住「默认表不被改动 + 回读会合并默认值」。

顺带确认（**这七种无需改 fork**）：nft 1.1.7 的 `limit` / `secmark` / `synproxy` /
`cthelper` / `cttimeout` / `ctexpect` / `connlimit`（nft 写作 `ct count`）七种对象的
私有数据，其属性编号与**同名表达式**完全一致（`NFTA_LIMIT_*` 既是 `limit` 语句的属性、
也是 `limit` 对象的属性；`NFTA_CT_HELPER_*` / `NFTA_CT_EXPECT_*` / `NFTA_CONNLIMIT_*`
同理）。而这些 expr 类型（`expr.Limit` / `SecMark` / `SynProxy` / `CtHelper` /
`CtTimeout` / `CtExpect` / `Connlimit`）本就在包里且 `exprFromName` 已按类型名注册了
读侧解析器 —— 加上 `AddObj` 走通用的 `expr.MarshalExprData(o.data())`，
它们**不改一行就能直接当对象 payload 用**。

另外在 `obj.go` 补了内核常量 `nftaObjUserData = 8`：`NFTA_OBJ_PAD = 7` 夹在中间，
`golang.org/x/sys` 至今没有导出这个常量。

实测校准（nft 1.1.7 + 本 fork）：`nft list table` 能原样打印出 nftweb 写入的 comment，
反向用 `nft add counter ... { comment "made by nft cli" }` 建的对象也能被 nftweb 读回。

### 读回：`objref` 的集合形态（对象 map）

`map ... { type inet_service : counter }` 这种对象映射，内核**不置** `NFT_SET_MAP`，
值不是数据类型而是对具名对象的引用。规则里引用它时，`objref` 表达式给的是
「键所在寄存器 + 集合名/ID」，`IMM_*` 属性整组缺席 —— 上游只解 `IMM_*`，
于是读回来 `Type=0`、渲染不出正文。

- `expr.Objref` 新增三个只读字段：`SetSReg uint32` / `SetName string` / `SetID uint32`。
- `unmarshal` 解 `NFTA_OBJREF_SET_SREG(3)` / `NFTA_OBJREF_SET_NAME(4)` /
  `NFTA_OBJREF_SET_ID(5)`（`golang.org/x/sys` 未导出这三个常量，按内核 uapi 硬编码）。
- 只改读侧；写侧仍按 `IMM_TYPE`/`IMM_NAME` 走，零值不写新属性，与上游逐字节兼容。
- 对象种类由被引用集合的 `NFTA_SET_OBJ_TYPE` 决定（见上一节 `Set.ObjType`），
  `objref` 自身不带。
- 涉及文件：`expr/objref.go`（本文件）。

### 表达式回读补齐（byteorder / rt / tproxy / ct 方向 / payload 校验和）

上游有几个表达式的 `unmarshal` 是 `not yet implemented`，还有几个的字段读错了宽度，
表现都是「内核里有这条规则，回读正文却缺一段 / 整条失败」。共五处：

- `expr/byteorder.go`：补 `unmarshal`，解 `NFTA_BYTEORDER_SREG/DREG/OP/LEN/SIZE`
  （原来直接返回 `not yet implemented`，带字节序运算的规则回读必失败）。
- `expr/rt.go`：补 `unmarshal`（`NFTA_RT_KEY`/`NFTA_RT_DREG`）；新增
  `RtXFRM RtKey = 4` 表示 `rt ipsec`——`enum nft_rt_keys` 里它是第 5 项，
  但 `golang.org/x/sys/unix` 尚未导出，按枚举顺序钉死字面量，换来源只改这一处。
- `expr/tproxy.go`：`NFTA_TPROXY_FAMILY` 是 **u32**（`NLA_U32`），原来读成 `Uint8`，
  内核回 `attribute 1 is not a uint8; length: 4`，整条链回读直接失败；改为
  `byte(ad.Uint32())`。
- `expr/ct.go`：`hasDirection` 只在方向属性真的存在时才置 `OptDirection`，但原代码
  只给 `pkts/bytes/avgpkt/l3protocol/protocol` 这五个键开放方向，其余键即使内核
  回了 `NFTA_CT_DIRECTION` 也被丢掉。补上 `zone/src/dst/protosrc/protodst/
  srcip/dstip/srcip6/dstip6` 后：`ct reply ip saddr` 不再被显示成
  `ct original ip saddr`；`ct original zone 1` 不再被压成 `ct zone 1`。
  zone 必须在列——它是 `parser_bison.y:5795-5814` 里的 `ct_key_dir_optional`，
  nft 发的就是 `ct load zone, dir original`（真机 inet:244 实测）。
- `expr/payload.go`（写侧）：`NFTA_PAYLOAD_CSUM_FLAGS` 原来嵌在
  `CsumType > 0` 分支里。nft 对 udp 改写（`udp sport/dport/checksum set`）发的是
  `csum_type=0 + csum_flags=1`（`NFT_PAYLOAD_L4CSUM_PSEUDOHDR`），嵌在 type 里会让
  udp 改写丢掉校验和调整语义（实测内核 `csum_flags` 0x0，nft 同规则为 0x1，
  2026-10-17）。现在 flags 一律写在顶层。

另有 `expr/expr.go` 的 `exprFromName`：表达式按名字反查类型，漏登记就返回 `nil`，
上层只能判成「读回缺口」。补登记了 `xfrm`、`socket`、`rt`、`tproxy`、`byteorder`
（`dup` 原本已实现，只是没登记，注释里也写明了）。

涉及文件：`expr/byteorder.go`、`expr/rt.go`、`expr/tproxy.go`、`expr/ct.go`、
`expr/payload.go`、`expr/expr.go`。

### 新表达式：`xfrm`（`ipsec` 匹配）

`expr/xfrm.go`（新增文件）实现 `ipsec in reqid 1` / `ipsec out spi 0x100` 的回读与写侧：

- 结构 `Xfrm{Dreg, Key, Dir, Spnum}`；`NFTA_XFRM_DREG/KEY/DIR/SPNUM = 1..4`
  （`golang.org/x/sys/unix` 未收录，就地定义）。
- `Key` 取 `enum nft_xfrm_keys`：`reqid=5`、`spi=6`。
- 两者字节序不同：`reqid` 走 HE 模板（主机序）、`spi` 走 BE 模板（大端）
  ——nft `src/xfrm.c:44-45`；实测 cmp 字节 `reqid 1 → 01 00 00 00`、
  `spi 0x100 → 00 00 01 00`。
- 涉及文件：`expr/xfrm.go`。

### 规则查询：`ErrRuleNotFound` 哨兵

按 handle 查规则时，内核对「没有这一条」可能回 `ENOENT`，也可能回一条空结果。
上游对后者只返回裸文本 `expected rule count 1, got 0`，调用方只能匹配错误文本 ——
文案改一个字，原本的 404 就会掉进默认分支变成 422/500，且编译期没有提示。

- 新增 `var ErrRuleNotFound = errors.New("nftables: rule not found")`。
- `GetRuleByHandle` / `ResetRule` 在结果数为 0 时返回
  `fmt.Errorf("%w: handle %d", ErrRuleNotFound, handle)`；结果数 > 1 仍用原通用报错
  （那是真异常，不该被当成“没找到”）。
- 调用方用 `errors.Is(err, nftables.ErrRuleNotFound)` 判断，不要匹配文本。
- `%w` 包装可穿透多层 `fmt.Errorf`；与 `unix.ENOENT` 并列判断即可覆盖两种内核形态。
- 涉及文件：`rule.go`（本文件）；nfapi 侧消费点是 `engine/store/reconcile.go` 的 `RuleGone`。


## 许可证与合规（重要）

本项目沿用上游的 **Apache License 2.0**：

- `LICENSE` 文件保持原样、未修改。
- 所有源文件的版权头（如 `Copyright 2018 Google LLC`）保持原样、未删除。
- 本文件 + `set.go` 中的 `nfapi fork` 注释记录了「文件被修改」这一事实，
  满足 Apache-2.0 §4(b) 对修改文件的声明要求。
- **推送到你自己的 GitHub 仓库不侵权**：Apache-2.0 明确允许复刻、修改与再分发；
  只要遵守上述三点（保留 LICENSE / 版权头 / 声明修改）即合规。
- 注意：**不要**用 “Google” 名义或商标暗示本 fork 获得 Google 官方背书。
  保留 Google 的版权署名是合规要求，不等同于背书。

## 模块路径（技术注意，非法律问题）

本 fork 的 `go.mod` module 仍是 `github.com/google/nftables`（与上游一致）。这意味着：

- nfapi 用 `replace github.com/google/nftables => <本仓库>` 消费，工作正常。
- 若想让他人直接 `go get github.com/get1book/nftables`，需把 `go.mod` 的
  module 改成 `github.com/get1book/nftables`（并同步仓库内 import），否则 Go
  会因「模块路径 ≠ 仓库路径」报错。对 nfapi 自用场景，不改即可。

## 如何被 nfapi 使用

在 `nfapi/go.mod` 中：

```go
replace github.com/google/nftables => /path/to/nftables-fork   // 本地开发
// 推送后建议改为伪版本（不要保留本地绝对路径）：
// replace github.com/google/nftables => github.com/get1book/nftables v0.3.1-nfapi.1
```

## 如何同步上游

上游更新时（冲突面极小，仅三字段改动）：

```sh
git remote add upstream https://github.com/google/nftables.git   # 若尚未添加
git fetch upstream
git rebase upstream/main        # 或 merge，保持三字段改动在栈顶
go test ./...
```
