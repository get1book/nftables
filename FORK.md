# FORK：google/nftables 的 nfapi 衍生分支

本仓库是 [`github.com/google/nftables`](https://github.com/google/nftables) 的一个 fork，
由 **nfapi** 项目维护，用于暴露 nft 私有的 userdata TLV：集合侧闭合
「nftables 库三处缺口」（具名 `typeof` 集合 / map 值显示 `""` / 匿名主机序集合显示 `""`），
有状态对象侧补上 `NFTA_OBJ_USERDATA`（counter / quota 的 `comment`）。

## 上游与基线

- 上游：`github.com/google/nftables`（**Apache License 2.0**）
- 本 fork 起始 commit：`f9b52ed2ba65`（对应上游版本
  `v0.3.1-0.20260430172505-f9b52ed2ba65`）
- 本 fork 当前 HEAD：`5d76844`，其上是未提交的有状态对象 userdata 改动（见下）。
  两块改动都是纯新增字段，未改动任何既有行为。

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
