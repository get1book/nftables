# FORK：google/nftables 的 nfapi 衍生分支

本仓库是 [`github.com/google/nftables`](https://github.com/google/nftables) 的一个 fork，
由 **nfapi** 项目维护，用于暴露 nft 私有的集合 userdata TLV，以闭合
「nftables 库三处缺口」（具名 `typeof` 集合 / map 值显示 `""` / 匿名主机序集合显示 `""`）。

## 上游与基线

- 上游：`github.com/google/nftables`（**Apache License 2.0**）
- 本 fork 起始 commit：`f9b52ed2ba65`（对应上游版本
  `v0.3.1-0.20260430172505-f9b52ed2ba65`）
- 本 fork 当前 HEAD：`5d76844`（仅新增三字段 + 测试，未改动任何既有行为）

## 为什么需要这个 fork

`google/nftables` 的 `Set` 结构体不暴露 nft 私有的 UDATA TLV。nfapi 要创建
`typeof` 集合、让 `map` 值 / 匿名主机序集合在 `nft list` 下正确显示，必须能写出
`KEY_TYPEOF` / `DATABYTEORDER` / `KEYBYTEORDER`。上游不接受这类底层改动，
故在此做**最小 fork**（透传字段，不引入任何表达式语义）。

## 改了什么

所有改动集中在 `set.go`，且**零值不写任何新 TLV，与上游逐字节兼容，可回滚**：

1. `Set` 新增三个字段：
   - `KeyTypeofExpr []byte` —— 透传 `KEY_TYPEOF` 二进制 payload（由 nfapi 编码）。
   - `DataByteOrder binaryutil.ByteOrder` —— 仅 `IsMap` 时写 `DATABYTEORDER`。
   - `KeyByteOrderExplicit bool` —— 为 `true` 时按 datatype 写 `KEYBYTEORDER`
     （concat→0 / 主机序→1 / 网络序→2），不再走上游
     `Anonymous||Constant||Interval` 短路。
2. `AddSet` 透传写入以上 TLV（含 `KeyTypeofExpr > 255` 字节的报错守卫，
   规避 `userdata.Append` 单字节长度的静默截断）。
3. `setsFromMsg` 回填以上字段（用于往返测试）。
4. 新增 `set_fork_test.go`（沿用上游 Apache-2.0 与 Google 版权头）。

`userdata` 包、常量表均**未改动**（fork 复用已有
`NFTNL_UDATA_SET_KEY_TYPEOF` / `NFTNL_UDATA_SET_DATABYTEORDER` 等）。

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
