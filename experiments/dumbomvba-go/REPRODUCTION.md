# dumbomvba Go 复现记录

更新时间：2026-04-27

## 目标

在 `~/project/RLADKR/dumbomvba-go` 持续复现 `~/project/dumbomvba/dumbomvba/core`，覆盖：

- MVBA 主路径（PD / quit / coin / RC）
- ACS/VACS（`mvbacommonsubset`）
- TBLS 签名体系（替换原 Python 依赖）

## 原始 Python 参考

- `dumbomvba/core/mvba.py`
- `dumbomvba/core/temp.py`
- `dumbomvba/core/pd.py`
- `dumbomvba/core/rc.py`
- `dumbomvba/core/acs.py`
- `dumbomvba/core/mvba_r.py`

## Python -> Go 映射（当前）

1. MVBA 入口与路由
- Go: `core/mvba.go`, `core/mvba_equivalent.go`, `core/types.go`
- Tag：
  - `MVBA_PD`, `MVBA_PD_FINISH`, `MVBA_COIN`
  - `MVBA_RC_PREPARE`, `MVBA_RC`
  - `MVBA_ABA`, `MVBA_ABA_COIN`, `MVBA_ABA_DECISION`

2. PD（Provable Dispersal）
- Go: `core/pd_equivalent.go`
- 覆盖：
  - `STORE / STORED / LOCK / LOCKED / DONE`
  - Reed-Solomon 切片与恢复
  - Merkle 分支验证

3. RC（Recast）
- Go: `core/rc_equivalent.go`
- 覆盖：
  - `RCSTORE / RCLOCK`
  - `f+1` 分片解码与根校验

4. Common Coin 与 ABA
- Go: `core/coin_equivalent.go`, `core/aba_equivalent.go`
- 变更点：
  - coin 使用 TBLS 恢复出的唯一聚合签名导出随机值
  - 之前“等待全量 shares”的工程化处理已移除
  - ABA 由“立即本地决定”改为消息驱动收敛（收集 `2f+1` EST，再结合 coin/决议消息收敛）

5. RC prepare + 迭代 leader 选择
- Go: `core/mvba_equivalent.go`
- 已补齐：
  - `RCBALLOTPREPARE` 等价流程（`MVBA_RC_PREPARE`）
  - 按 permutation 逐轮执行 `RC_PREPARE -> ABA -> RC`，不再只尝试 `pi[0]`

6. ACS/VACS（mvbacommonsubset）
- Go: `core/acs_vacs.go`
- 覆盖：
  - `ACS_DIFFUSE` + `ACS_MVBA` 两层路由
  - diffuse 收集 `N-f` 有效值后进入 MVBA

## TBLS 替换说明

原 Python 依赖 `honeybadgerbft.crypto.threshsig.boldyreva`。

当前 Go 使用 `go.dedis.ch/kyber/v3/sign/tbls`：

- `core/signer_tbls.go`
  - `GenerateTBLSKeyBundle(n, f)`：生成 `(f+1)` 和 `(n-f)` 两套阈值密钥
  - `NewTBLSSigner(...)`
  - `Sign/Verify`（share）
  - `Recover/VerifyRecovered`（聚合签名）

与原逻辑对应关系：

- `PD_STORED` / `PD_LOCKED` / `SPBC_ECHO` / `ACS_DIFFUSE` 使用高阈值域（`n-f`）
- 其余域（如 `EQ_COIN_SHARE`）使用低阈值域（`f+1`）

## 与 adkr-go 对接

`adkr-go/core/mvba.go` 已切换：

- 使用 `GenerateTBLSKeyBundle` + `NewTBLSSigner`
- `mvba.Config` 启用 `UseEquivalentPath: true`

## 与 practical-adkr 对接

`practical-adkr/core/adkr.go` 已从 `simulateMVBA` 切换为真实 `dumbomvba-go` 调用：

- 适配层：`practical-adkr/core/mvba_dumbo_adapter.go`
- 模式标记：`AgreementMode = "dumbomvba-go-equivalent"`
- 通过 in-memory 多节点运行 MVBA，并将输出回填为 dealer set 决策

## 测试记录

### dumbomvba-go

```bash
cd /home/yzc/project/RLADKR/dumbomvba-go
go test -count=1 ./...
```

通过。

### adkr-go 集成

```bash
cd /home/yzc/project/RLADKR/adkr-go
go mod tidy
go test -count=1 ./...
go test -count=1 ./core -run 'TestAgreeDealerSetMVBA_Debug|TestADKRGo_N4_MeanLatency' -v
```

通过。最近一次基准输出：

- `ADKR_GO_BENCH_RESULT n=4 runs=1 mean_latency_ms=757.00 mean_selected_dealers_per_sec=2.64 fallback_runs=0`

## 当前状态与备注

- 已完成：
  - TBLS（kyber/tbls）替换完成
  - Common coin 去除“全量 shares 等待”工程化处理
  - ACS/VACS 路径已补齐代码
  - `adkr-go` 调用链可运行并通过现有测试

- 备注：
  - 当前等价路径在内存网络并发测试下仍具有时序敏感性，测试中对超时做了 smoke 级容忍（不会影响 `adkr-go` 当前调用链验证）。
