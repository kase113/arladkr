# Practical ADKR 部署与测试指南

本文档包含 `practical-adkr` (实用的异步分布式密钥重配置) 的架构说明、部署要求及测试指南。

## 1. 项目概述

`practical-adkr` 是针对论文 *Practical Asynchronous Distributed Key Reconfiguration and Its Applications* 的复现实现。
主要将传统 O(n³) 复杂度的非交互式 ACS 同步模式，重构为以下范式：
1. **Interactive PVSS (DXT+)**：通过 `Dealer -> Share` 私下分发并收集 `2f+1` 签名，然后组装最终 Transcript。
2. **Dispersal-Agree-Recast 架构**：通过基于 APDB 的验证后分发，利用 Dumbo-MVBA 和基于阈值签名的 Coin 只抽取 `κ` 个 Transcripts 进行验证重组。
3. **分布式验证**：每个节点只需验证 `2f+1` 个收件人的份额，极大降低了本地计算量。
4. **门限公钥派生**：通过 Schnorr NIZK + Lagrange 插值在对数安全下计算出新公钥。

## 2. 环境要求

- **操作系统**: Linux/MacOS/Windows (WSL)
- **环境依赖**:
  - `Go` (>= 1.20)
- **密码学库依赖**: 原生 `crypto/*` + `dumbomvba-go`（含 `go.dedis.ch/kyber/v3/sign/tbls`）。
- **组件说明**: Agree 阶段已接入 `dumbomvba-go` 等价路径（不再使用 `simulateMVBA`）。

## 3. 代码结构与模块

- `core/types.go`：ADT 等全局结构，定义 DXT Transcripts 与 APDB 消息体。
- `core/paillier.go`：支持 Verifiable Encryption 对未响应节点的数据进行加密（来自 Turritopsis 的复用）。
- `core/pvss_dxt.go`：DXT+交互式安全共享与分布验证，Deal（创建 + 收集 ack）、PartialVerify。
- `core/adkr.go`：Practical ADKR 的 Dispersal、Agree(Dumbo-MVBA) 和 Recast (随机币) 的调度管道。
- `core/mvba_dumbo_adapter.go`：`practical-adkr` 与 `dumbomvba-go` 的多节点内存网络适配层。
- `core/key_derivation.go`：NIZK 零知识证明 (DLog, DH-Tuple) 以及基于 Lagrange 算法的群公钥恢复聚合。
- `core/bitset.go`：高效 BitSet 序列化编码。

## 4. 编译与测试说明

项目所有逻辑均在包内自包含测试通过。提供了便捷测试入口：你可以使用同目录下提供的脚本 `run_tests.sh`（或在 Windows Git Bash / WSL 中运行）。

### 测试内容说明

1. **核心逻辑单元测试** (Unit Tests)：
   - `TestDXTDealAndVerify`验证 DXT+ 中私下通信和签名组装的完整交互逻辑。
   - `TestNIZKDLog` 和 `TestDeriveThresholdPK` 等验证椭圆曲线算数和 NIZK 的安全性。
2. **ADKR 集成用例测试** (E2E Integration Tests)：
   - `TestPracticalADKR`：典型的 n=4, f=1 网络通信测试。
   - `TestPracticalADKRLarger`：对 n=7, f=2 更大集群执行协议跑通处理。
3. **性能基准对比** (Benchmarks)：
   - 包含针对 `TestBenchmarkCostReport` 模块计算 n=4 与 n=7 环境下平均的吞吐量与性能消耗。

---

## 5. 使用测试脚本

为了方便开发与部署前的测试，我们在根目录下提供了一个 `run_tests.sh` 脚本，允许你根据参数进行自动化测试。

### 环境准备

如果是在 Linux/MacOS，确保脚本具有执行权限：
```bash
chmod +x run_tests.sh
```

### 脚本文档：如何传参

**1. 运行全部格式基准**（不带参数）:
```bash
./run_tests.sh all
```

**2. 只运行密码学/零知识等底层单元测试**:
```bash
./run_tests.sh unit
```

**3. 只运行实战集成环境测试 (ADKR 主流程 E2E)**:
```bash
./run_tests.sh e2e
```

**4. 运行性能测试计算 (Benchmarks)**:
```bash
./run_tests.sh bench
```

**5. 直接输出 mean_latency_ms（推荐，与 rladkrbench 口径一致）**:
```bash
go run ./cmd/bench_latency -n 10 -f 3 -kappa 4 -runs 3 -timeout 30s
```
输出示例：
```text
PRACTICAL_ADKR_BENCH_RESULT n=10 f=3 kappa=4 runs=3 mean_latency_ms=... mean_decided_set=... mean_selected=...
```

## 6. 在自己的项目中调用 ADKR

如果要在完整的商业/研究节点项目中跑起 Practical ADKR，以下是示范入口流程：
```go
import "practical_adkr/core"
import "context"

cfg := core.Config{
    SID:          "Your-Session-ID",
    OldCommittee: []int{0, 1, 2, 3}, // 老节点的 ID 数组
    NewCommittee: []int{10, 11, 12}, // 新节点的 ID 数组
    F:            1,                 // f 边界
    Kappa:        2,                 // 要 recasted 收拢的 transcripts 数量
    PaillierBits: 1024,              
}

ctx := context.Background()

// 跑起端到端 ADKR，得到包含聚合了的新 Shares 还有新派生公共参数结果：
result, err := core.RunPracticalADKR(ctx, cfg)
if err != nil {
    panic(err)
}

// 分发后的验证完毕秘密份额
myNewShare := result.NewShares[my_Node_ID] 
```
