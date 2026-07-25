# ARLADKR-Go 实现过程维护文档

更新时间：2026-05-31

## 1. 文档目的

本文件用于在 `rladkr-go` 现有实现基础上，系统化推进 `ARLADKR`（Aggregate RL-ADKR）落地，持续维护：

- `rladkr` 语义到代码的映射
- `apvss` 关键思想到协议对象层的吸收方式
- 当前实现与目标语义的差距
- 分阶段改造计划、验收标准与风险边界
- 每轮实现日志与验证记录

## 2. 输入来源

- 现有工程：`/home/yzc/project/RLADKR/arladkr`
- ARLADKR 思路稿：`/home/yzc/project/RLADKR/arladkr/arladkr.md`
- APVSS 论文文档：`/home/yzc/project/RLADKR/arladkr/apvss.md`
- RLADKR 既有维护文档：`/home/yzc/project/RLADKR/rladkr/RLADKR_GO_IMPLEMENTATION.md`

## 3. ARLADKR 目标定位（本实现口径）

基于 `arladkr.md` 的主张，当前工程目标收敛为一条主线：

1. 以 `AggRLO`（`AggHeader + AggLock`）作为 agreement 前沿对象。
2. 采用 `LockAgg -> AgreeAgg -> RecoverAgg -> Derive` 四阶段。
3. 维持 `fastlane + fallback` 的 network-adaptive 执行。
4. 在 `RecoverAgg -> receiver decrypt` 链路上保留 `Update + Erase` 的 receiver-side forward secrecy 闭环。

与 `apvss.md` 的关系：

- 借鉴的是“聚合优先 + 公共可验证 + 自适应威胁建模”的设计思想。
- 不将 APVSS 直接当黑盒嵌入；而是将其映射为 ARLADKR 的对象语义和验证接口增强。

## 4. 当前代码基线审计（2026-05-09）

### 4.1 当前已具备能力

- 端到端主流程已存在：`RunEpoch` 串联 `BuildDealerArtifacts -> Fastlane/Fallback -> RecoverAndDerive -> UpdateAndErase`。
- 协议对象已具备 `Header/Lock/Descriptor` 与 digest 绑定。
- 已有门限签名支撑的 lock/cert 校验路径（`ValidateDescriptor`）。
- fallback 支持分布式 actor 模式，包含 RBC + ABA + common coin 组合流程。
- recover 阶段已具备 transcript 解析、share 校验与聚合公钥导出流程。
- receiver 侧状态演进与擦除（含状态持久化）已具备。

### 4.2 基线差距说明（历史快照，后续进展见第 10 节）

- （基线时）agreement 围绕 per-dealer `Descriptor` 集合决策，不是单对象 `AggRLO` 决策。
- （基线时）尚未形成显式 `AggHeader`、`AggLock`、`AdmitAgg` 接口。
- （基线时）fallback 输入是 descriptor 集合视图，不是 canonical `H(AggRLO)` 输入。
- （基线时）recover 按 sampled dealer 子集遍历恢复，不是一次性 `RecoverAgg(single aggregate payload)`。
- 当前状态更新：上述 4 项已在第 10 节后续实现日志中逐步落地（M3/M4/M5）。

### 4.3 本地基线验证

- 执行：`go test ./...`
- 结果：通过
  - `ok   rladkr_go/core  19.930s`

## 5. RLADKR -> ARLADKR 的映射与差距（结合 APVSS）

| 维度 | 现状（rladkr-go） | ARLADKR 目标 | 差距等级 |
|---|---|---|---|
| Agreement 对象 | 多 `Descriptor` 集合 | 单 `AggRLO` | 高 |
| 锁语义 | per-dealer recoverability lock | 聚合级 `AggLock`（common-holder 证书） | 高 |
| Gate 谓词 | `ValidateDescriptor` | `AdmitAgg(AggRLO)` | 高 |
| Fallback 输入 | descriptor proposal/blob | canonical `digest(AggRLO)` | 高 |
| Recover 语义 | 多 dealer 抽样恢复 | 单聚合对象恢复 `RecoverAgg` | 高 |
| 绑定链 | `payload -> root -> descriptor` | `AggLock -> AggHeader -> AggPayload` | 中高 |
| APVSS 对齐 | 有公开验证与聚合元素，但无显式 `ADist/AVer/Agg` API 分层 | 抽象出 APVSS-style 接口层并可测试 | 中 |
| 自适应叙事 | 静态主线 + 局部后腐蚀防护 | 明确区分 static / post-erasure adaptive / posterior corruption | 中 |

## 6. APVSS 抽象到工程接口的落地建议

目标不是复制论文证明，而是把接口语义落到可测试工程层。

### 6.1 建议新增接口层（`core/apvss_iface.go`）

建议抽象：

- `ADist(dealer, receiverSet) -> Transcript`
- `Ver(transcript) -> bool`
- `Agg(transcripts) -> AggTranscript`
- `AVer(aggTranscript) -> bool`
- `Rec(aggTranscript, openings) -> secret/material`

意义：

- 把当前散落在 `transcript_codec.go`、`disperse.go`、`recover_derive.go` 的能力收束成统一 API。
- 便于后续将 `AggRLO` 与 `AdmitAgg` 直接绑定到聚合 transcript 的验证结果。

### 6.2 与 `arladkr.md` 的对象层对齐

新增/重构对象建议：

- `AggHeader`：固定 dealer 集合、聚合 root、epoch/sid、metadata commitment。
- `AggLock`：对 `H(AggHeader)` 的门限证书 + canonical signer set。
- `AggRLO`：`(AggSet, AggHeader, AggLock)`。

### 6.3 本轮执行决策：采用 Optrand-PVSS 语义路径

- 采用仓库：`DimitrisPapac/Optrand-PVSS` 作为 APVSS 聚合语义参考实现。
- 本项目中的落地方式：先接入 **Optrand 风格的 `share verify + aggregate + aggregate verify`** 校验链，不一次性替换成完整外部密码学栈。
- 执行策略：
  - 在 `fastlane gate` 增加 Optrand share 级校验；
  - 在 `proposal` 决策前增加聚合 transcript 构建与校验；
  - 通过新增测试锁定接口行为，再逐步推进到 `AggRLO` 对象级接口。

## 7. 分阶段改造计划（可执行）

### M0（已完成）基线冻结与审计

- 记录当前流水线、测试状态、风险边界。
- 输出本维护文档初版。

### M1 对象层升级：引入 AggRLO 数据结构

- 文件：`core/types.go`
- 目标：新增 `AggHeader`、`AggLock`、`AggRLO` 类型与 digest/canonical 编码函数。
- 验收：新增单测验证 canonical 编码稳定性和 digest 一致性。

### M2 LockAgg 重构：从 per-dealer lock 到 aggregate lock

- 文件：`core/disperse.go`、新增 `core/lockagg.go`
- 目标：
  - 先形成候选 dealer 集合 `S`。
  - 生成 `AggHeader`。
  - 由 holder 对 `H(AggHeader)` 产生 share，并恢复 `AggLock` 证书。
- 验收：
  - `VerifyAggLock` 成功路径。
  - signer 子集不同但 canonical 后结果一致。

### M3 AgreeAgg 重构：fastlane/fallback 统一面向 AggRLO

- 文件：`core/gate_fastlane.go`、`core/fallback_dispatch.go`、`core/fallback_acs.go`
- 目标：
  - `AdmitAgg` 替代 `ValidateDescriptor` 作为 gate。
  - fastlane 广播对象改为 `AggRLO` 或 `digest(AggRLO)`。
  - fallback MVBA 输入改为 `digest(AggRLO)` + 本地 canonical 组装。
- 验收：
  - fastlane/fallback path consistency：两路径同输入同输出。

### M4 RecoverAgg 重构：单对象恢复

- 文件：`core/recover_derive.go`、新增 `core/recoveragg.go`
- 目标：
  - 从 `AggRLO` 恢复单聚合 payload。
  - receiver 按索引解封装，直接进入 derive。
- 验收：
  - 不再出现按 dealer 逐个恢复的主循环。
  - 恢复失败定位到对象级错误（header/lock/binding）。

### M5 APVSS-style 验证接口与测试矩阵

- 文件：新增 `core/apvss_iface.go`、`core/apvss_iface_test.go`
- 目标：
  - 给出 `ADist/Ver/Agg/AVer/Rec` 的工程语义包装。
  - 引入至少 3 类负向测试：恶意聚合、签名集合不一致、绑定破坏。
- 验收：
  - 接口测试覆盖 fastlane/fallback 两条主路径下的对象验证。

### M6 基准与文档闭环（已完成）

- 文件：`cmd/rladkrbench/main.go`、本维护文档
- 目标：
  - 增加 ARLADKR 指标：`AggRLO ready time`、`AdmitAgg pass ratio`、`RecoverAgg success ratio`。
  - 更新复杂度与边界说明。
- 验收：
  - `go test ./...` 全绿。
  - 输出至少一组 `n=4/6` 对比数据（改造前 vs 改造后）。

## 8. 安全边界与不承诺项（当前实现口径）

- 不宣称 erasure-free fully adaptive old-dealer security。
- 旧委员会主模型保持静态腐蚀；仅在满足 erasure 时序下讨论 post-erasure 风险。
- receiver-side posterior corruption 防护依赖 `Update + Erase` 正确执行。
- APVSS 论文中的 AGM/COMDL 完整证明不在工程实现范围；工程中保留“可验证接口 + 失败可观测性 + 负向测试”来对齐语义。

## 9. 验证标准（ARLADKR 版本）

- 功能闭环：`LockAgg -> AgreeAgg -> RecoverAgg -> Derive -> Update/Erase` 跑通。
- 一致性：诚实节点输出同一 canonical `AggRLO` digest。
- 对象安全：`AdmitAgg` 能拒绝签名不齐、集合不一致、绑定破坏对象。
- 恢复安全：`RecoverAgg` 输出与 `AggHeader/AggLock` 绑定一致。
- 工程可用：`go test ./...` 全通过，`rladkrbench` 可输出 ARLADKR 指标。

## 10. 实现日志

### 2026-05-09（本轮：建立 ARLADKR 维护文档并完成基线审计）

- 在 `rladkr-go` 复制工程基础上完成首轮 ARLADKR 定位分析。
- 读取并对齐三份输入文档：`apvss.md`、`arladkr.md`、`RLADKR_GO_IMPLEMENTATION.md`。
- 完成代码基线审计（对象、agreement、recover、forward secrecy、持久化）。
- 输出本维护文档，给出从 RLADKR 到 ARLADKR 的 6 阶段改造路线。
- 本轮验证：`go test ./...` 通过。

### 2026-05-09（本轮追加：开始执行 Optrand-PVSS 接入实现）

- 新增 `core/apvss_optrand.go`：
  - `OptrandShareVerify`：对单 dealer transcript 执行 Optrand 风格的 share 级入场校验（descriptor、payload-root、threshold、ciphertext 完整性）。
  - `BuildOptrandAggregatedTranscript`：对 dealer 集合构建 canonical 聚合 transcript（per-dealer contribution digest + aggregate digest）。
  - `VerifyOptrandAggregatedTranscript`：重算并校验聚合 transcript 绑定关系。
- 新增 `core/apvss_optrand_test.go`（TDD）：
  - `TestOptrandShareVerify`
  - `TestOptrandAggregateAndVerify`（包含篡改 digest 的负向测试）
- 修改 `core/gate_fastlane.go`：
  - `RunGateAndFastlane` 接口扩展为接收 `artifacts`；
  - ready candidate 选择增加 `OptrandShareVerify`；
  - fastlane proposal 决议前增加 Optrand aggregate build/verify。
- 修改 `core/epoch.go`：
  - `RunEpoch` 调用 fastlane 时传入 `artifacts`，使 Optrand 校验链进入主路径。
- 本轮验证证据：
  - `go test ./core -run 'TestOptrand' -count=1` 通过；
  - `go test ./...` 通过（`ok   rladkr_go/core  24.874s`）。

### 2026-05-09（本轮追加：统一 `ADist/Ver/Agg/AVer/Rec` 接口并接入 `AggRLO/AdmitAgg`）

- 新增 `core/apvss_iface.go`：
  - 定义统一 APVSS 接口：`ADist / Ver / Agg / AVer / Rec`；
  - 新增 `OptrandAPVSS` 实现与 `NewOptrandAPVSS()`；
  - `Agg/AVer` 复用 Optrand 聚合路径，`Rec` 输出可验证聚合恢复材料摘要（工程语义层）。
- 新增 `core/aggrlo.go`：
  - `BuildAggRLO`：由 APVSS 聚合结果构建 `AggHeader + AggLock + AggRLO digest`；
  - `AdmitAgg`：统一执行对象级 admission（sid/epoch、dealer canonical、aggregate 绑定、APVSS AVer、AggLock 阈值签名校验、RLO digest 绑定）。
- 修改 `core/types.go`：
  - 新增 `AggHeader`、`AggLock`、`APVSSAggregate`、`AggRLO` 类型。
- 修改 `core/gate_fastlane.go`：
  - fastlane proposal 前流程改为：`APVSS.Agg -> BuildAggRLO -> AdmitAgg`。
- 新增 `core/apvss_iface_test.go`（TDD）：
  - `TestOptrandAPVSSInterface_RoundTrip`：覆盖统一接口端到端；
  - `TestAggRLO_AdmitAgg`：覆盖 `AggRLO/AdmitAgg` 正向与篡改 digest 负向路径。
- 本轮验证证据：
  - `go test ./core -run 'TestOptrandAPVSSInterface_RoundTrip|TestAggRLO_AdmitAgg|TestOptrand' -count=1` 通过；
  - `go test ./...` 通过（`ok   rladkr_go/core  26.193s`）。

### 2026-05-09（本轮追加：fallback 输入切换为 `digest(AggRLO)`）

- 新增 `core/fallback_aggrlo_codec.go`：
  - `BuildFallbackAggRLOProposal`：从 dealer 集合构建 `APVSS aggregate + AggRLO`，输出 fallback 提案 blob（包含 dealers、agg digest、rlo digest）。
  - `ValidateFallbackAggRLOProposal`：重建并校验提案，要求通过 `AdmitAgg`，并返回 canonical dealer 集合。
- 修改 `core/fallback_dispatch.go`、`core/epoch.go`：
  - `RunFallbackMVBA` 增加 `artifacts` 入参；
  - epoch fallback 路径传入 `artifacts`，确保 fallback 输入可执行 AggRLO 语义校验。
- 修改 `core/fallback_acs.go`（distributed-actor kernel）：
  - proposal 构建从 `BuildDescriptor` 切换到 `BuildFallbackAggRLOProposal`；
  - RBC 消息校验从 `ValidateFallbackDescriptor` 切换到 `ValidateFallbackAggRLOProposal`；
  - per-node 决策 union 阶段同样基于 `ValidateFallbackAggRLOProposal`。
- 修改 `core/fallback_mvba.go`（legacy-sim kernel）：
  - round proposal/leader proposal 构建与校验切换到 AggRLO proposal 编解码；
  - `runFallbackRoundNode` 增加 `artifacts` 入参以支持 `AdmitAgg` 校验路径。
- 修改测试：
  - 新增 `core/fallback_aggrlo_codec_test.go`：
    - `TestFallbackAggRLOProposalBuildAndValidate`
    - `TestFallbackAggRLOProposalRejectsTamper`
  - 更新 `core/fallback_acs_protocol_test.go` fixture 与 `runRBCAll` 调用，适配新入参与新提案格式。
- 本轮验证证据：
  - `go test ./core -run 'TestFallbackAggRLOProposal|TestRunRBCAll_ReturnsErrorWhenRelayBroadcastFails|TestRunEpoch_Fallback' -count=1` 通过；
  - `go test ./...` 通过（`ok   rladkr_go/core  50.487s`）。

### 2026-05-31（本轮：按 `arladkr.md` 新执行流重构 `AgreeAgg` 主线）

- 新增 `core/agreeagg.go`：
  - 定义 `AgreeAggOutput`；
  - 新增显式 `AgreeAgg(ctx, cfg, descriptors, artifacts)`；
  - 新增 `PrepareFallbackState`，先基于 canonical ready-pool 准备一个通过 `AdmitAgg` 的 `AggRLO`；
  - 新增 `buildAggRLOForDealers` 与 `fallbackSeedDealers` 作为 fastlane/fallback 共享对象组装入口。
- 修改 `core/epoch.go`：
  - epoch 主流程从“`RunGateAndFastlane` 成功后直接得到 dealer set，再在 agreement 之后重建 `AggRLO`”改为：
    `AgreeAgg -> RecoverAggFromAggRLO -> RecoverAndDeriveFromAggRLO`；
  - `LockedSet` 现直接来自已确认的 `AggRLO.Header.Dealers`，避免 agreement 后对象语义漂移。
- 修改 `core/recoveragg.go`：
  - 保留原 `RecoverAgg(cfg, lockedSet, artifacts)` 包装接口；
  - 新增 `RecoverAggFromAggRLO(cfg, rlo, artifacts)`，使恢复阶段直接消费 agreement 产出的单对象。
- 修改 `core/gate_fastlane.go`、`core/fallback_mvba.go`、`core/fallback_acs.go`：
  - 提炼 `canonicalReadyCandidates`；
  - fastlane 与 fallback 的初始 dealer 候选现共享同一 ready-pool canonicalization 规则；
  - fallback 起始提案不再独立按 dealer id 重新裁剪，从而与 prepared fallback 的对象语义保持一致。
- 新增 `core/agreeagg_flow_test.go`（TDD）：
  - `TestAgreeAgg_ReturnsFastlaneAggRLO`
  - `TestAgreeAgg_FallbackReturnsCanonicalAggRLO`
  - `TestRunEpoch_BindsRecoverAggToAgreementAggRLO`
- 本轮效果：
  - 执行流更贴近 `arladkr.md` 中的 `Fastlane with Prepared Fallback`；
  - `RunEpoch` 不再在 agreement 之后“重新拼对象”，而是沿着单一 `AggRLO` 继续执行 `RecoverAgg -> Derive`。

### 2026-05-31（本轮追加：开始接入 `LocalNodeIDs` 运行层语义）

- 修改 `core/config.go`：
  - 新增 `Config.LocalNodeIDs`；
  - 新增 `parseLocalNodeIDsEnv` / `filterNodeIDs`；
  - `NormalizeConfig` 现会自动消费 `RLADKR_LOCAL_NODE_IDS`，并按 `OldCommittee` 过滤、去重、排序。
- 修改 `cmd/rladkrbench/main.go`：
  - 新增 `readLocalNodeIDsEnv`；
  - bench 运行时会把 env 中的本地节点集合写入 `core.Config.LocalNodeIDs`。
- 修改 `core/transport_factory.go`、`core/transport_tcp_loopback.go`：
  - transport 构造新增本地节点子集参数；
  - 仅为本地节点集合注册 listener / inbox；
  - 非本地节点仅保留 `RLADKR_NODE_ADDRS` 或 `base-port` 推导出的地址映射。
- 新增测试：
  - `core/local_nodes_test.go`
  - `cmd/rladkrbench/local_nodes_test.go`
- 当前边界说明：
  - 这一步首先打通了 `fabfile.py -> env -> bench -> Config -> transport` 这条链；
  - 但 fallback distributed kernel 仍包含“单进程全节点本地 actor”假设，因此还不能诚实声称“每机只跑本地节点 actor”的真实多机执行已完成；
  - 后续若继续推进，需要把 fastlane/fallback actor 启动与 `CallHelp/RBC/ABA` 消息等待逻辑进一步改成跨进程语义，而不是单进程全节点语义。

### 2026-05-31（本轮追加：fallback distributed kernel 收缩到本地 inbox / 状态面）

- 修改 `core/fallback_acs.go`：
  - 新增对 `localOldNodes(cfg)` 的使用；
  - `runRBCAll` 现在只对本地节点集合执行 `RecvChan` 轮询与本地 `rbcState` 维护；
  - `runBinaryABAForDealer` 现在只对本地节点集合维护 `estimate/decided/chans`；
  - `deriveCommonCoinBit` 的本地 share 聚合与 coin-bit 恢复也收缩到本地节点集合。
- 新增内核级测试：
  - `TestRunRBCAll_LocalNodeSubsetDoesNotRequireRemoteRecvChan`
  - `TestRunBinaryABAForDealer_LocalNodeSubsetDoesNotRequireRemoteRecvChan`
- 本轮效果：
  - fallback distributed kernel 不再把“远端节点也必须在本地注册 inbox”当作前提；
  - 远端节点可以只作为消息发送方存在，本地节点通过网络收到其消息后推进本地 `RBC/ABA` 状态机。
- 当前仍未完成的部分：
  - 还没有补一条真正贴近 `fab + 多进程` 的端到端入口测试；
  - 因此，当前更准确的说法是“fallback distributed kernel 的内核语义已开始适配本地子集节点模式”，而不是“多机端到端运行已全部完成”。

### 2026-06-01（本轮：bench 入口统计口径切到本地子集节点模式）

- 修改 `cmd/rladkrbench/main.go`：
  - 新增 `requiredCompletedNodes`；
  - bench 成功判定不再固定使用 `n-f`，而是优先使用 `LocalNodeIDs` 长度；
  - benchmark 输出新增：
    - `local_node_count`
    - `required_completed_nodes`
- 新增测试：
  - `TestRequiredCompletedNodes_UsesLocalNodeSubsetWhenPresent`
  - `TestRequiredCompletedNodes_NeverExceedsGlobalNodeCount`
  - `TestBenchResultIncludesLocalNodeMetrics`
- 本轮效果：
  - 当 `fab` 或未来多进程编排为某个进程注入 `RLADKR_LOCAL_NODE_IDS=1,3` 时，
    bench 不会再因为“只看到 2 个本地节点输出”而按全局 `n-f` 误判失败；
  - 统计结果里也会显式记录该进程实际负责的本地节点数量与成功阈值，便于后续汇总多进程实验结果。

### 2026-06-01（本轮追加：打通 fallback 的真实多进程本地子集执行）

- 问题现象：
  - 新增的黑盒测试 `cmd/rladkrbench/TestBenchMultiProcessFallbackLocalNodeSubsets` 最初长期失败；
  - 失败模式不是 fastlane，而是 `fallback_policy=force` 下双进程中只有一边成功，另一边最终 `context deadline exceeded`；
  - bench 入口已补 stderr 诊断输出，确认失败发生在 `RunEpoch` 内部，而不是统计口径误判。
- 根因 1：`runRBCAll` 仍按“单进程全节点”语义为所有 sender 本地发起 `RBC_INIT`
  - 这会让某个进程替远端节点伪造起播 `RBC_INIT`；
  - 在真实多进程下会形成非对称的起播顺序与状态推进，导致一侧 fallback 卡死。
- 根因 2：`runBinaryABAForDealer` / `deriveCommonCoinBit` 会提前消费掉“未来阶段消息”
  - 例如远端进程较快时，`ABA_AUX` / `ABA_CONF` / `ABA_COIN_SHARE` 可能先于本地 `EST` 阶段到达；
  - 旧实现会在当前阶段把这些消息从 channel 读走后直接忽略，后续阶段因此永远等不到阈值消息。
- 本轮修改：
  - 修改 `core/fallback_acs.go`
    - `runRBCAll` 启动阶段只允许 `LocalNodeIDs` 发起 `RBC_INIT`；
    - `runBinaryABAForDealer` 新增按本地节点维护的 `pending` phase buffer；
    - `deriveCommonCoinBit` 复用同一 `pending` 语义，保证 `ABA_COIN_SHARE` 不会因提前到达而丢失。
  - 修改 `core/fallback_acs_protocol_test.go`
    - 新增 `TestRunRBCAll_LocalNodeSubsetOnlyInitiatesLocalRBCInit`；
    - 新增 `TestRunBinaryABAForDealer_LocalNodeSubsetBuffersOutOfPhaseMessages`；
    - 两条测试都按 TDD 先失败后修复。
  - 修改 `cmd/rladkrbench/main.go`
    - 新增 `EPOCH_RUN_ERROR` / `EPOCH_RUN_INCOMPLETE` stderr 诊断输出，便于黑盒多进程排查。
- 本轮效果：
  - 双进程 fallback 黑盒已通过：
    - 两个进程都得到 `success_runs=1`；
    - `fallback_runs=1`；
    - `local_node_count=1`；
    - `required_completed_nodes=1`。
  - 双进程 fallback 延迟从此前接近 20s 超时边缘，下降到约 10.47s - 10.48s，且两侧对称。
- 本轮验证证据：
  - `go test ./core -run 'TestRunBinaryABAForDealer_LocalNodeSubsetBuffersOutOfPhaseMessages|TestRunRBCAll_LocalNodeSubsetOnlyInitiatesLocalRBCInit' -count=1` 通过；
  - `go test ./cmd/rladkrbench -run 'TestBenchMultiProcessFallbackLocalNodeSubsets' -count=1 -v` 通过；
  - `go test ./... -count=1` 通过；
  - `python3 -m unittest tests.test_fabfile_aws` 通过。

### 2026-06-01（本轮追加：`fabfile.py` 开始生成每 host 独立的 `LocalNodeIDs`）

- 问题现象：
  - 虽然协议内核已经支持 `RLADKR_LOCAL_NODE_IDS`；
  - 但 `fabfile.py` 的 `_remote_env_lines` 仍会在 `-n 4` 这类 bench 覆盖下，把 `RLADKR_LOCAL_NODE_IDS=0,1,2,3` 发给所有 host；
  - 同时还会把 `RLADKR_NODE_ADDRS` 错误渲染成“所有节点都在当前 host 上”，与真实多机拓扑不符。
- 本轮修改：
  - 修改 `[fabfile.py](/home/yzc/project/RLADKR/fabfile.py)`
    - 新增 `_host_local_node_ids(cfg, host, node_count)`；
    - `rladkr-go` / `arladkr` 的远端 env 生成现按 resolved inventory 中的 `node.id -> ip` 映射，为每个 host 单独分配 `RLADKR_LOCAL_NODE_IDS`；
    - `-base-port` 覆盖场景下，`RLADKR_NODE_ADDRS` 改为保留全局 host 分布，只覆盖端口。
  - 修改 `[test_fabfile_aws.py](/home/yzc/project/RLADKR/tests/test_fabfile_aws.py)`
    - 新增 `test_remote_env_lines_assign_local_node_subset_per_host`。
- 本轮效果：
  - 当 4 个逻辑节点分布在 2 台机器上时：
    - `10.0.0.10 -> RLADKR_LOCAL_NODE_IDS=0,1`
    - `10.0.1.10 -> RLADKR_LOCAL_NODE_IDS=2,3`
  - `RLADKR_NODE_ADDRS` 仍保持：
    - `0=10.0.0.10:42010,1=10.0.0.10:42011,2=10.0.1.10:42012,3=10.0.1.10:42013`
  - 这使 `fab aws-run-bench --project=arladkr` 在 env 语义上终于与前面完成的多进程协议内核对齐。
- 本轮验证证据：
  - `python3 -m unittest tests.test_fabfile_aws.FabfileAWSTest.test_remote_env_lines_assign_local_node_subset_per_host` 通过；
  - `python3 -m unittest tests.test_fabfile_aws.FabfileAWSTest.test_aws_run_bench_prints_arladkr_command tests.test_fabfile_aws.FabfileAWSTest.test_remote_env_lines_respect_bench_arg_node_count_and_base_port` 通过。

### 2026-06-01（本轮追加：`aws_run_bench` 改为“先异步拉起，再统一等待”）

- 问题现象：
  - 旧版 `fab aws-run-bench` 会按 host 串行执行；
  - 对真实分布式协议 bench 来说，这意味着第一台机器已经在跑甚至接近结束时，后一台才刚开始，语义上不对。
- 本轮修改：
  - 修改 `[fabfile.py](/home/yzc/project/RLADKR/fabfile.py)`
    - 新增 `_bench_run_id()`；
    - 新增 `_remote_status_paths()`；
    - 新增 `_remote_wait_command()`；
    - `_remote_bench_command()` 支持：
      - `run_id`
      - `wait=False`
    - 远端 bench 改为异步 `nohup bash -lc ... &`；
    - 每轮 bench 会写：
      - `${project}.bench.<run_id>.txt`
      - `${project}.status.<run_id>`
      - `${project}.last_run_id`
    - `aws_run_bench` 现改为两阶段：
      - 先对所有 host 执行 launch
      - 再对所有 host 执行 wait
  - 修改 `[test_fabfile_aws.py](/home/yzc/project/RLADKR/tests/test_fabfile_aws.py)`
    - 新增 `test_remote_bench_command_writes_run_scoped_status_and_bench_files`
    - 新增 `test_aws_run_bench_dry_run_prints_launch_and_wait_commands`
- 本轮效果：
  - `fab` 层终于不再按 host 串行启动协议；
  - 更接近真实多机协议实验的“共同启动 + 独立完成 + 统一等待”语义；
  - 后续 `aws_collect` / 结果汇总也有了稳定的 `run_id` 落点。
- 本轮验证证据：
  - `python3 -m unittest tests.test_fabfile_aws.FabfileAWSTest.test_remote_bench_command_writes_run_scoped_status_and_bench_files tests.test_fabfile_aws.FabfileAWSTest.test_aws_run_bench_dry_run_prints_launch_and_wait_commands` 通过；
  - `python3 -m unittest tests.test_fabfile_aws` 全绿（15 tests）。

### 2026-06-01（本轮追加：`aws_collect` 生成 run-aware 本地摘要）

- 问题现象：
  - `aws_collect` 之前虽然会把文件拉回来；
  - 但 collect 完成后，本地没有一份结构化摘要来说明“每台 host 最近一次 bench/status 到底在哪里、是否存在”。
- 本轮修改：
  - 修改 `[fabfile.py](/home/yzc/project/RLADKR/fabfile.py)`
    - 新增 `_read_text_if_exists()`；
    - 新增 `_write_collect_summary()`；
    - `aws_collect` 结束后自动生成 `summary.json`；
    - `manifest.json` 新增 `latest_run_id_file` 字段。
  - 修改 `[test_fabfile_aws.py](/home/yzc/project/RLADKR/tests/test_fabfile_aws.py)`
    - 扩展 `test_aws_collect_writes_manifest`
    - 新增 `test_aws_collect_writes_summary_json`
- 本轮效果：
  - collect 目录现在至少包含：
    - `manifest.json`
    - `summary.json`
    - 每 host 子目录
  - `summary.json` 会按 host 汇总：
    - `latest_status_path`
    - `latest_bench_path`
    - `bench_exists`
    - `journal_exists`
  - 后续再做真正的多轮统计汇总时，就有了一个稳定的摘要入口。
- 本轮验证证据：
  - `python3 -m unittest tests.test_fabfile_aws.FabfileAWSTest.test_aws_collect_writes_manifest tests.test_fabfile_aws.FabfileAWSTest.test_aws_collect_writes_summary_json` 通过；
  - `python3 -m unittest tests.test_fabfile_aws` 全绿（16 tests）。

### 2026-06-01（本轮追加：补统一启动栅栏、`run_id` 定向 collect 与结果解析）

- 问题现象：
  - 虽然 `aws_run_bench` 已支持“先 launch 再 wait”；
  - 但各 host 真正开始协议前仍缺一个统一起跑栅栏；
  - 同时 `aws_collect` 还不能显式收集某个 `run_id`，`summary.json` 也还没有解析 bench 结果字段。
- 本轮修改：
  - 修改 `[fabfile.py](/home/yzc/project/RLADKR/fabfile.py)`
    - 新增 `_parse_bench_result_line()`；
    - `bench` 启动前现在会先写 `${project}.ready.<run_id>`；
    - 只有等所有 host 的 ready 文件数达到目标值后，才真正开始协议执行；
    - `aws_collect` 新增 `run_id` 参数；
    - `_remote_collect_commands_for_run()` 支持按指定 `run_id` 拉取对应 bench/status 路径；
    - `summary.json` 新增 `bench_result` 字段。
  - 修改 `[test_fabfile_aws.py](/home/yzc/project/RLADKR/tests/test_fabfile_aws.py)`
    - 新增 `test_remote_bench_command_includes_start_barrier`
    - 新增 `test_aws_collect_supports_explicit_run_id`
    - 新增 `test_collect_summary_parses_bench_result_line`
- 本轮效果：
  - `aws_run_bench` 已具备：
    - host 子集 env
    - 异步 launch
    - 统一 wait
    - 统一启动栅栏
  - `aws_collect` 已具备：
    - 默认 latest collect
    - 指定 `run_id` collect
    - `manifest.json`
    - `summary.json`
    - `bench_result` 解析
- 本轮验证证据：
  - `python3 -m unittest tests.test_fabfile_aws.FabfileAWSTest.test_remote_bench_command_includes_start_barrier tests.test_fabfile_aws.FabfileAWSTest.test_aws_collect_supports_explicit_run_id tests.test_fabfile_aws.FabfileAWSTest.test_collect_summary_parses_bench_result_line` 通过；
  - `python3 -m unittest tests.test_fabfile_aws` 全绿（19 tests）。

### 2026-05-31（本轮：对齐 `arladkr.md` 与 `fabfile.py` 的 bench/部署契约，并新增专项追踪文档）

- 新增专项追踪文档：
  - `ARLADKR_FAB_SYNC_TRACKING.md`
  - 用于专门追踪：
    - `arladkr.md` 对象语义落地状态；
    - `fabfile.py` / `deployment/config.yaml` 与 `arladkr` bench 的契约一致性；
    - 当前从“单机全节点仿真”到“多机每节点执行”的缺口。
- 更新 `tests/test_fabfile_aws.py`：
  - 新增 `test_arladkr_project_uses_bench_and_env_contract`
  - 新增 `test_aws_run_bench_prints_arladkr_command`
  - 锁定 `arladkr` 项目在 `fabfile.py` 中的约定：
    - `path=arladkr`
    - `bench_cmd=go run ./cmd/rladkrbench`
    - 仍消费 `RLADKR_NODE_ADDRS / RLADKR_LOCAL_NODE_IDS`
- 本轮审计结论：
  - `arladkr/core` 已具备：
    - `AggHeader`
    - `AggLock`
    - `APVSSAggregate`
    - `AggRLO`
    - `AdmitAgg`
    - `RecoverAgg`
  - `RunEpoch` 已输出：
    - `AggRLODealers`
    - `RecoveredAggregate`
    - `AggRLODigest`
    - `AggRLOReadyLatency`
    - `AdmitAggAttempts`
    - `AdmitAggPasses`
    - `RecoverAggSuccess`
  - `arladkrbench` 已输出 ARLADKR 专属指标：
    - `mean_aggrlo_ready_ms`
    - `admitagg_pass_ratio`
    - `recoveragg_success_ratio`
- 仍然存在的真实缺口：
  - `arladkr/go.mod` 仍使用 `module rladkr_go`，尚未做工程命名分离；
  - bench 当前仍是“单进程全节点仿真”，并未读取 `RLADKR_LOCAL_NODE_IDS` 进入“每机子集节点”执行语义；
  - 因此，当前 `fab aws-run-bench --project=arladkr` 在语义上仍是“远端单机全节点仿真”，不是“多机真实私网协议执行”。
- 本轮目标是先把“文档 + 契约 + 可验证状态”补齐，不贸然重写多机执行内核。

### 2026-05-09（本轮追加：执行下一步 M4 首段，接入 `RecoverAgg` 单对象恢复）

- 新增 `core/recoveragg.go`：
  - `RecoverAgg(cfg, lockedSet, artifacts)`：
    - 基于统一 APVSS 接口构建单聚合对象；
    - 执行 `BuildAggRLO + AdmitAgg`；
    - 执行 `APVSS.Rec` 得到单对象恢复材料。
  - 输出 `RecoverAggOutput{AggRLO, Recovered}`，供 epoch 主流程消费。
- 扩展 `core/types.go` 的 `EpochResult`：
  - 新增 `AggRLODigest []byte`
  - 新增 `RecoveredAggregate []byte`
- 修改 `core/epoch.go`：
  - 在 `RecoverAndDerive` 之前增加 `RecoverAgg` 阶段；
  - 将 `AggRLODigest` 与 `RecoveredAggregate` 写入 epoch 输出；
  - 保持既有 `RecoverAndDerive` 与旧测试口径兼容（渐进迁移）。
- 新增测试 `core/recoveragg_test.go`（TDD）：
  - `TestRecoverAgg_BuildsSingleAggregateObject`
  - `TestRunEpoch_ExposeRecoverAggOutputs`
- 本轮验证证据：
  - `go test ./core -run 'TestRecoverAgg_BuildsSingleAggregateObject|TestRunEpoch_ExposeRecoverAggOutputs' -count=1` 通过；
  - `go test ./...` 通过（`ok   rladkr_go/core  54.148s`）。

### 2026-05-09（本轮追加：`Derive` 切换为消费 `RecoverAgg` 输出）

- 修改 `core/recover_derive.go`：
  - 新增 `RecoverAndDeriveFromAggRLO(cfg, recoverOut, artifacts)`；
  - 由 `recoverOut.AggRLO.Header.Dealers` 驱动派生，明确形成 `RecoverAgg -> Derive` 链路。
- 修改 `core/types.go`：
  - `EpochResult` 新增 `AggRLODealers []int`，用于暴露 RecoverAgg 阶段的单对象 dealer 集合。
- 修改 `core/epoch.go`：
  - 主流程从 `RecoverAndDerive(cfg, lockedSet, artifacts)` 改为 `RecoverAndDeriveFromAggRLO(cfg, recoverAggOut, artifacts)`；
  - 输出中填充 `AggRLODealers`。
- 修改测试 `core/recoveragg_test.go`（TDD）：
  - 扩展 `TestRunEpoch_ExposeRecoverAggOutputs`，校验 `AggRLODealers` 输出；
  - 新增 `TestRecoverAndDeriveFromAggRLO`，校验 sampled dealer 属于 `AggRLO` dealer 集合。
- 本轮验证证据：
  - `go test ./core -run 'TestRunEpoch_ExposeRecoverAggOutputs|TestRecoverAndDeriveFromAggRLO' -count=1` 通过；
  - `go test ./...` 通过（`ok   rladkr_go/core  53.131s`）。

### 2026-05-09（本轮追加：`RecoverAgg -> Derive` 绑定校验增强）

- 修改 `core/recover_derive.go` 的 `RecoverAndDeriveFromAggRLO`：
  - 新增 APVSS 绑定重算链：
    1. 用 `AggRLO.Header.Dealers` 重新执行 `APVSS.Agg`；
    2. 校验重算 `AggregateDigest` 与 `AggRLO.Header.AggregateDigest` 一致；
    3. 重新执行 `APVSS.Rec`；
    4. 校验重算 `RecoveredMaterial` 与 `recoverOut.Recovered.RecoveredMaterial` 一致；
  - 绑定校验通过后再进入 `RecoverAndDerive`。
- 测试（TDD）：
  - 在 `core/recoveragg_test.go` 新增：
    - `TestRecoverAndDeriveFromAggRLO_RejectsRecoveredMaterialTamper`
  - 该测试先红（未校验时可被篡改通过），实现后转绿。
- 本轮验证证据：
  - `go test ./core -run 'TestRecoverAndDeriveFromAggRLO_RejectsRecoveredMaterialTamper|TestRecoverAndDeriveFromAggRLO|TestRecoverAgg_BuildsSingleAggregateObject' -count=1` 通过；
  - `go test ./...` 通过（`ok   rladkr_go/core  54.349s`）。

### 2026-05-09（本轮追加：完成 M6 基准指标闭环并接入 epoch 级统计）

- 新增 epoch 指标暴露（`core/types.go`）：
  - `AggRLOReadyLatency time.Duration`
  - `AdmitAggAttempts int`
  - `AdmitAggPasses int`
  - `RecoverAggSuccess bool`
- 新增 AdmitAgg 统计器（`core/crypto_runtime.go` + `core/aggrlo.go`）：
  - 在运行时记录 `AdmitAgg` 尝试次数/通过次数；
  - 采用互斥保护，兼容 distributed fallback 并发校验路径。
- 增强 `RecoverAgg` 输出（`core/recoveragg.go`）：
  - 增加 `AggRLOReadyLatency`（从 RecoverAgg 开始到 `AdmitAgg` 通过的阶段时延）。
- 修改 `RunEpoch` 输出（`core/epoch.go`）：
  - 汇总并返回 `AdmitAggAttempts/Passes`；
  - 返回 `AggRLOReadyLatency` 与 `RecoverAggSuccess=true`（成功路径）。
- 修改基准程序（`cmd/rladkrbench/main.go`）：
  - 协议标识更新为 `ARLADKR-GO`；
  - 新增输出字段：
    - `mean_aggrlo_ready_ms`
    - `admitagg_pass_ratio`
    - `recoveragg_success_ratio`
  - 抽出 `formatBenchResult` 与比例计算函数，便于单测。
- 新增/更新测试（TDD）：
  - 新增 `cmd/rladkrbench/main_test.go`：
    - `TestAdmitAggPassRatio`
    - `TestFormatBenchResultIncludesARLADKRMetrics`
  - 更新 `core/recoveragg_test.go`：
    - `TestRunEpoch_ExposeRecoverAggOutputs` 增补新指标断言。
- 本轮验证证据：
  - `go test ./cmd/rladkrbench ./core -run 'TestAdmitAggPassRatio|TestFormatBenchResultIncludesARLADKRMetrics|TestRunEpoch_ExposeRecoverAggOutputs' -count=1` 通过；
  - `go test ./... -count=1` 通过（`ok   rladkr_go/cmd/rladkrbench  0.017s`，`ok   rladkr_go/core  56.863s`）。

### 2026-06-29（本轮追加：本地 `n=127` baseline 复核与 LockAgg / fallback 复用优化）

背景：

- 当前工作重点已经从 `Practical ADKR` 切到 `ARL-ADKR`。
- 本地比较环境保持为单机 `proc-sim`，并沿用：
  - `n=127`
  - `f=42`
  - internal delay `50-100ms`
  - `fallback-policy=force`
- 这轮先不继续做论文级新机制研究，而是把当前工程实现收敛到一个更合理的本地最优版。

本轮先确认的 baseline：

- 重新构建 `bin/rladkrbench` 后，当前有效 baseline 为：
  - out dir: `/tmp/arladkr-internal50-100-newbin-n127`
  - `127/127` success
  - `mean_latency_ms = 222431.32`
  - `mean_online_protocol_ms = 114988.50`
  - `lockagg_ms = 25125.52`
  - `mvba_only_ms = 75723.59`
  - `agreeagg_ms = 100849.23`
  - `recover_ms = 176.76`

这组数据的直接结论：

- 当前 `RecoverAgg` 已经不是 ARL 的主要瓶颈。
- online 大头集中在：
  - `LockAgg`
  - fallback `MVBA`
- 其中 `agreeagg_ms` 本质上是：
  - `LockAgg + MVBA-only`

本轮新增工程优化：

1. fallback proposal runtime cache

- 已把 fallback `AggRLO` proposal blob 放入 runtime cache，避免同一 dealer 集被重复编码/重建。

2. locally-constructed `AggRLO` admit short-circuit

- 对本地刚构造且已验证过的 `AggRLO`，允许在严格指纹命中时跳过重复本地验证。

3. aggregate / AggRLO build cache

- 新增 runtime 级 dealer-set cache：
  - 缓存 `APVSSAggregate`
  - 缓存 `AggRLO`
- 目标是避免同一组 dealers 在这些路径中被重复构建：
  - `LockAgg`
  - fallback proposal build / validate
  - recover path rebuild

4. recover 直接复用 agreed `AggRLO.Aggregate`

- `RecoverAggFromAggRLO(...)` 不再重新调用 `Agg(...)` 重建同一 aggregate。
- 对 `optrand` 直接复用已绑定 aggregate 进入 recover/materialize。

已完成验证：

- `go build -o /home/RLADKR/arladkr/bin/rladkrbench ./cmd/rladkrbench`
- `go test ./core -run 'Test(FallbackAggRLOProposalBuildAndValidate|FallbackAggRLOProposalRejectsTamper|AgreeAgg_FallbackReturnsCanonicalAggRLO|RunEpoch_BindsRecoverAggToAgreementAggRLO|RunEpoch_FallbackMVBA)$' -count=1`

状态判断：

- 当前 ARL 的真实问题不像 `Practical` 那样集中在 recover timeout。
- 经过这一轮清理后，更明确的工程热点是：
  - `LockAgg` 的 aggregate/object 构建
  - fallback `MVBA` 的 `common subset / eq` 阶段
- 本轮新的 `n=127` benchmark 已完成：
  - out dir: `/tmp/arladkr-internal50-100-opt2-n127`
  - `127/127` success
  - `mean_latency_ms = 218137.48`
  - `mean_online_protocol_ms = 113521.33`
  - `lockagg_ms = 24196.86`
  - `mvba_only_ms = 77086.84`
  - `agreeagg_ms = 101283.69`
  - `recover_ms = 207.50`

与 rebuilt baseline `/tmp/arladkr-internal50-100-newbin-n127` 对比：

- `mean_latency_ms`: `222431.32 -> 218137.48`
- `mean_online_protocol_ms`: `114988.50 -> 113521.33`
- `lockagg_ms`: `25125.52 -> 24196.86`
- `mvba_only_ms`: `75723.59 -> 77086.84`

解释：

- aggregate / `AggRLO` 复用确实对 `LockAgg` 有帮助；
- 但 fallback `MVBA` 仍然主导 online latency，且其波动幅度足以吞掉部分 `LockAgg` 收益；
- 因此这轮优化值得保留，但它还不是 ARL 本地 `n=127` 的主要突破口。
