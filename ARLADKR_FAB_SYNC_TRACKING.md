# ARLADKR 与 Fabric/Bench 对接追踪

更新时间：2026-05-31

## 1. 目的

本文件用于专门追踪 `ARLADKR` 当前协议实现与仓库级部署/基准入口之间的对接状态，重点覆盖：

- `arladkr.md` 中对象语义是否已经落到代码；
- `fabfile.py` 中 `arladkr` 项目条目与实际 bench 契约是否一致；
- 当前哪些能力已经可被 `fab aws-run-bench` / `export-env` 直接消费；
- 哪些能力仍然停留在“单机全节点仿真”，尚未进入真实多机每节点执行模式。

## 2. 输入来源

- 协议思路文档：`/home/yzc/project/RLADKR/arladkr.md`
- 现有协议实现：`/home/yzc/project/RLADKR/arladkr`
- 部署与 bench 入口：`/home/yzc/project/RLADKR/fabfile.py`
- 基线部署配置：`/home/yzc/project/RLADKR/deployment/config.yaml`
- 历史维护文档：`/home/yzc/project/RLADKR/arladkr/ARLADKR_GO_IMPLEMENTATION.md`

## 3. 当前已对齐项

### 3.1 协议对象层

当前 `arladkr/core` 已具备下列对象和语义：

- `AggHeader`
- `AggLock`
- `APVSSAggregate`
- `AggRLO`
- `AdmitAgg`
- `RecoverAgg`

并且 `RunEpoch` 已输出：

- `AggRLODealers`
- `RecoveredAggregate`
- `AggRLODigest`
- `AggRLOReadyLatency`
- `AdmitAggAttempts`
- `AdmitAggPasses`
- `RecoverAggSuccess`

这说明 `arladkr.md` 主张的 `LockAgg -> AgreeAgg -> RecoverAgg -> Derive` 主线，已经在对象层和 epoch 结果层形成了明确投影。

补充对齐状态（2026-05-31）：

- 已新增显式 `AgreeAgg` 入口，统一承接 `Fastlane + Prepared Fallback`；
- `PrepareFallbackState` 会先从 canonical ready-pool 构造一个可通过 `AdmitAgg` 的 `AggRLO`；
- `RunEpoch` 现已改为直接消费 `AgreeAgg` 输出的 `AggRLO`，不再在 agreement 之后根据 `lockedSet` 重新构造一遍聚合对象；
- `RecoverAgg` 已补 `RecoverAggFromAggRLO` 入口，使 `RecoverAgg -> Derive` 链路直接绑定到 agreement 确认的单对象。
- `Config.LocalNodeIDs` / `RLADKR_LOCAL_NODE_IDS` 已开始接入运行层：
  - bench 会读取该环境变量；
  - transport 仅为本地节点集合注册 listener / inbox；
  - fastlane 本地结果输出也已收缩到本地节点集合。
 - fallback distributed kernel 已进一步改为：
   - `RBC` 只为本地节点维护接收状态与 `RecvChan` 轮询；
   - `ABA/common coin` 只为本地节点维护本地 inbox / estimate / decision / coin recovery 状态；
   - 远端节点仍可作为广播发送方参与，但不再要求本地为其注册 `RecvChan`。

### 3.2 bench 层

当前 `arladkr/cmd/rladkrbench/main.go` 已输出 ARLADKR 特有指标：

- `mean_aggrlo_ready_ms`
- `admitagg_pass_ratio`
- `recoveragg_success_ratio`
- `local_node_count`
- `required_completed_nodes`

并维持与 `fabfile.py` 中现有项目约定兼容：

- bench 命令仍为 `go run ./cmd/rladkrbench`
- 环境变量仍消费：
  - `RLADKR_NODE_ADDRS`
  - `RLADKR_LOCAL_NODE_IDS`
  - `RLADKR_DIAL_HOST`

因此，`fab aws-run-bench --project=arladkr` 在命令拼装层是成立的。

### 3.3 Fabric 项目条目

`deployment/config.yaml` 当前为 `arladkr` 保持了独立项目项：

- `path: arladkr`
- `bench_cmd: go run ./cmd/rladkrbench`
- `env.RLADKR_NODE_ADDRS`
- `env.RLADKR_LOCAL_NODE_IDS`

这意味着：

- `export-env --project=arladkr`
- `aws-run-bench --project=arladkr`

在接口契约上与 `rladkr-go` 已对齐。

## 4. 当前未对齐项 / 真实缺口

### 4.1 模块命名未分离

`arladkr/go.mod` 当前仍然是：

```go
module rladkr_go
```

且 `arladkr/cmd/rladkrbench/main.go` 仍然 import：

```go
import "rladkr_go/core"
```

这虽然在独立目录下可工作，但会带来两个问题：

- 工具链日志无法清晰区分 RLADKR 与 ARLADKR；
- 后续若需要把两个项目同时作为依赖或组合测试目标，会增加辨识和维护成本。

当前策略：先不做大范围模块重命名，避免把稳定实现面整体打乱；仅在文档中明确这是一个待处理工程债。

### 4.2 仍然是“单进程全节点仿真”而非“多机每节点执行”

当前 `arladkrbench` 与 `rladkr-go` 一样，仍然是在一个进程内直接构造：

- `OldCommittee = [0..n-1]`
- `NewCommittee = [0..n-1]`
- 调用一次 `core.RunEpoch(...)`

协议内部虽然使用 TCP transport，但仍然是**单进程驱动所有节点 actor**。

因此：

- `fab aws-run-bench --project=arladkr`
  当前含义是“在某台机器上运行一个带 TCP transport 的本地全节点仿真 bench”，
  而不是“4 台机器分别运行自己的节点副本并通过私网互联完成协议”。

这也是当前从 `fabfile.py` 进入真实分布式执行时的最大语义缺口。

### 4.3 `RLADKR_LOCAL_NODE_IDS` 尚未进入协议运行语义

虽然 `fabfile.py` 和 `deployment/config.yaml` 会生成 `RLADKR_LOCAL_NODE_IDS`，
但当前 `arladkr` 运行路径仍未完整读取该环境变量来决定：

- 本机只负责哪些 node id；
- 是否只监听本机所属节点；
- 是否在多机场景中跳过其他节点的本地 actor 启动。

当前状态更新：

- “只监听本机所属节点” 已实现；
- `bench -> Config` 的 env 传递已实现；
- fallback distributed kernel 的本地 inbox / 状态面已收缩到 `LocalNodeIDs`；
- 双进程本地子集黑盒 bench 已补齐并通过：
  - `TestBenchMultiProcessFastlaneLocalNodeSubsets`
  - `TestBenchMultiProcessFallbackLocalNodeSubsets`
- 其中 fallback 路径还额外修复了两类真实多进程问题：
  - `RBC_INIT` 只能由本地节点发起，不能替远端 sender 本地伪造起播；
  - `ABA/coin` 对未来阶段消息增加了 phase buffer，避免提前到达的 `AUX/CONF/COIN_SHARE` 被错误丢弃。
- 因此，“单机多进程、每进程只跑本地节点子集”的协议语义现已闭环；
- 仍未完成的是 `fab` 层面的远端多机进程编排，而不是协议内核本身。

## 5. 本轮修改（2026-05-31）

本轮目标不是重写多机执行内核，而是先把 `arladkr` 与 `fabfile.py` 的现状对齐并形成可追踪状态。

完成项：

1. 为 `tests/test_fabfile_aws.py` 增加 `arladkr` 项目契约测试：
   - `arladkr` 项目 path / bench_cmd 是否正确；
   - dry-run 的 `aws-run-bench --project=arladkr` 是否会输出正确命令与 env。
2. 新建本追踪文档，明确：
   - 已对齐项；
   - 未对齐项；
   - 下一步真实分布式执行缺口。
3. 根据 `arladkr.md` 新执行流补齐协议主线：
   - 新增 `core/agreeagg.go`，将 `Fastlane` 与 `Prepared Fallback` 统一为 `AgreeAgg`；
   - fastlane/fallback 的初始 dealer 候选改为共享同一 canonical ready-pool 选择逻辑；
   - `RunEpoch` 改为 `AgreeAgg -> RecoverAggFromAggRLO -> RecoverAndDeriveFromAggRLO`，消除 agreement 后重建对象的旧路径。
4. 开始接入 `LocalNodeIDs` 运行层语义：
   - `core/config.go` 增加 `LocalNodeIDs` 与 `RLADKR_LOCAL_NODE_IDS` 解析；
   - `cmd/rladkrbench/main.go` 增加 env 读取并传入 `core.Config`；
   - `core/transport_tcp_loopback.go` 改为只为本地节点注册 listener/inbox，远端节点仅保留地址映射。
5. 继续把 `LocalNodeIDs` 推入 fallback distributed kernel：
   - `core/fallback_acs.go` 中 `runRBCAll` 与 `runBinaryABAForDealer` 不再对远端节点调用 `RecvChan`；
   - 新增内核级测试，验证本地子集模式下无需远端 inbox 即可处理远端注入消息。
6. 补 bench 入口统计口径：
   - bench 成功阈值改为优先使用 `LocalNodeIDs` 长度；
   - 新增 `local_node_count` 与 `required_completed_nodes` 输出字段，避免多进程实验时把“本进程只跑部分节点”误判为失败。
7. 补真实双进程 fallback 黑盒与协议修复：
   - 新增 `cmd/rladkrbench/multiprocess_test.go` 中的 fastlane/fallback 双进程回归；
   - `core/fallback_acs.go` 中：
     - `runRBCAll` 仅允许本地节点发起 `RBC_INIT`；
     - `runBinaryABAForDealer` / `deriveCommonCoinBit` 增加 phase buffer；
   - `cmd/rladkrbench/main.go` 增加 stderr 级 `EPOCH_RUN_ERROR` 诊断，便于后续 `fab` 远端收集。
8. 补 `fabfile.py` 的 host -> local-node 子集映射：
   - `aws_run_bench` 相关 env 生成不再把同一份 `RLADKR_LOCAL_NODE_IDS` 发给所有 host；
   - 现在会根据 resolved inventory 中的 `node.id -> ip` 映射，为每个 host 计算自己的本地节点子集；
   - 同时修复 `bench_args` 覆盖 `-base-port` 时的 `RLADKR_NODE_ADDRS`，保持全局拓扑地址不被错误替换成“当前 host 全占”。
9. 补 `aws_run_bench` 的异步拉起与 run-scoped 状态文件：
   - bench 现在会生成 `launch-run-id=<...>`；
   - 每台 host 先异步 `nohup` 拉起自己的 bench，再统一进入 wait 阶段；
   - 远端会写：
     - `${project}.bench.<run_id>.txt`
     - `${project}.status.<run_id>`
     - `${project}.last_run_id`
   - 这样 `fab` 层终于不再是“逐台同步串行跑 bench”，而是更接近真实分布式实验的“先共同启动，再等待全部完成”。
10. 补 `aws_collect` 的 run-aware 收集摘要：
   - `manifest.json` 现在会记录 `latest_run_id_file`；
   - `aws_collect` 在拉取结束后会生成 `summary.json`；
   - `summary.json` 会按 host 汇总：
     - `latest_status_path`
     - `latest_bench_path`
     - `bench_exists`
     - `journal_exists`
   - 这让一次 collect 之后，至少能快速看出每台 host 最近一次 bench/status 文件是否存在，而不必手工翻目录。
11. 补统一启动栅栏、`run_id` 定向 collect 与 bench 结果解析：
   - bench 启动前现在会先写 `${project}.ready.<run_id>`，并等待所有 host 的 ready 文件数达到目标值后再真正开始协议；
   - `aws_collect` 新增 `run_id` 参数，可显式收集指定轮次的 `bench/status` 文件；
   - `summary.json` 现在会额外解析 `bench.txt` 中的 `E2E_BENCH_RESULT`，生成 `bench_result` 结构化字段。

## 6. 下一步建议

### P1：补 `arladkrbench` 的“每机子集节点”运行模式

目标：

- 读取 `RLADKR_LOCAL_NODE_IDS`
- 仅为这些 node id 启动本地 actor / listener
- 其余节点只作为远端地址存在于 `RLADKR_NODE_ADDRS`

状态更新：

- listener / env 读取已完成；
- fastlane / fallback distributed kernel 的本地 inbox / 状态面已开始收缩；
- bench 统计口径也已适配本地子集节点模式；
- 本地双进程端到端入口测试已补齐并通过；
- `fabfile.py` 也已能为不同 host 生成不同的 `RLADKR_LOCAL_NODE_IDS`；
- `aws_run_bench` 的“先拉起后等待”也已补齐；
- 统一启动栅栏也已补齐；
- `aws_collect(run_id=...)` 也已补齐；
- 当前真正还没做的只剩：
  - 更强的健康检查与失败重试策略；
  - 多轮实验结果自动聚合与跨 run 对比报表；
  - 真正上 AWS 的实机验证。

### P2：为 `RunEpoch` 增加节点子集执行入口

建议新增类似配置：

- `LocalNodeIDs []int`

使 `AgreeAgg` / `RunGateAndFastlane` / `RunFallbackMVBA` 只为本机节点集合创建 goroutine 和 listener。

### P3：等多机执行语义稳定后，再考虑模块重命名

届时可将：

- `arladkr/go.mod`

从 `module rladkr_go` 调整为更独立的模块名，以减少长期混淆。

## 7. 本轮验证

已完成验证：

- `cd /home/yzc/project/RLADKR/arladkr && go test ./... -count=1`
- `python3 -m unittest tests.test_fabfile_aws`

补充验证：

- `cd /home/yzc/project/RLADKR/arladkr && go test ./cmd/rladkrbench -run 'TestBenchMultiProcessFastlaneLocalNodeSubsets|TestBenchMultiProcessFallbackLocalNodeSubsets' -count=1 -v`
- `cd /home/yzc/project/RLADKR && python3 -m unittest tests.test_fabfile_aws.FabfileAWSTest.test_remote_env_lines_assign_local_node_subset_per_host`
- `cd /home/yzc/project/RLADKR && python3 -m unittest tests.test_fabfile_aws.FabfileAWSTest.test_remote_bench_command_writes_run_scoped_status_and_bench_files tests.test_fabfile_aws.FabfileAWSTest.test_aws_run_bench_dry_run_prints_launch_and_wait_commands`
- `cd /home/yzc/project/RLADKR && python3 -m unittest tests.test_fabfile_aws.FabfileAWSTest.test_aws_collect_writes_manifest tests.test_fabfile_aws.FabfileAWSTest.test_aws_collect_writes_summary_json`
- `cd /home/yzc/project/RLADKR && python3 -m unittest tests.test_fabfile_aws.FabfileAWSTest.test_remote_bench_command_includes_start_barrier tests.test_fabfile_aws.FabfileAWSTest.test_aws_collect_supports_explicit_run_id tests.test_fabfile_aws.FabfileAWSTest.test_collect_summary_parses_bench_result_line`

## 8. AWS 镜像更新记录（2026-06-01）

本轮针对“旧 AMI 内 `arladkr` 仍为旧版”的问题，完成了以下收口：

1. 使用当前临时更新机 `i-0af82e6329f268263` / `44.199.243.5` 重新执行：
   - `AWS_PROFILE=rladkr fab aws-up --project=arladkr`
   - 确认本地 `arladkr` 已同步到远端 `/opt/rladkr/arladkr`。
2. 对比关键源码哈希，确认远端与本地一致：
   - `cmd/rladkrbench/main.go`
   - `core/agreeagg.go`
   - `core/fallback_acs.go`
   - `core/transport_tcp_loopback.go`
   - `core/config.go`
3. 在实例上用显式 `/usr/local/go/bin/go` 复跑 ARLADKR 本地子集多进程 bench 测试：
   - `go test ./cmd/rladkrbench -run 'TestBenchMultiProcessFastlaneLocalNodeSubsets|TestBenchMultiProcessFallbackLocalNodeSubsets' -count=1`
   - 通过。
4. 修复并固化 AWS bootstrap 缺口：
   - `fabfile.py::_remote_bootstrap_command` 现会主动创建并 `chown`：
     - `/home/ubuntu/.cache/go-build`
     - `/home/ubuntu/go/pkg/mod`
   - 避免旧镜像残留的 root-owned Go cache/mod 目录导致 bench/test 权限失败。
5. 修复 `aws-create-image` 在 `management: ssh` + `static_ips` 场景下无法拿到 `instance_id` 的问题：
   - 保持 `_aws_host_targets` 在普通 SSH dry-run 路径不依赖 AWS 查询；
   - 新增按需实例反查逻辑，仅供 `aws-create-image` 使用。
6. 基于该临时实例创建新 AMI：
   - `ami-05ac5dfccbed66509`
   - 名称：`rladkr-bench-arladkr-20260601`
   - 当前状态：`available`
   - `deployment/config.yaml` 已更新为新的 `aws.instance.ami`。

补充验证：

- `cd /home/yzc/project/RLADKR && python3 -m unittest tests.test_fabfile_aws`
  - 当前为 `23` 个测试全部通过。

## 9. AWS 私网 4 节点实验记录（2026-06-01）

本轮基于新 AMI 完成了第一轮同区域私网 `ARLADKR` 实测联调。

### 9.1 实例拓扑

- 区域 / AZ：`us-east-1 / us-east-1a`
- AMI：`ami-05ac5dfccbed66509`
- 规格：`c5.xlarge`
- 节点数：`4`
- 协议地址使用私网：
  - `172.31.3.101`
  - `172.31.3.117`
  - `172.31.7.95`
  - `172.31.10.253`
- 管理入口使用公网 SSH：
  - `44.213.128.157`
  - `35.153.49.40`
  - `44.192.109.97`
  - `3.237.194.7`

### 9.2 本轮编排修复

为了让“协议走私网、管理走公网 SSH”成立，本轮额外完成：

1. `fabfile.py::_aws_remote_exec`
   - 在 `management: ssh` 场景下改为优先使用 `public_host` 发起 SSH，而不是误连私网地址。
2. `fabfile.py::_aws_host_targets`
   - 当 `use_private_ip: true` 且仍使用 SSH 管理时，会按需反查每个私网 host 对应的公网 IP。
3. 修复多机启动栅栏：
   - 旧实现是每台 host 在本地磁盘等待 `N` 个 `ready` 文件，无法跨机成立；
   - 现改为 `launch -> start -> wait` 三阶段：
     - 每台 host 先写本地 `ready.<run_id>` 并等待本地 `start.<run_id>`；
     - `fab aws-run-bench` 在全部 launch 完后统一下发 `start`；
     - 然后再逐机 wait `status.<run_id>`。

### 9.3 实测命令

- `fab aws-up --project=arladkr`
- `fab aws-run-bench --project=arladkr --bench-args='-n 4 -f 1 -runs 1 -epochs 1 -transport tcp-distributed -timeout 90s'`

对应成功返回的 run id：

- `run-20260601-102336`

### 9.4 当前实验结果

远端 bench 文件已生成，4 台 host 的 `status.run-20260601-102336` 均为 `success`，说明：

- 远端进程拉起成功；
- 多机私网拓扑与启动栅栏已真正跑通；
- bench 命令完成返回，没有卡死在 orchestration 层。

但协议结果当前仍为：

```text
E2E_BENCH_RESULT protocol=ARLADKR-GO ... n=4 f=1 ... success_runs=0 ... local_node_count=1 required_completed_nodes=1
```

这表明当前问题已经从“部署/编排问题”收缩为“协议在真实 4 机私网下未形成成功样本”，而不是基础设施未启动。

后续本地精确复现后，已进一步确认原因不是 AWS 私网环境本身，而是本轮 bench 参数选择不当：

- `fallback-policy=off` 时，`n=4, f=1` 会在 fastlane 失败后直接退出；
- 本地 4 进程复现实测错误为：
  - `fastlane failed and fallback disabled: fastlane view=2 decision timeout: 0/1`
- 将策略改为 `fallback-policy=auto` 后，本地 4 进程 `tcp-distributed` 已可稳定得到：
  - `success_runs=1`
  - `fallback_runs=0`
  - `mean_latency_ms ~= 3.3s ~ 3.4s`
  - `mean_aggrlo_ready_ms ~= 220ms ~ 270ms`

因此，后续 AWS 同区域私网实验的推荐 bench 策略应改为：

```text
-fallback-policy auto
```

而不是继续使用：

```text
-fallback-policy off
```

另一个额外发现是：

- `fallback-policy=force` 在当前 4 进程本地复现里仍会出现早期 `RBC_INIT` 连接拒绝：
  - `send failed after retries: from=0 to=1 tag=RBC_INIT err=dial tcp ...: connect: connection refused`
- 这说明“强制直接进入 fallback”路径仍存在启动竞态；
- 但 `auto` 路径已足以支撑当前 AWS 私网实测，不阻塞继续做性能实验。
- 为了避免后续 `fab aws-run-bench --project=arladkr` 再因遗漏参数而回到错误默认值，现已在 `fabfile.py` 中补齐：
  - 当 `project=arladkr` 且调用方未显式传 `-fallback-policy` 时，自动补 `-fallback-policy auto`；
  - 若调用方已经显式传入 `off|auto|force`，则保持调用方原意，不做覆盖。

### 9.4.1 `force` fallback 本地专项修复进展

围绕 `fallback-policy=force` 的 4 进程本地复现，本轮继续做了两层收口：

1. transport 启动宽限：
   - 新增远端 listener readiness 等待；
   - 将 fallback 启动阶段消息的重试宽限从仅 `RBC_INIT` 扩展到整组 `RBC_* / ABA_*`。
2. fallback 阶段 transport 生命周期收口：
   - `runFallbackACSMVBA` 内部改为让 `RBC + ABA + coin` 共享同一条 transport；
   - 避免 `RBC` 结束后 `Close()` 再重建 transport 时出现端口空窗。

修复后的最新本地现象是：

- `RBC_INIT connect refused` 已基本被压下；
- 大多数进程可完成 `force` fallback；
- 但 4 进程 `n=4,f=1` 黑盒回归仍未完全稳定收敛，残余失败已从“连接拒绝”进一步收缩为：
  - 某些进程在 `ABA_AUX / ABA_COIN_SHARE` 尾部仍可能因对端提前退出而失败；
  - 或在 20s bench timeout 内触发 `context deadline exceeded`。

这说明当前 `force` 路径的主故障已经不再是最早期 listener 未启动，而是：

- 多进程子集模式下，不同进程的 fallback 完成时间不一致；
- 较早完成的本地进程可能在其他进程仍需要其后续 ABA/coin 消息时退出；
- 剩余问题更接近 force-only 活性/退出屏障问题，而不是 admission 或 AWS 编排问题。

因此当前结论更新为：

- `auto`：已可作为 AWS 私网实验默认策略；
- `force`：启动竞态已显著缓解，但仍未完全达到稳定黑盒通过状态，后续需要继续补“force-only completion barrier / linger until peer quiescence”。

### 9.5 额外环境问题

本地收集目录所在磁盘已满：

- `/dev/sda3` 使用率 `100%`

因此本轮 `fab aws-collect --out-dir=...` 未能在本地创建 artifacts 目录，完整日志回传暂未完成。
当前仅通过远端直接读取关键 bench/status 文件完成初步判断。

### 9.6 采集策略调整

为了避免本地磁盘再次被全量日志拉满，本轮已将 `aws-collect` 调整为默认轻量模式：

- 默认收集：
  - `bench.txt`
  - `latest_bench_path.txt`
  - `latest_status_path.txt`
  - `error_summary.txt`
- `error_summary.txt` 仅从远端 `runner.stderr.log` 中提取关键错误摘要，例如：
  - `EPOCH_RUN_ERROR`
  - `EPOCH_RUN_INCOMPLETE`
  - `send failed after retries`
  - `decision timeout`
- 默认不再收集：
  - `runner.stdout.log`
  - `runner.stderr.log` 全量副本
  - `journal.log`
  - `system.txt`
  - `containers.log`

如需临时回到重日志模式，可在配置中显式开启：

- `aws.logs.collect_protocol_logs: true`
- `aws.logs.collect_system_metrics: true`
- `aws.logs.collect_container_logs: true`

本文件只记录对接状态，不替代协议维护文档中的详细实现日志。
