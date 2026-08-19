# AWS 实验过程追踪

本文记录 ARLADKR 与 PracticalADKR 在 AWS 上进行学术实验的实际执行状态、资源、费用和清理结果。
它是操作账本，不替代 [AWS 公网实验推荐流程](AWS_PUBLIC_EXPERIMENT_GUIDE.md)。文档不得记录
AWS access key、SSO token、SSH private key、节点 secret share 或 setup bundle 内容。

## 当前状态

| 项目 | 当前值 |
| --- | --- |
| AWS profile | `arladkr-sso` |
| 账号 | `992382847511` |
| Region | `us-east-1` |
| AZ | `us-east-1f` (`use1-az5`) |
| 实例类型 | `c7g.xlarge` Spot，4 vCPU、8 GiB、ARM64 |
| 最近 ExperimentGroup | `p10-use1-dxtreadyfix-20260818`（success，已销毁） |
| 固定实验 AMI | `ami-0cee8a82967ef97ac` |
| 当前基线 AMI snapshot | `snap-0a49c63bc97d1d443` |
| 保留自有 AMI / snapshot | `4 / 4` |
| Terraform instance count | `0` |
| 当前运行实例 | `0`（最新两批 n=10 fleet 均已终止） |
| 当前挂载 EBS | `0` |
| 当前临时 S3 | `0` |

当前 AMI 为 Amazon Linux ARM64，Go `1.26.5 linux/arm64`。实验记录同时固定 AMI ID 与
`source_revision`；后者在工作树有修改时是 HEAD、diff 和相关未跟踪源码的 SHA-256，而不是只记录
可能失真的 Git HEAD。

## 执行时间线

时间均为 UTC。实例生命周期以 EC2 返回的时间为准，避免用聊天时间估算费用。

| 时间 | 事件 | 结果 |
| --- | --- | --- |
| 2026-08-17 14:38:15 | 首次启动 10 台 `c7g.xlarge` Spot | 同一 AZ，私网协议流量，SSM 在线 |
| 2026-08-17 14:41:32-33 | 首次缩容 | 9 台终止，保留 1 台 image-source |
| 2026-08-17 14:48-14:49 | 安装 Go 并同步源码 | Go 与源码 SHA-256 校验通过；临时 S3 随后删除 |
| 2026-08-17 14:50 | 两套 benchmark 构建 | ARLADKR、PracticalADKR 全包 compile-only 通过 |
| 2026-08-17 14:55:37 | 创建 AMI | `ami-0746b30452d74675f`，随后等待 snapshot 100% |
| 2026-08-17 15:02:29 | 终止 image-source | 根盘随实例删除 |
| 2026-08-17 15:06:15 | 从固定 AMI 启动 1 台克隆 | SSM、`node-slot`、二进制哈希和 `-h` smoke 通过 |
| 2026-08-17 15:08:23 | 终止克隆 | 根盘随实例删除 |
| 2026-08-17 15:29-15:31 | 固定 AMI 显式扩容 n=10 | 10 台 `c7g.xlarge` Spot，全部 `us-east-1f` |
| 2026-08-17 15:32 | Fabric SSM preflight | 10/10 SSM Online；ARM64、Go、二进制验证通过 |
| 2026-08-17 15:34-15:39 | ARLADKR trusted setup | 10/10 SSM/S3 下载成功，bundle digest 为 `5ff46e3ea2f995faa50a002b319247649c52392a8c409c41727339e14d0e3cf7` |
| 2026-08-17 15:40 | setup 权限审计 | 10/10 marker、5 个 scalar、1 个 identity 文件和 `0600` 权限通过 |
| 2026-08-17 17:54 | ARLADKR 分布式 smoke | 修复 receiver actor 地址表与 `f_new` 个 lane-offer 发送失败的 fallback 活性后，10/10 成功 |
| 2026-08-17 18:07 | PracticalADKR setup v2 | 增加 Dumbo equivalent path 的 `f+1`/`n-f` 双阈值 BLS material；bundle digest `ac9d13f4bf49ad4b89865c915a904858659b51ce6ef5ab4fa9be88f3be17b77e` |
| 2026-08-17 18:11-18:13 | Practical 两组对照 | matched-lifetime 与 high-assurance 均 10/10 成功 |
| 2026-08-17 18:23:33 | 最终实验 fleet 缩容 | Terraform 销毁 10 台实例；实例实际运行约 65.6 分钟 |
| 2026-08-18 | 清理复核 | 运行实例、实验 EBS、EIP、NAT Gateway、临时 S3 object/bucket 均为 0；AMI 与 snapshot 保留 |
| 2026-08-18 | 公私网 roster 流程收口 | 未启动资源；增加确定性 `/23` 私网地址、整数 `NodeSlot` roster 和可选动态公网 `/32` 白名单 |
| 2026-08-18 08:06-08:10 | 一键生命周期 workflow validation | `aws-paper-run` 创建 n=10、完成 PracticalADKR、收集 artifact 并销毁全部 29 个 Terraform 资源 |
| 2026-08-18 08:24-08:27 | ARL 一键生命周期 workflow validation | n=10 公网 TCP 10/10 成功，收集 artifact 并销毁全部 29 个 Terraform 资源 |
| 2026-08-18 08:40-08:57 | 同 fleet 交替验证 | ARL 成功后 Practical 默认 10/10 timeout；整轮 invalidated，Terraform 销毁全部 29 个资源 |
| 2026-08-18 10:03-10:07 | cleanup barrier 首轮 AWS 验证 | barrier 的 path `pkill` 自匹配当前 shell，0/10 cleanup-ready；整轮 invalidated，29 个资源已销毁 |
| 2026-08-18 10:10-10:16 | cleanup barrier 修复后验证 | cleanup-ready 10/10、runner ready 10/10；Practical 0/7 quorum，整轮 invalidated，29 个资源已销毁 |

## 镜像内容与验证

镜像构建在真实 `c7g.xlarge` ARM64 实例完成，使用统一 Go `1.26.5`，避免两套协议使用不同
编译器或架构。已验证：

- `go test -run '^$' ./...`：ARLADKR 全包通过；
- `go test -run '^$' ./...`：PracticalADKR 全包通过；
- `rladkrbench`：ARM aarch64 ELF，SHA-256 `b6de050edfcca05c1066a3e9a9c67a131f1d9c29a698e53057fe1b92e2ba11de`；
- `bench_latency`：ARM aarch64 ELF，SHA-256 `c5ba736ccc06175d461ab4b69748b80f66ab6f00df8abb283a4e890e4e8dc3e1`；
- 克隆实例可通过 SSM 执行两个二进制的 help smoke；
- 源码归档 SHA-256：`714d82712bd38d7718922f2ab5e004f3d7d1264f898bf48241704155967060fd`；
- 源码、`/etc/rladkr` 和实验 artifact 中没有节点私钥、`.scalar`、setup bundle 或证书。

节点密钥不能写入 AMI。扩容后必须针对每个逻辑节点独立生成并 provision trusted setup；一台
EC2 只对应一个逻辑节点，不能为了省钱把多个节点塞进同一台实例。

## Terraform 操作

Terraform 栈位于 `deployment/terraform/aws-smoke`。`instance_count` 默认值已经改为 `0`，
防止不带参数执行时意外产生计费实例；`ami_id` 用于固定实验镜像。

### 启动 n=10

```bash
export AWS_PROFILE=arladkr-sso
export AWS_REGION=us-east-1
cd /home/yzc/arladkr/ARL-ADKR-CV-sAPVSS-handoff-2026-07-23/arladkr/deployment/terraform/aws-smoke

terraform plan \
  -var instance_count=10 \
  -var ami_id=ami-0cee8a82967ef97ac \
  -out=n10.tfplan
terraform apply n10.tfplan
terraform output -json
```

启动后先确认所有节点 SSM `Online`，再生成私网 roster、独立 setup bundle 和实验环境文件。
不得把公网 IP 写入协议地址，公网 IP 仅用于管理面；节点协议使用同一 VPC 内的私网 IP。

### 立即缩容

```bash
terraform apply -auto-approve \
  -var instance_count=0 \
  -var ami_id=ami-0cee8a82967ef97ac
```

若需要删除整个临时网络，在确认 AMI 不再使用后执行 `terraform destroy`，并另外处理 AMI 与
snapshot。AMI 不属于当前 Terraform 栈的销毁范围。

## 费用账本

实时费用以 AWS Cost Explorer 最终账单为准；实验期间用资源时长估算，且每次扩容前后都要更新
累计值。本轮 AWS Spot 历史返回 `c7g.xlarge us-east-1f` 约 `$0.0527/小时/台`。以下累计只使用本文已经给出金额的
历史条目，不把单轮金额误写成总成本；未量化的更早镜像构建/中断 fleet 仍不在其中。

| 已记录阶段 | 估算成本 | 累计 |
| --- | ---: | ---: |
| 2026-08-17 最终 n=10 fleet | `$0.66` | `$0.66` |
| 2026-08-18 单 Region 公网 smoke | `$0.22` | `$0.88` |
| 新 AMI 与 Practical 公网 smoke | `$0.08` | `$0.96` |
| Practical 一键生命周期验证 | `$0.04` | `$1.00` |
| ARL 一键生命周期验证 | `$0.02` | `$1.02` |
| 同 fleet 交替失败轮 | `$0.18` | `$1.20` |
| cleanup barrier 自匹配失败轮，0.499 instance-hours | `$0.030` | `$1.230` |
| cleanup barrier 修复后 Practical 失败轮，0.748 instance-hours | `$0.046` | `$1.276` |
| boto3 profile 缺失的 preflight 失败轮，约 0.169 instance-hours | `$0.011` | `$1.287` |
| DXT readiness 修复后 Practical 成功轮，约 1.032 instance-hours | `$0.063` | **`$1.350`（约 `$1.35`）** |
| 三洲 n=10 协议失败轮及 n=4 基础设施失败尝试 | 约 `$0.29` | 约 `$1.64` |
| 三洲 n=4 `r03` Spot 回收轮，约 0.574 instance-hours | 约 `$0.05` | **约 `$1.69`** |
| 三洲 n=4 `r04` Terraform 重复 ingress 失败轮 | 约 `$0.03` | 约 `$1.72` |
| 三洲 n=4 `r05` listener 启动偏斜定位轮，约 0.589 instance-hours | 约 `$0.04` | **约 `$1.76`** |
| 三洲 n=4 `r06` listener 修复验证与 SSM 截断定位轮 | 约 `$0.06` | **约 `$1.82`** |

持续成本另计：4 个 AMI snapshot 的逻辑块约 21.34 GiB，按 `$0.05/GiB-month` 粗算上界约
`$1.07/月`，增量共享后实际可能更低。当前运行实例、公网 IPv4、实验 gp3、临时 S3、实验 VPC
均为 0，因此当前 fleet 小时成本为 `$0/小时`。

VPC、subnet、route table、security group、IAM role 和 instance profile 当前保留。此前一批 n=10 Spot
集群中有 2 台被 AWS 回收，该轮不计入论文数据；最终用于三组成功实验的 10 台实例已由 Terraform
全部销毁。当前没有运行实例、实验 EBS、EIP、NAT Gateway 或临时 S3 桶；账号保留的 4 个自有 AMI
及其 snapshot 是唯一持续产生存储费的实验资源。最终账单仍以 AWS Cost Explorer 为准。

## 每轮实验清理清单

实验结果写入本地并确认完整后，按以下顺序执行：

1. 将实验状态标记为 `success`、`failed` 或 `invalidated`；Spot interruption、节点未达到
   `n-f` 就绪或任一协议失败时，整轮标记 `invalidated`，不能混入论文数据。
2. 保存 run ID、源码提交、AMI、实例类型、Region/AZ、私网 roster、n/f、采样模式、延迟和通信量。
3. 执行 `terraform apply -var instance_count=0 -var ami_id=...`。
4. 用 `describe-instances`、`describe-volumes`、`describe-addresses` 和 `describe-nat-gateways`
   按 `ExperimentGroup` 检查没有运行实例、EBS、EIP 或 NAT Gateway。
5. 删除本轮临时 S3 object/bucket、SSM 临时 artifact 和本地临时 setup 目录。
6. 只有确认后续不再使用时，才注销 AMI 并删除对应 snapshot：

```bash
aws ec2 deregister-image --profile arladkr-sso --region us-east-1 \
  --image-id ami-0746b30452d74675f
aws ec2 delete-snapshot --profile arladkr-sso --region us-east-1 \
  --snapshot-id snap-0d79faf532738800c
```

删除前必须确认没有实例仍引用该 AMI。清理完成后把资源清点和费用估算追加到本文件。

## Fabric 适配结果

本轮已完成 `practicaladkr_project_code/fabfile.py` 的关键 AWS 适配：

- 默认 AWS 管理面改为 SSM，运行用户改为 `ec2-user`；
- bootstrap 支持 Amazon Linux 的 `dnf`，并按 `arm64/amd64` 选择 Go 包；
- 预构建 AMI 模式跳过 Ubuntu 包安装、源码同步和不存在的 DXT 目录，只验证 Go、二进制和 SSM；
- `aws-up` 改为通过 SSM 检查节点，不要求 SSH；
- SSM setup 上传使用临时 SSE-S3 object、预签名 URL 和 SHA-256 校验，完成后删除 object/bucket；
- `aws-collect` 在 `management: ssm` 时通过 SSM 返回的有界 base64 records 收集 benchmark/status/log
  artifact，不再调用 SSH/SCP；每文件最多 4096 原始字节，以保持在 SSM inline-output 上限内。完整协议
  原始日志不属于该轻量采集路径，需要时应改用受控的临时 S3 artifact bucket；
- 论文实验配置固定保存 n=10 私网 roster；Spot interruption 后可在 preflight 中保留固定 roster 和
  故障节点，但 `aws-run-bench` 的新轮次必须先让完整 n 个在线节点通过 cleanup-ready，不能在缺节点时
  复用旧 fleet；缺节点轮次标记为 invalidated，不重新编号在线节点；
- setup 改为 `shared-public` 实验模式：本地一次生成全体节点材料并按项目/n/f/Paillier bits/源码提交缓存，
  单个公共 archive 只上传一个临时 S3 object，再用一次批量 SSM command 安装到全部在线节点。传输材料
  可公开，但为兼容协议加载器，secret 文件在实例上仍保持 `0600`；不再执行逐节点权限审计；
- `aws-up` 使用一次批量 SSM 健康检查；`aws-run-bench` 现在先执行跨协议的全节点 `cleanup-ready`
  barrier：停止并回收 `rladkr-*.service`、清理 benchmark/runner 进程和旧 marker，轮询 `pgrep` 归零，
  用 `ss` 检查 ARL 与 Practical 的全部声明端口，并在每个节点写入、校验新的 env/address map。
  只有 n 个节点全部返回 `cleanup-ready` 后才生成新的同步 `start_at`；runner 随后仍在 `n-f` 节点
  ready 后启动，artifact collect 对在线节点并行；
- n=10 首次缓存构建与安装实测：ARLADKR 约 4 秒，PracticalADKR 约 10 秒。后续 cache hit 时两项目
  可并行完成，整体约 10 秒量级；旧串行流程每项目需要数分钟和约 30 次 SSM command；
- 新增配置 `practicaladkr_project_code/deployment/config.aws-arm64-ssm.yaml`，固定 AMI、私网地址、
  单 AZ、Spot 和 n=10。
- ARL 分布式 env 现在显式提供每节点 `RLADKR_ARTIFACT_CACHE_DIR`，并把 old actor `0..n-1` 与
  receiver actor `n..2n-1` 映射到同一实例的两组固定端口；lane offer 允许至多 `f_new` 个发送失败
  进入既有 fallback 证明路径，不再因单个启动竞态终止整个 epoch。
- Practical 的 threshold setup 升级为 v2：同一 artifact 同时携带 `n-f` high-threshold 与 `f+1`
  low-threshold BLS shares，运行时按 Dumbo domain 选择 signer。离线 setup 仍只生成一次并分发，不计入
  在线 latency。
- Terraform 继续保留现有 `10.42.1.0/24` smoke 子网，并从 host offset 10 为每个 slot 分配确定性
  私网 IP；n=256 时必须显式传入不小于 `/23` 的 `node_subnet_cidr`。`node_roster` 按 slot 输出
  instance ID、private/public IP、Region 和 AZ。
- Fabric 动态 roster 强制校验唯一且连续的整数 `NodeSlot=0..n-1`，不再按 IP 字符串排序。新增独立
  `config.aws-public-ssm.yaml`；公网协议模式默认关闭，开启后 Terraform 只允许本 fleet 公网 `/32` 和
  显式跨 Region peer `/32` 访问 inventory 指定的 TCP 端口。管理面仍使用 SSM，不开放 SSH。
- SSM 管理模式的源码同步不再依赖 SSH：控制机只打包一次配置的源码树，经临时 SSE-S3 object 分发，
  节点校验 SHA-256 后安装；object 和临时 bucket 在完成或失败后都会删除。该路径用于源码同步和 AMI
  预热，预构建 AMI 的普通 `aws-paper-run` 不会在每轮重复构建源码。
- 新增 `aws-paper-run`，为每轮创建独立 Terraform state、运行配置、inventory、artifact 与 JSON
  实验记录，并顺序执行 apply、SSM 检查、setup、benchmark、wait、collect 和 destroy。异常及 Ctrl-C
  同样进入 finally 清理；只有显式 `--keep-fleet` 才保留资源。实验名限制为至多 37 个 IAM 安全字符。

## n=10 同 AZ 实测结果

以下三轮均使用 `us-east-1f`、10 台 `c7g.xlarge` Spot、私网 TCP、`n=10/f=3`、`runs=1`，
且 setup keygen 不计入在线延迟。通信量为单节点 benchmark 报告值；论文正式数据仍应增加重复轮次并
报告跨节点/跨轮次分布。

| run_id | 项目/设置 | latency | online | setup | sent | recv | 状态 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `run-20260817-175428` | ARLADKR，CV smoke | 4136.18 ms | 4016.91 ms | 119.27 ms | 2,934,856 B | 1,936,224 B | 10/10 success |
| `run-20260817-181151` | Practical，matched-lifetime | 4437.09 ms | 4429.11 ms | 7.91 ms | 1,045,108 B | 999,783 B | 10/10 success |
| `run-20260817-181301` | Practical，high-assurance | 4102.60 ms | 4094.94 ms | 7.58 ms | 990,883 B | 992,709 B | 10/10 success |

ARL 的报告 latency 已按既定口径扣除 recovery service grace；该轮原始 latency 为 5136.88 ms，
扣除的 service grace 为 1000.70 ms。ARL candidate formation 为 2572 ms，平均 ACK/fallback 数为
9/1。n=10 下 `smoke` 仅用于流程验证，不是正式安全参数点；`2^-80` 需要的 sample 超过 n=10。

## 尚未完成的下一步

- 单 Region 一键生命周期已用 PracticalADKR n=10 实际验证。cleanup-ready barrier 已通过定向 Fabric
  测试，下一步先在同一 AMI/topology 下完成
  ARL、Practical 默认和 Practical high-assurance 各至少 5-10 个 matched fresh run，报告 median/p95，
  不把单轮数值直接作为论文结论。
- ARL n=10 只能使用 smoke sampling；正式安全参数比较需要选择能容纳目标 sample 的更大 n。
- 在 n=16/32 前验证 Spot 容量；正式论文数据优先考虑 On-Demand，Spot interruption 的轮次不保留。
- 多 Region 的统一 roster、跨 Region SSM 同步启动和收集仍未实现；当前公网改动只完成单 Region
  动态公网流程和 regional stack 的 peer CIDR 基础，不得据此声称已支持正式跨洲实验。

## 追踪条目模板

复制以下表格追加到本文件末尾，每个 `run_id` 一行：

| 日期/UTC | run_id | 项目/采样 | n/f | Region/AZ | AMI | 实例数 | 状态 | latency | comm | 费用估算 | 清理 |
| --- | --- | --- | ---: | --- | --- | ---: | --- | ---: | ---: | ---: | --- |
|  |  |  |  |  |  |  |  |  |  |  | pending |

## 2026-08-18 单 Region 公网 smoke

本轮用于验证公网 TCP 编排，不作为论文安全参数或正式性能数据。配置为
`us-east-1/us-east-1f`、AMI `ami-0746b30452d74675f`、10 台 `c7g.xlarge` Spot、`n=10`、`f=3`，
公网协议端口 `30000-60000`，管理面为 SSM；setup/keygen 不计入在线协议 latency。

| run_id | 项目/参数 | ready | 结果 | latency | grace | 在线协议 | sent/recv | 状态 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `run-20260818-040740` | ARLADKR，错误参数 `-cv-sampling-target smoke` | 10/10 | 0/10 | - | - | - | - | invalidated：参数名不存在 |
| `run-20260818-041039` | ARLADKR，`-cv-failure-target smoke`，缺少确定性 base port | 10/10 | 1/10 | - | - | - | - | invalidated：receiver `:30011` 连接拒绝 |
| `run-20260818-042133` | ARLADKR，`-cv-failure-target smoke` | 10/10 | 10/10 | **4663.83 ms** | 1001.39 ms | **4544.39 ms** | **35,978,407 / 35,797,564 B** | success |

有效轮的 10 个节点均报告 `success_runs=1`，唯一 consensus hash 为
`e7e30fc260a4a9d0318af276c61d10ab42291a2772caefa1d4bf2e9b16f3afea`，setup bundle digest 为
`5972bf860b245aeaf8440356d23cd87e2e08a6dd35a1ed6408fe03a4972f50b9`。10 个节点报告 latency 均值为
4663.83 ms；按本项目约定扣除 recovery-service grace 后，在线协议均值为 4544.39 ms，原始均值为
5665.21 ms。`candidate_formation_ms` 均值为 2803.40 ms，`leaf_build_ms` 均值为 912.70 ms；
`cv_failure_target=smoke` 只验证流程，不代表目标安全参数。

041039 轮失败的根因是 Fabric 生成了与 `network.node_port_base=30000` 一致的公网地址表，但没有
把 `-base-port 30000` 传给 ARL 二进制，导致本地监听器使用随机端口而远端拨号固定的 `:30011`。
Fabric 已在 `_normalize_aws_bench_args` 中对 `arladkr`/`rladkr-go` 自动注入配置的 base port，并增加
回归测试；协议实现和论文参数未改变。

### 本轮 AWS 成本与清理

实例启动时间为 `04:03:21-04:03:25 UTC`，终止时间为 `04:24:52-04:24:53 UTC`，平均单实例存活
1291.1 秒，合计约 3.586 instance-hours。按本时段 Spot 观察价 `$0.0524/h` 估算：

| 项目 | 计算 | 估算 |
| --- | --- | ---: |
| c7g.xlarge Spot | 3.586 h x `$0.0524` | `$0.188` |
| 公网 IPv4 | 3.586 h x `$0.005` | `$0.018` |
| gp3 根盘 | 10 x 30 GiB x 0.3586 h / 730 x `$0.08/GiB-month` | `$0.012` |
| 公网出站流量上界 | 35,978,407 B x `$0.09/GB` | `$0.003` |
| 合计 | 不含 AMI snapshot 长期存储 | **约 `$0.22`** |

费用是实验期间的实时估算，Spot 账单、IPv4 计费粒度和同 Region 公网流量最终以 Cost Explorer 为准。
Terraform 缩容第一次遇到旧 SG ingress revoke 的 AWS 幂等竞态，重试后已显示 `No changes`。最终清点：
实验 tag 下运行/停止实例 `0`、creating/available/in-use 实验 EBS `0`、已关联或已分配 EIP `0`、
可用/待处理 NAT Gateway `0`。VPC、subnet、route table、SG、IAM role/profile 和 AMI 未删除，后者
仍产生 snapshot 存储费。

## 2026-08-18 新 AMI 后 PracticalADKR 公网 smoke

旧 AMI `ami-0746b30452d74675f` 内置的 `bench_latency` 仍是 threshold-setup v1，
与当前源码 v2 不兼容。本轮先从旧 AMI 启动临时 source instance，通过 SSM 安装当前源码构建的
ARM64 二进制（`bench_latency` SHA-256 `7399ea6b...ccb02c`，`rladkrbench` SHA-256
`3eef2b5f...995b63d`），创建新 AMI `ami-0cee8a82967ef97ac`，再启动实验 fleet。

实验配置为 `us-east-1/us-east-1f`、10 台 `c7g.xlarge` Spot、公网 TCP、SSM 管理、`n=10/f=3`、
Practical `paillier-bits=3072`、`runs=1`、`kappa-profile=matched-lifetime`。setup bundle digest 为
`ac9d13f4bf49ad4b89865c915a904858659b51ce6ef5ab4fa9be88f3be17b77e`。

| run_id | ready/result | mean latency | mean online | p50/p95 | 状态 |
| --- | ---: | ---: | ---: | ---: | --- |
| `run-20260818-054826` | 10/10, 10/10 | 4438.63 ms | 4428.76 ms | 3899.42/4707.69 ms | success |

10 个节点的 consensus hash 一致；每节点 `success_runs=1`，`fallback_runs=0`，`timeout_runs=0`。
本轮未启用 `comm-metrics`，因此通信字节字段为 0，不用于通信量结论。该结果仅为公网流程 smoke，
不是论文正式性能数据。

说明：账号当前仅配置 SSM、没有 SSH key，标准 Fabric 源码同步步骤未执行；AMI 中运行的
`bench_latency` 与 `rladkrbench` 已由当前工作树交叉编译为 ARM64、完成 SHA-256 校验后通过 SSM 安装，
因此本轮执行二进制版本与当前源码一致。后续若需要在 AMI 内保留完整源码树，应补充 SSM 源码归档同步流程。

实例已全部清理，临时 S3 bucket 已删除。AWS 记录显示 source instance 存活约 11.3 分钟，10 节点
fleet 存活约 6.3 分钟，合计约 1.24 instance-hours。按 c7g.xlarge Spot 约 `$0.0524/h` 估算，
实例费用约 `$0.065`，公网 IPv4、gp3 与少量流量约 `$0.01`，合计约 `$0.08`；新 AMI snapshot
当前可见逻辑块约 2.67 GiB，按 `$0.05/GiB-month` 约 `$0.13/月`，实际增量账单以 Cost Explorer 为准。

## 2026-08-18 单 Region 一键生命周期验证

本轮验证新增的隔离 Terraform/Fabric 流程，不作为论文正式性能数据。两次预检查
`paper-practical-n10-use1-20260818-ssm-v1` 和 `paper-practical-n10-use1-20260818-ssm-v2` 分别在
provider 下载阶段被中断、在 plan 阶段发现 IAM 名称过长；两次都未创建 AWS 资源。修复后执行：

```bash
AWS_PROFILE=arladkr-sso fab aws-paper-run \
  --project=practical-adkr \
  --bench-args='-n 10 -f 3 -runs 1 -timeout 60s -paillier-bits 3072 -mvba-network tcp -strict-network=true -comm-metrics=true' \
  --config-path=deployment/config.aws-public-ssm.yaml \
  --experiment-name=p10-use1-20260818-ssmv3 \
  --timeout-s=300
```

| experiment/run | n/f | ready/result | mean latency | mean online | mean sent/recv per node | fleet sent/recv | 状态 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `p10-use1-20260818-ssmv3` / `run-20260818-080926` | 10/3 | 10/10, 10/10 | 3928.81 ms | 3918.52 ms | 989,639 / 989,588 B | 9,896,392 / 9,895,879 B | success |

10 个节点的 consensus hash 均为
`88a5b20bb87530aa241602f85bbe709c784c591477b3f8101bbb251d7434fba9`，setup digest 均为
`b157e08a9b3ca0e34d18367907232379964235d30b35fab2ff891fb23909f953`。实验固定
AMI `ami-0cee8a82967ef97ac`，源码身份为
`6e554391ee862b761ebc76c494b51d827e20a8561273578fa60adac3d6201fb4`。本地记录位于
`practicaladkr_project_code/deployment/aws-state/p10-use1-20260818-ssmv3/`。

实例从创建到销毁约 3.4 分钟，10 台合计约 0.57 instance-hours。按本时段 Spot 约 `$0.0524/h`、
公网 IPv4 `$0.005/h`，加 gp3 和不足 0.02 GB 的协议流量，估算约 `$0.04`，不含持续保留的 AMI
snapshot。流程完成后 Terraform 成功销毁 29 个资源；按 ExperimentGroup 复核，pending/running/
stopping/stopped 实例为 0，VPC 为 0，临时 S3 object/bucket 为 0。

### ARLADKR 验证轮

随后用同一 AMI、AZ、实例类型和一键生命周期运行 ARLADKR：

| experiment/run | n/f | ready/result | mean latency | mean online | mean raw/grace | mean sent/recv per node | fleet sent/recv | 状态 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `a10-use1-20260818-ssm01` / `run-20260818-082651` | 10/3 | 10/10, 10/10 | 5244.69 ms | 5121.67 ms | 6245.57 / 1000.88 ms | 3,793,560 / 3,780,903 B | 37,935,599 / 37,809,028 B | success |

所有节点 consensus hash 均为
`7f6fb4e5baa7d52466eafecf90bf5c7c2ffa86ee22e09d92e6e50204c71ec504`，setup digest 均为
`8e5c81c6cce7b2040d096f3c8592d389a592ba914550d1b899cf1029f5798b95`。平均 leaf build 为
1067.50 ms，candidate formation 为 3154.10 ms，ACK/fallback 为 8.5/1.5。结果使用 `smoke`
sampling，只验证 n=10 流程；延迟按既定口径扣除了 recovery service grace。

实验记录的源码身份为 `5fb95a25961c648835e239cdd404bd17eb8b71a313262a0bc7cb89f68d15184f`，
本地 record 与 artifact 位于
`practicaladkr_project_code/deployment/aws-state/a10-use1-20260818-ssm01/`。10 台实例实际存活约
99-103 秒，合计约 0.286 instance-hours；按 Spot、IPv4、gp3 和公网出站上界估算约 `$0.02`。
Terraform 成功销毁 29 个资源，复核 pending/running/stopping/stopped 实例、VPC 和 EBS 均为 0。

### 同 fleet 交替验证失败轮

`suite10-use1-20260818-r01` 首次尝试以同一批 10 台 `c7g.xlarge` Spot、同一 AMI、AZ、roster、
公网 TCP 和 Security Group 依次运行 ARL、Practical 默认、Practical high-assurance。ARL
`run-20260818-084113` 已 10/10 成功；随后 Practical 默认 `run-20260818-084926` 的 10 个节点均为
`success_runs=0`、`timeout_runs=1`，没有 consensus hash。因此整轮标记为 **invalidated**，未运行
high-assurance，也不纳入任何 latency/communication 比较。

现有 artifact 只能确认该失败发生在同 fleet 的跨协议切换后，尚不足以证明具体原因；不得把它归因于
任一协议。失败 artifact 保留在
`practicaladkr_project_code/deployment/aws-state/suite10-use1-20260818-r01/artifacts/practical-default/`。
实例于 `08:40:15-19 UTC` 启动、`08:57:31-33 UTC` 终止，合计约 2.88 instance-hours，按 Spot、IPv4、
gp3 与少量流量估算约 `$0.18`。复核实例、VPC 和 EBS 均为 0，Terraform 销毁 29 个资源。

## 2026-08-18 cleanup-ready barrier AWS 验证

第一次使用 ExperimentGroup `p10-use1-barrier-20260818`。10 台实例于 `10:03:15-19 UTC` 启动，
barrier 中按 path 执行的 `pkill -f` 同时匹配了当前 cleanup shell 命令行里的旧 runner 文件名，导致
0/10 cleanup-ready。协议没有启动，轮次标记为 invalidated。实例于 `10:06:15-17 UTC` 终止，累计
1795 instance-seconds，即 0.499 instance-hours：Spot `$0.0263`、公网 IPv4 `$0.0025`、gp3
`$0.0016`，合计约 `$0.030`。Terraform 销毁全部 29 个资源。

修复后使用 ExperimentGroup `p10-use1-barrierfix-20260818` 和 run ID
`run-20260818-101237`。本轮得到：

- cleanup-ready `10/10`；
- runner launch `10/10`；
- runner ready `10/10`，quorum 要求 `7`；
- 只有上述 barrier 完成后才发布同步 `start_at=1787047980`；
- 70 秒状态为 success `0/7`、failed `8`、running `2`，因此 Practical benchmark 未形成 quorum。

该轮只证明 Fabric cleanup/env/address/start barrier 在真实 AWS 上通过，不是 Practical 性能结果，
也不能据此归因协议失败原因。旧失败路径在 destroy 前没有调用 collect，因此本轮没有保存 journal；
代码随后改为失败时先尽力 collect，并为每节点保存对应 transient unit 的 `systemctl status` 与
`journalctl -u`。相关 Fabric 单元测试为 29/29 通过。

第二轮实例于 `10:10:24-28 UTC` 启动、`10:14:54-58 UTC` 终止，累计 2691 instance-seconds，
即 0.748 instance-hours：Spot `$0.0394`、公网 IPv4 `$0.0037`、gp3 `$0.0025`，加少量未采集协议
流量后按 `$0.046` 记账。两轮新增约 `$0.076`，本文已量化历史成本由 `$1.20` 累计到约 `$1.276`
（取两位小数 `$1.28`），不含 snapshot 持续费用和更早未量化资源。

最终按两个 ExperimentGroup 复核：pending/running/stopping/stopped 实例、实验 EBS、VPC 均为 0，
两次 Terraform 都销毁 29 个资源。下一次付费重试必须使用新增的失败诊断收集路径；在拿到 unit journal
并定位 Practical 失败前，不继续盲目创建 fleet。完成单项目 fresh-fleet 验证后，再做三配置同 fleet
交替和 matched repeated runs；多 Region 工作仍按原计划后置。

## 2026-08-18 Practical DXT 启动竞争修复（本地）

继续分析旧的 `suite10-use1-20260818-r01` artifact 后，发现失败节点的单轮退出时间分成明显层次：
4 个节点分别约为 `3.851s`、`3.925s`、`4.328s`、`4.354s`，贴近 DXT 网络 ACK 的默认 `4s`
窗口；其余节点约为 `18-19s` 或 `55s`。同一 AMI、源码 revision、n/f 与 setup digest 的独立
fresh-fleet 轮次 `run-20260818-080926` 曾 10/10 成功。这说明 cleanup barrier 已不是当前失败点，
更可能是各进程完成密钥加载和 listener bind 的时间不同，而 DXT dealer 在本机 listener 建立后就立即
启动，没有等待远端 receiver listener 达到协议所需阈值。旧轮次没有保存 journal，因此这里记录为
高概率定位，而不是已由运行日志严格证明的根因。

已在 PracticalADKR 的 DXT TCP service 中增加带 `SID`、`epoch` 和目标 node ID 绑定的 readiness
request/ack。每个分布式 dealer 在发起 DXT 前等待至少 `2f+1` 个新委员会 receiver 返回有效 ACK；
该阈值与 DXT transcript 的真实 ACK 条件一致，不要求无故障的 n/n，也不改变 DXT 密文、证明、
APDB、MVBA 或恢复协议。等待耗时写入现有 `dxt_network_wait` phase；readiness 控制流量不计入协议
通信量。benchmark 现在还会把 `PRACTICAL_RUN_ERROR` 写进每节点 bench artifact，下一次失败无需仅
依赖全局 stderr 即可看到具体阶段。

新增测试覆盖延迟启动时不会提前越过 `2f+1` barrier、达到 quorum 后继续、错误 epoch 被拒绝，
以及 readiness 字节不进入协议通信统计。本地定向 network tests 和全包编译检查通过。本地修复阶段
尚未创建 AWS 资源，当时累计量化成本保持约 `$1.276`；随后按下节只运行一次 n=10 Practical
fresh-fleet 复验，并使用已经启用的 unit journal 收集。

### Fresh-fleet AWS 复验

第一次复验使用 `p10-use1-dxtready-20260818`。Terraform 成功创建 29 个资源，但随后 Fabric 的
dynamic inventory 使用裸 `boto3.client`，没有继承 Terraform 已显式使用的 `arladkr-sso` profile，
因此在协议启动前报 `NoCredentialsError`。`finally` 正常销毁全部 29 个资源。已把 Fabric 内 EC2、
SSM、S3 和 STS 的 14 个 client 创建点统一到 profile-aware factory，并在公网配置中显式固定
`profile: arladkr-sso`；新增单测验证 profile/Region 传递。Fabric 测试为 30/30 通过，真实 STS
调用也返回账号 `992382847511`。

CloudTrail 显示该失败轮实例约从 `10:38:48-51 UTC` 存活到 TerminateInstances
`10:39:50 UTC`，按每台至少 60 秒计约 0.169 instance-hours。Spot、IPv4 和 gp3 合计保守记
`$0.011`，没有协议流量。

修复后以 `p10-use1-dxtreadyfix-20260818`、run ID `run-20260818-104738` 重跑相同 n=10、f=3、
3072-bit Paillier、strict public TCP 配置，结果为：

- SSM online、cleanup-ready、launch、runner ready 均为 10/10；
- 同步 `start_at=1787050206` 只在 runner ready 10/10 后发布；
- 4 秒状态检查已经 success 10/10、failed 0，quorum 要求为 7；
- artifact 10/10 收集成功，setup bundle digest 一致；
- 10 个节点的 consensus hash 均为
  `2bc13120e69b17cf2c98a2c5deecdcb7f0db4386a0ecd58d71f405a5ba1923aa`；
- 节点延迟均值 `3892.41 ms`，范围 `3665.01-4117.56 ms`；平均 online protocol
  `3881.83 ms`，平均发送/接收 `985038/984810` bytes；
- 本轮所有节点在进入 DXT 时已达到 readiness quorum，因此记录的 `dxt_network_wait` 为 `0 ms`；
  该值不表示 barrier 未执行，只表示没有额外等待。

成功轮 CloudTrail launch 到 TerminateInstances 合计约 3714 instance-seconds，即 1.032
instance-hours。Spot 约 `$0.0544`、公网 IPv4 约 `$0.0052`、gp3 约 `$0.0034`，少量流量后按
`$0.063` 记账。两轮新增约 `$0.074`，量化累计由 `$1.276` 更新为 `$1.350`（约 `$1.35`），
不含持续 snapshot 费用。

成功轮 artifact 位于
`practicaladkr_project_code/deployment/aws-state/p10-use1-dxtreadyfix-20260818/artifacts/`。最终复核两个
ExperimentGroup 的实例均为 `terminated`，EBS 和 VPC 查询均为空，Terraform 两轮各销毁 29 个资源。

## 2026-08-18 三洲 n=10 编排准备

新增最小的跨 Region Fabric 编排，固定 `us-east-1:4`、`eu-west-1:3`、
`ap-southeast-1:3` 和连续 NodeSlot 0-9。SSM discovery、单节点命令、区域批量命令、ready quorum、
状态轮询和 artifact 收集都按目标 Region 路由；三份 Terraform state 先独立创建，再使用其他 Region
公网地址的 `/32` 二次 apply。ARLADKR 与 PracticalADKR 将复用同一 fleet，并由 cleanup-ready 屏障
隔开。新增 3 项跨 Region 测试后 Fabric 全套为 33/33 通过，三 Region dry-run 也完成 apply/peer
CIDR plan/协议顺序/逆序 destroy 全流程，没有创建实例。

源 AMI `ami-0cee8a82967ef97ac` 已复制为 `eu-west-1/ami-09c02ed1bf7b2b15b` 和
`ap-southeast-1/ami-0091cf6c0499f49fe`，两者均已 available。复制前确认目标 Region 无可复用镜像，
三 Region 无 pending/running/stopping/stopped 的 `ProtocolSuite=rla` 实例。按此前记录的约
21.34 GiB 实际 snapshot 数据估算，两份副本持续存储约 `$2.13/月`，另有一次性跨 Region copy
数据传输费用，需以后续账单为准。该项暂不并入按实例生命周期量化的 `$1.350`，成本台账记为
`$1.350 + AMI copy/storage pending`；实验结束后若不再重复跨 Region 测试，应注销两份 AMI 并删除
对应 snapshot，停止持续计费。

## 2026-08-18 三洲 n=4 Spot 中断定位与悉尼替代

`cross-n4-3c-20260818-r03` 使用 `us-east-1:2`、`eu-west-1:1`、
`ap-southeast-1:1`，所有实例均为 `c7g.xlarge Spot`。四节点完成 SSM online、setup 分发、
cleanup-ready、runner launch 和 ready 4/4，并在 `start_at=2026-08-18T12:07:43Z` 同步进入协议。
本轮不能用于判断 90 秒是否足够：新加坡实例的 Spot request `sir-rcizhd7p` 在
`12:07:22Z` 已收到 `instance-terminated-no-capacity`，即同步启动前 21 秒已进入 AWS 两分钟
回收通知窗口，最终由 AWS service 在 `12:09:25Z` 终止。其余实例由 Terraform 正常终止。

四台实例合计存活约 2068 instance-seconds，即 0.574 instance-hours；按运行时三地 Spot 价、
公网 IPv4、gp3 与少量流量估算约 `$0.05`。加上此前跨 Region 尝试后，本文量化累计暂记约
`$1.69`，AMI copy 和 snapshot 持续费用仍单列。三 Region 的实验实例、VPC 和 EBS 已复核为 0。

为避免 Spot 中断掩盖协议诊断，Fabric 的失败收集现在自动只对仍在线节点执行 best-effort collect，
manifest 记录 expected/unavailable hosts；cross-region suite 保留 benchmark quorum failure 为主错误，
把 collect failure 作为附加字段。该修改不改变协议、计时或通信口径，Fabric 测试为 34/34 通过。

按 Spot placement score，亚太候选当前最高仅 3/10；后续仍坚持 Spot，第三地改为
`ap-southeast-2/ap-southeast-2c`。预烘焙镜像已复制为
`ap-southeast-2/ami-09b5f867c562fbd39` 并 available。该副本约增加 21.34 GiB snapshot 的持续
存储和一次性跨 Region copy 费用，最终以账单为准。

## 2026-08-18 三洲 n=4 `r04/r05` 启动路径定位

`cross-n4-3c-20260818-r04` 的四台 Spot 实例均成功创建，但跨 Region `/32` 规则的第二次
Terraform apply 报 `InvalidPermission.Duplicate`，协议没有启动。原因是同一 security group 同时由
inline `ingress` 和独立 `aws_vpc_security_group_ingress_rule` 管理。Terraform 已改为仅使用独立的
`private_self` ingress rule；`terraform fmt -check` 和 `terraform validate` 通过。该轮资源全部销毁，
估算新增约 `$0.03`。

`cross-n4-3c-20260818-r05` 使用 `us-east-1:2`、`eu-west-1:1`、`ap-southeast-2:1`，四台实例
均为 Spot，且实验期间没有回收事件。SSM 4/4、setup、cleanup-ready、launch 和 runner ready 均成功，
但 ARLADKR 很快失败为 `remote readiness timeout: ready=2/3`。各节点日志显示欧洲/悉尼节点先打开
listener，等待远端 120 秒后退出；较慢的美国节点约一分钟后才进入同一阶段，此时早期 listener 已
关闭并产生 `connection refused`。因此本轮定位为 listener 生命周期覆盖范围不足，而不是 90 秒
benchmark timeout 或 MVBA 工作量问题；PracticalADKR 没有启动。

`RunCVEpochV2` 现于本地 epoch runtime/密码学材料加载前创建 agreement TCP transport，并让该
transport 在整个加载阶段保持存活。该修改不改变协议消息、证明或在线 latency 口径。Fabric suite
还会在 SSM fleet 全部在线后、协议 setup 前将当前源码交叉编译为 Linux ARM64 二进制并原子安装，
把 archive、`rladkrbench` 和 `bench_latency` 的 SHA-256 写入 `experiment-record.json`；因此后续轮次
不会误用预烘焙 AMI 中的旧二进制。失败 artifact 改为逐文件 SSM 收集，避免 4096-byte inline output
截断。相关 Fabric 测试为 37/37，通过 Go transport/readiness 定向测试与 compile-only 校验。

`r05` 从 `12:31:42Z` 至 `12:40:32Z`，四台合计约 0.589 instance-hours；计入 Spot、IPv4、gp3
和少量跨区流量后保守估算约 `$0.04`。`r04/r05` 新增约 `$0.07`，量化累计从 `$1.69` 更新为约
`$1.76`；AMI copy/snapshot 持续成本仍单列。销毁后已复核美国、爱尔兰、悉尼三地实验实例和 EBS
均为 0。

## 2026-08-18 三洲 n=4 `r06` listener 修复实机验证

`cross-n4-3c-20260818-r06` 继续使用 `us-east-1:2`、`eu-west-1:1`、
`ap-southeast-2:1`，Terraform plan、state 和实例 metadata 均确认四台为 `c7g.xlarge Spot`，没有
On-Demand fallback。跨区 `/32` 二次 apply、SSM 4/4、当前源码二进制 staging、setup、cleanup-ready
与 runner ready 4/4 均成功。实验记录的 `rladkrbench` SHA-256 为
`b3c208f078d1af1febdd53cd705e2ac97a7293f3e491476abc4c3b02f47492ee`，与本地当前源码 ARM64
构建一致。

ARLADKR 达到论文 runner 的 n-f=`3/3` 成功判据，三名成功节点 consensus hash 均为
`6033c1421699a2e4f7829596a9c86a406cf8c5b7be44d322cab45e4ebb5c4d45`。成功节点报告的
service-grace-adjusted latency 约 `23.71-26.29 s`，raw latency 约 `24.71-27.29 s`，candidate
formation 约 `8.98-9.64 s`。悉尼节点失败为 aggregate recovery 仅达到 1 holder、需要 2；这不影响
n-f 成功判据，且已确认不再是 `r05` 的 listener readiness 启动偏斜。

PracticalADKR 本轮没有启动，因为 artifact 收集器仍将单个 ARL benchmark 文件限制为 4096 bytes。
ARL 的单行结果超过该上限，虽逐文件 SSM 收集避免了文件间截断，单文件本身仍被静默截断，summary
解析为 0 results 并报 `collected nodes disagree on setup bundle or timing metadata`。收集器现改为先查询
文件字节数、再以不超过 2 KiB 的 base64 块分页读取并严格校验块长度，默认单文件上限 1 MiB；summary
的一致性也只在成功的 n-f 样本集合内比较，失败节点仍保留诊断。新增 7 KiB artifact 重组与
3-success/1-failure quorum 回归测试后，Fabric 为 39/39 通过。

`r06` 从 `13:00:23Z` 至 `13:11:17Z`，按三地当时 Spot 价（美国 `$0.0732`、爱尔兰
`$0.0744`、悉尼 `$0.0887` 每台小时）、公网 IPv4、gp3 与少量流量保守记约 `$0.06`；量化累计
由约 `$1.76` 更新为约 `$1.82`，AMI copy/snapshot 持续成本仍单列。Terraform 逆序 destroy 完成后，
三地 pending/running/stopping/stopped 实验实例与 available/in-use 实验 EBS 均复核为 0。

## 2026-08-18 三洲 n=4 `r07` 同 fleet 比较与 Practical APDB 定位

`cross-n4-3c-20260818-r07` 继续使用 `us-east-1:2`、`eu-west-1:1`、
`ap-southeast-2:1`。四台实例均为 `c7g.xlarge Spot`，Terraform 的
`instance_market_options.market_type` 为 `spot` 且中断行为为 `terminate`，没有 On-Demand fallback。
当前源码 ARM64 二进制、跨区公网 `/32` allowlist、SSM、setup、cleanup-ready、launch 和 runner-ready
均为 4/4；ARLADKR 与 PracticalADKR 使用相同实例、公网地址和拓扑，中间经过 cleanup-ready 屏障。

ARLADKR 达到 n-f=`3/3`，三名成功节点 consensus hash 均为
`9053aec0dd50fca4556cb97f3f3cf96d98182786f5b52e1947bf9130b1279469`。成功节点报告的
service-grace-adjusted latency 约 `15.97-20.16 s`，raw latency 约 `16.97-21.16 s`，candidate
formation 约 `6.08-6.32 s`。悉尼节点 aggregate recovery 未达到所需 holder 数，但不影响 n-f 成功
判据。新的分块 SSM 收集器完整收集了四份 ARL artifact，验证了 `r06` 的截断修复。

PracticalADKR 四个节点均未完成。悉尼节点先失败为
`network APDB readiness: reachable=1 need=3`；美国和爱尔兰节点随后分别在 Dumbo-MVBA 的
quitPD 或 permutation coin 阶段超时。代码审计确认 APDB readiness 将每个 peer 的 TCP dial 固定为
`100 ms`、完整 request/ack I/O 固定为 `200 ms`。该窗口适用于同 Region，但小于或接近悉尼到美国/
爱尔兰的公网 RTT，因此悉尼只能计入本地节点；其他节点继续推进后形成阶段偏斜。这不是 Spot 容量、
Terraform、SSM、地址表或 90 秒总 timeout 问题。

APDB readiness 现使用可配置的 `PRACTICAL_APDB_READY_DIAL_TIMEOUT_MS` 和
`PRACTICAL_APDB_READY_IO_TIMEOUT_MS`，默认分别为 `1000 ms` 和 `2000 ms`；peer 探测并发执行，
quorum 仍严格为 n-f，不改变 APDB、MVBA 或密码学协议。新增测试模拟 `350 ms` ACK，验证跨洲 RTT
不再被旧的 `200 ms` 窗口拒绝；两份 Practical module 的定向测试及 compile-only 检查均通过。

`r07` 从 `13:22:47Z` 至 `13:37:45Z`，四台实例主要运行约 15 分钟。按三地 Spot 价、公网 IPv4、
gp3 和少量跨区流量保守新增约 `$0.09`，量化累计由约 `$1.82` 更新为约 `$1.91`；AMI copy/snapshot
持续成本仍单列。Terraform destroy 完成后已再次查询美国、爱尔兰、悉尼三地，
pending/running/stopping/stopped 实例及 available/in-use EBS 均为 0。

## 2026-08-18 三洲 n=4 `r08` CompProve 定位与销毁流程补强

`cross-n4-3c-20260818-r08` 使用与 `r07` 相同的美国 2、爱尔兰 1、悉尼 1 topology，四台均为
`c7g.xlarge Spot`，没有 On-Demand fallback。当前源码 ARM64 binary staging、SSM、跨区 `/32`、
cleanup-ready 和 runner-ready 均为 4/4。ARLADKR 达到 n-f=`3/3`，成功节点 consensus hash 均为
`e76706d468f8d357f53145e5931f68d69275f37d7eb8f430819316b49b670372`；成功节点
service-grace-adjusted latency 约 `20.07-24.69 s`。悉尼节点仍因 aggregate recovery holder 不足失败，
但不影响 n-f 成功判据。

PracticalADKR 不再出现 `network APDB readiness: reachable=1 need=3`，证明 `r07` 后增加的 APDB
跨洲 readiness 窗口已生效。失败推进到 Algorithm 3 CompProve：两个接收者只有
`valid=2 ids=[5 6] need=3`，另一节点报告本地 ACK aux 缺失。代码审计发现 CompProve listener 在各
进程内创建，但 share multicast 前没有跨节点 readiness；单次 route 默认约 `500 ms`，整个 key
derivation 默认 `15 s`，对跨美国、爱尔兰、悉尼的阶段偏斜过于激进。

CompProve 现于发送 key share 前并发探测新委员会 listener，并要求 n-f 返回绑定 `SID`、epoch 和
recipient 的 ready-ack；该控制流不计入协议通信量。严格网络默认 key-derivation 窗口调整为 `45 s`，
CompProve route I/O 至少 `2 s`，分别可由 `PRACTICAL_KEY_DERIVE_TIMEOUT_MS`、
`PRACTICAL_COMPPROVE_ROUTE_TIMEOUT_MS`、`PRACTICAL_COMPPROVE_READY_DIAL_TIMEOUT_MS` 和
`PRACTICAL_COMPPROVE_READY_IO_TIMEOUT_MS` 覆盖。n-f share threshold、CompProve 证明及验证逻辑均未
改变。新增测试验证 listener 数不足时不会提前继续，达到 n-f 后才放行；两份源码镜像保持逐字一致。

Fabric cross-region suite 现在还会在最后一个协议 collect 后、Terraform destroy 前执行一次全节点
cleanup-ready，复用已有的 systemd stop/kill、`pgrep`、`ss` 端口释放和 marker 清理逻辑。最终 cleanup
失败只写入 `experiment-record.json`，不会阻止逆序 destroy，避免资源因诊断失败滞留。Fabric 39 项
测试通过；CompProve、APDB 定向测试及 compile-only 检查通过。完整 Practical core 测试中既有的
`TestPartialVerifyN7Comparison` 曾因时序进入 `full-local-fallback`，启用 trace 重跑后 21 个 vote 条目
全部达到 5 票并通过；该项记录为与本次修改无调用关系的测试时序不稳定。

`r08` 从 `13:55:45Z` 至 `14:10:55Z`，四台 Spot 主要存活约 15 分钟，按三地 Spot、公网 IPv4、gp3
和少量流量保守新增约 `$0.09`，量化累计由约 `$1.91` 更新为约 `$2.00`；AMI snapshot 持续费用仍
单列。实验记录为 `cleanup=destroyed`。本次审计没有发现 OS、SSM agent、systemd 或依赖层缺陷；当前
启动后 staging 会校验最新二进制 digest，因此暂不重建 AMI，避免无必要的 snapshot 和跨区复制成本。

## 2026-08-19 三洲 n=4 `r09` Spot 回收与资源清理

运行 `cross-n4-3c-20260819-r09` 前，另发现并清除了 `us-east-1` 中遗留的
`smoke-n10-use1-20260818-practical-v2` VPC `vpc-03903797302e14bd2`，包括其 subnet、security
group、route table 和 internet gateway；清理前确认该 VPC 已无实例、ENI、EBS 或 NAT gateway。

`r09` 继续使用美国 2、爱尔兰 1、悉尼 1 的三洲 topology，四台均为 `c7g.xlarge Spot`，没有
On-Demand fallback。四台一度全部达到 SSM reachable，当前 ARM64 binaries 也在四台全部安装并通过
SHA-256 校验。ARL setup bundle 在本地成功生成，digest 为
`15a9f84c994e34826026afbafe2412ea84d4d17ce12a200314cff9554d92fc2c`，但在发出共享 setup 安装命令前，
悉尼实例 `i-0cd39804e2addf1de` 已于 `04:02:10Z` 被 AWS 回收；命令于 `04:02:17Z` 发出后，SSM 返回
`StatusDetails=Undeliverable`、`ResponseCode=-1`，所以本轮失败与 setup bundle 内容、协议实现或网络
timeout 无关，ARLADKR 和 PracticalADKR 均未启动。本轮结果标记为 invalidated，不纳入论文延迟数据。

四台实例共存活 2086 instance-seconds：美国两台分别约 647/648 秒、爱尔兰约 510 秒、悉尼约 281 秒。
按当时 `c7g.xlarge` Spot 单价（`us-east-1a $0.0738/h`、`eu-west-1c $0.0745-$0.0746/h`、
`ap-southeast-2c $0.0890/h`）计算，EC2 约 `$0.044`；加入公网 IPv4、短时 gp3 和少量控制/传输流量，
本轮保守记约 `$0.05`，量化累计由约 `$2.00` 更新为约 `$2.05`。最终账单仍以 Cost Explorer 为准，
AMI snapshot 持续费用继续单列。

Terraform 已逆序销毁三地 stack。AWS CLI 复核显示四台实例均为 `terminated`，三地该实验标签下的
Spot request、EBS volume、VPC、EIP 和非 deleted NAT gateway 均为 0。最终 cleanup-ready 因悉尼实例
已被回收而无法解析该 host，记录为 failed，但不影响 Terraform destroy。Fabric 的 SSM batch 错误现在
同时记录 `StatusDetails`、response code、stdout 和 stderr，后续 Spot 回收不会再被误报为空错误。

## 2026-08-19 三洲 n=4 `r10` Mumbai Spot smoke

由于 `r09` 的悉尼 Region placement score 仅为 `1/10`，且实例在 setup 命令发出前被 Spot 回收，
本轮不再使用悉尼；新加坡此前已有 `instance-terminated-no-capacity`，也不回退到新加坡。现有三洲
配置改为 `us-east-1:2`、`eu-west-1:1`、`ap-south-1:1`，Mumbai `aps1-az3` 的 placement score
为 `3/10`，四台仍全部是 `c7g.xlarge Spot`，无 On-Demand fallback。Mumbai 使用从已验证的新加坡
AMI 临时复制的 `ami-00466faea4dfcbe0f`，复制完成后本轮结束即注销 AMI 并删除
`snap-080b81fdd07ce23e8`；不重建操作系统镜像。

实验 `cross-n4-3c-20260819-r10` 于 `04:12:51Z` 开始，四台均 SSM Online、setup bundle 和当前
ARM64 binary digest 校验通过，四台均通过 cleanup-ready。ARLADKR 于 `run-20260819-041845` 达到
`n-f=3`：成功节点 service-grace-adjusted latency 为 `15.101 s`、`15.296 s`、`24.300 s`，
三个成功节点 consensus hash 均为
`12bfd72c593d2a8fc2ef9a5e2b3e3d61e362c1717d32e78a04f71a95be2c263e`；Mumbai 节点未完成 CV APDB
recovery（本地 holder 不足），但不影响本轮 n-f smoke 判据。PracticalADKR 于
`run-20260819-042430` 也达到 `n-f=3`，三个成功节点 latency 为 `5.021 s`、`5.115 s`、`7.994 s`，
consensus hash 均为 `3ac65a752a12327ee6087f06e948c843a046a2decef6efc8ece45ddac1bbe899`，
`success_rate=1.0`、`fallback_policy=off`。这些是跨洲公网 smoke，不是论文正式性能结论；ARL
启用了 `comm-metrics`，Practical 本轮未启用通信量统计，不做通信量横向结论。

四台实例分别于 `04:13:23Z`、`04:14:07Z`、`04:14:49Z` 启动，美国两台于 `04:30:56Z`、爱尔兰
于 `04:29:58Z`、Mumbai 于 `04:28:05Z` 由 Terraform 终止，合计约 3853 instance-seconds。
按运行时 Spot 价（美国 `$0.0738/h`、爱尔兰约 `$0.0746/h`、Mumbai `$0.0456/h`），EC2 约 `$0.073`；
公网 IPv4、短时 30 GiB gp3 和少量控制流量约 `$0.007`，本轮生命周期成本保守记约 `$0.08`，
量化累计由约 `$2.05` 更新为约 `$2.13`。AMI 跨区复制的数据传输/快照复制费用取决于实际有效块数，
不并入上述实例生命周期累计，待 Cost Explorer 最终账单确认。

Terraform 三地 stack 均 destroy 完成，`final_cleanup=cleanup-ready`。AWS CLI 复核三地该
`ExperimentGroup` 下实例、Spot request、EBS、VPC、EIP 和非 deleted NAT gateway 均为 0；临时
Mumbai AMI/snapshot 也已注销。`r10` 是可用于 smoke 记录的成功轮次，Spot 未发生中断。

## 2026-08-19 单 Region n=10 `r11` ARLADKR Spot smoke

本轮只复测 ARLADKR，不启动 PracticalADKR。实验名为
`paper-arladkr-n10-20260819-r11`，run ID 为 `run-20260819-044443`，使用
`us-east-1` 的 `use1-az5`（`us-east-1f`）单 AZ topology、10 台 `c7g.xlarge` Spot，
无 On-Demand fallback；AMI 为 `ami-0cee8a82967ef97ac`。参数为 `n=10, f=3, runs=1,
epochs=1, timeout=180s`，公网 SSM 编排和 `base-port=30000`，实验二进制及 setup bundle
均通过 digest 校验。

资源阶段为 10/10 实例创建、10/10 SSM Online、10/10 setup、10/10 cleanup-ready、
10/10 runner 启动；最终收集到 10 份 host 目录，其中 9 份包含有效 bench artifact，
1 台（`98.81.19.23`）没有生成 bench 文件。有效节点数为 `9/10`，协议 quorum 为
`n-f=7`，因此 `quorum_success=true`，但这不是“10 个节点全部完成”的性能样本。
9 个有效 artifact 的 consensus hash 全部一致：
`dff584168b98b22352a58baff69820a08e475bc8767babbacd215a249a6cffb9`。

有效节点的 service-grace-adjusted latency（ms）为
`4868.78, 4942.82, 5498.13, 5544.76, 5553.13, 5575.33, 5588.22, 5623.53,
5644.52`；均值 `5426.58 ms`，中位数 `5553.13 ms`，p95 `5644.52 ms`，最大值
`5644.52 ms`。对应 raw latency 均值约 `6426.58 ms`，每个节点扣除的
`mean_recover_service_grace_ms` 约 `1000 ms`。因此报告时必须同时给出 `9/10` 完成率和
`7/10` quorum 判定，不能将均值表述为全体 10 节点延迟。

本轮使用 `mode=strict`、`online_protocol_excludes_setup=true`、`comm_metrics=true`、
`cv_failure_target=smoke`，proposer/validator sample 均为 3；APVSS 为
`ack-fallback`，fallback profile 为 `feldman-batch-v1`，各节点 fallback count 为 1 或 3。
这些设置属于当前 smoke 配置，不能替代 high-assurance 或完整 I-only backend 的正式论文实验。
同 Region、同 AZ 的低 RTT 是本轮约 5.43 秒延迟明显低于此前跨洲 `r10` 的主要环境原因，
不是计时器跳过协议阶段的证据；setup 仍被单独计时，latency 只排除约 1 秒 recovery-service grace。

实验记录时间为 `04:41:59Z`--`04:51:27Z`。按本轮历史 `c7g.xlarge us-east-1f Spot`
约 `$0.0527/小时/台`、10 台实例生命周期，加上公网 IPv4、短时 30 GiB gp3 和少量控制流量，
生命周期成本保守估算约 `$0.10`；累计量化成本由约 `$2.13` 更新为约 `$2.23`。AMI snapshot
持续费用和最终 Cost Explorer 账单仍单列，以账单为准。

Fabric 最终记录 `status=success, cleanup=destroyed`。AWS CLI 复核本实验标签下没有
pending/running/stopping/stopped 实例、Spot request、残留 EBS、VPC、EIP 或 NAT gateway。

## 2026-08-19 三洲 n=4 `r12` ARLADKR-only Spot smoke

本轮按用户要求只测试 ARLADKR，不启动 PracticalADKR。实验名为
`paper-arladkr-cross-n4-20260819-r12`，run ID 为 `run-20260819-071424`，使用固定跨洲
公网 topology：`us-east-1:2`（`use1-az1`, slots 0--1）、`eu-west-1:1`
（`euw1-az1`, slot 2）和 `ap-southeast-2:1`（`apse2-az2`, slot 3）。四台均为
`c7g.xlarge` Spot，无 On-Demand fallback；AMI 分别为 `ami-0cee8a82967ef97ac`、
`ami-09c02ed1bf7b2b15b` 和 `ami-09b5f867c562fbd39`。参数为
`n=4, f=1, runs=1, epochs=1, timeout=900s`，公网 TCP `/32` allowlist、SSM 管理、
setup cache 和当前 ARM64 binary digest 均通过校验。

资源和启动阶段为 4/4 实例创建、4/4 SSM Online、4/4 setup、4/4 cleanup-ready、
4/4 runner 启动。`aws-wait` 在 3 个节点成功后达到 `n-f=3`，因此返回 smoke 成功；
artifact 收集结果为 `3/4`：美国两节点和爱尔兰节点有 bench 文件，悉尼节点在收集时仍为
`running`，没有有效 bench artifact。三个有效节点的 consensus hash 全部一致：
`b61816d2b53288114618c09fdf32a63fca2ec2be2d8f449cd0f9f24a9f5b1335`。

三个有效节点的 service-grace-adjusted latency（ms）为
`16430.06, 17498.81, 19873.10`；均值 `17933.99 ms`，中位数 `17498.81 ms`，p95
`19873.10 ms`，最大值 `19873.10 ms`。raw latency 均值为 `18934.83 ms`，每个节点
扣除约 `1000 ms` recovery-service grace。candidate formation 分别约 `5683 ms`、
`5877 ms` 和 `5167 ms`。因此本轮应报告为 `3/4` artifact、`3/4` quorum smoke，
不能称作完整四节点延迟样本。

本轮仍是 `mode=strict`、`online_protocol_excludes_setup=true`、`comm_metrics=true`、
`cv_failure_target=smoke`，proposer/validator sample 为 3，APVSS 使用
`ack-fallback`/`feldman-batch-v1`。跨洲 RTT、抖动和节点阶段偏斜使 online protocol
约 `16.4--19.8 s`，显著高于同 AZ r11 的约 `4.9--5.6 s`；这正是环境差异，不应直接解释
为协议计时器少算阶段。悉尼节点未完成 artifact 也说明 `n-f` quorum smoke 不能替代
完整 fleet 成功。

实验从 `07:08:56Z` 持续到 `07:17:38Z`。按三地当时 Spot 价格、四台实例实际生命周期、
公网 IPv4、30 GiB gp3 和少量跨区控制/协议流量，生命周期成本保守估算约 `$0.10`，
量化累计由约 `$2.23` 更新为约 `$2.33`；最终账单以 Cost Explorer 为准，AMI snapshot
持续费用单列。实验记录为 `status=success`、Terraform `cleanup=destroyed`。最终 cleanup
barrier 因悉尼实例在收集时仍运行且地址解析状态变化记录为 failed，但 Terraform 已逆序
销毁三地 stack；随后 AWS 资源复核应以实例、Spot request、EBS、VPC、EIP 和 NAT 全部为零
为完成标准。

## 2026-08-19 法兰克福拓扑 `r13` 编排中止与清理

按用户指定的 `us-east-1:2`、`eu-west-1:1`、`eu-central-1:1` topology 启动了
`paper-arl-euc1-n4-r13`。四台实例均为 `c7g.xlarge` Spot，分别使用
`ami-0cee8a82967ef97ac`、`ami-09c02ed1bf7b2b15b` 和临时复制的
`eu-central-1/ami-03013d3446cc2edce`。首次实验名过长触发 Terraform IAM
`name_prefix` 长度校验，未创建资源；缩短名称后四台实例成功创建，但在全部节点进入
SSM/setup 前用户要求改用两区域拓扑，因此 ARLADKR 协议没有启动，不产生延迟或通信数据。

随后按法兰克福、爱尔兰、美国逆序执行 Terraform destroy，并经过最终一致性复核确认三地
active instances、Spot 资源、EBS、VPC 和安全组均为 0。四台实例仅短暂运行，按当时
美国 `$0.0738/h`、爱尔兰 `$0.0746/h`、法兰克福 `$0.1028/h` Spot 价，加公网 IPv4、
30 GiB gp3 和少量控制流量，保守将本次编排成本记为约 `$0.04`；累计量化成本由约 `$2.33`
更新为约 `$2.37`。该轮标记为 `invalidated`，不纳入论文性能样本。法兰克福 AMI 副本
`ami-03013d3446cc2edce` 及其快照未随实验销毁，持续存储费用单独计账。

后续两区域配置固定为 `us-east-1:2`、`eu-west-1:2`，见
`practicaladkr_project_code/deployment/config.aws-cross-region-n4-use1-euw1.yaml`；
干跑 `paper-arl-use1-euw1-n4-r14-dryrun` 已通过，尚未启动实际实例。

在后续确定只使用美国和爱尔兰两区后，法兰克福 AMI
`ami-03013d3446cc2edce` 已注销，其专用 snapshot `snap-009519f0112eb9bb0` 已删除；因此该副本
不再产生持续存储费用。美国和爱尔兰的已验证基线 AMI 继续复用。

## 2026-08-19 两区域 n=4 `r14/r15` 编排失败与流程优化

用户将 topology 改为 `us-east-1:2`、`eu-west-1:2`，固定使用
`use1-az1`/`ami-0cee8a82967ef97ac` 和 `euw1-az1`/`ami-09c02ed1bf7b2b15b`，四台均为
`c7g.xlarge` Spot。`r14` 首个 Region apply 在两个本地 `/32` 规则并发创建时触发
`InvalidPermission.Duplicate`；实例已创建但协议未启动。根因是 Terraform 用两个独立的
`aws_vpc_security_group_ingress_rule` 管理同一安全组的本地规则，AWS 已接受其中一个请求后
provider 重试产生重复授权。该轮通过 state destroy 清理，未产生协议数据，成本保守记约 `$0.02`。

Terraform 模块随后将同一 Region 的本地公网 CIDR 合并为一个
`aws_security_group_rule`，跨 Region peer CIDR 仍使用独立规则；`terraform fmt -check`、
`terraform validate` 和 Fabric 回归均通过。

`r15` 使用修复后的模块成功完成两区四台 Spot 创建、跨区 peer allowlist、SSM Online、当前
ARM64 binary staging 和共享 ARL setup 安装；setup digest 为
`170842fc1aabf5fded7ac078881716d78fb387c6b84f018f0abc27d7803780dd`。协议尚未启动时用户要求
停止，因此没有 latency、consensus 或通信数据。停止后按爱尔兰、美国逆序 destroy，并复核
两区 active instances、open/active Spot requests、EBS、VPC、安全组、EIP 和 NAT 全部为 0。
本轮四台约运行 10--12 分钟，按美国 `$0.0738/h`、爱尔兰 `$0.0746/h`、公网 IPv4、30 GiB
gp3 和少量 SSM/S3 流量，保守记约 `$0.06`；累计量化成本由约 `$2.39` 更新为约 `$2.45`。
`r14/r15` 均标记为 `invalidated`，不纳入论文性能样本。

### AWS 流程复用与优化审计

- setup key material 已按 `project/n/f/Paillier bits/source revision` 缓存；只要源码 revision
  和实验参数不变，下一轮直接命中 `deployment/setup-cache`，不重复生成密码学材料。
- 当前二进制仍按源码交叉编译并校验 digest；它保留了论文实验的“运行当前源码”语义，但可将
  `aws.runner.s3_bucket` 配置为一个预先创建且有生命周期规则的实验 bucket，复用 bucket，避免
  每个命令创建/删除临时 bucket。对象仍按 digest 命名并在成功或失败后删除。
- AMI、Terraform provider cache、AWS 实验配置和本地 setup cache 都可以跨轮复用；AMI 只能在
  OS/依赖确实变化时重建，源码变化由 binary staging 覆盖。AMI snapshot 持续成本单列。
- 每轮仍必须重新申请 Spot fleet、生成独立 Terraform state、重新写公网 `/32` allowlist、执行
  全节点 cleanup-ready、分发当前 binary/setup，并在收集后 destroy。复用运行中的实例或旧监听
  进程会污染论文 latency 和网络条件，不建议。
- Fabric 的跨 Region SSM batch 现已并发执行，控制命令使用独立的
  `ssm_command_timeout_seconds=180`，不再继承 `bench_timeout_seconds=900`；这只改变编排等待，
  不改变协议 timeout 或 latency 口径。Fabric 39/39 测试通过。

## 2026-08-19 两区域 n=4 `r16` 性能审计与 WAN fan-out 修复

`paper-arl-use1-euw1-n4-r16` 使用 `us-east-1:2` 和 `eu-west-1:2` 的四台
`c7g.xlarge` Spot，4/4 节点完成且 consensus hash 一致。四个
service-grace-adjusted latency 为 `11522.90`、`11261.29`、`11386.63` 和
`11961.72 ms`，均值 `11533.14 ms`；raw 均值为 `12533.61 ms`，报告正确扣除了约
`1000 ms` 的 recovery service grace。setup 约 `48 ms`，离线 key generation 和
同步启动等待均不在 latency 内。四个实例的 service CPU time 约 `2.8--3.0 s`，因此
`11.5 s` 的主要来源是 WAN 轮次/阈值等待而不是标量解密计算。

阶段均值为：leaf build `822 ms`、component disperse `577 ms`、candidate formation
`4725 ms`、aggregate agreement `1201 ms`、recover shard `3412 ms`（其中约 `1000 ms`
为已从报告 latency 扣除的 service grace）、receipt/handoff `1499 ms`。标量 bounded-DLog
仅 `4.30 ms`。candidate relay 每节点发送约 `25.6--37.0 KiB`，结合旧的 `100 ms` ACK
初始等待，表明跨大西洋 ACK 往返和验证时延会造成不必要重发。

修复保持协议消息、阈值、签名、候选验证和决定规则不变：认证 envelope 的 candidate delivery
现在先返回非语义 ACK，候选仍在后续完整验证后才被缓存、转发或参与决定；已缓存的相同
canonical wire 快速抑制；ACK wait 改为 per-peer channel，避免一个 peer 的 ACK 错误唤醒另一
peer；candidate ACK 基础等待从 `100 ms` 调整为 `250 ms`。decision share、handoff、scalar
share 和 recovery request 使用最多 16 路的有界并行 fan-out，控制重传周期从 `100 ms` 调整为
`250 ms`。这消除串行 TCP send 对 WAN 关键路径的放大，同时不改变收件人集合。

本地验证通过：candidate/ACK 聚焦测试 `0.59 s`，真实 APDB recovery/decision 网络回归
`14.29 s`，`go test ./cmd/rladkrbench -count=1` 通过，`go test ./... -run '^$' -count=1`
通过，`git diff --check` 通过。严格 benchmark 拒绝 `tcp-loopback` 是有意的
`strict-network` 防护，不把本地 loopback 当作公网实验结果。

AMI 不需因本修复重建。两区现有 AMI 为 `arladkr-bench-arm64-v2-20260818`
(`ami-0cee8a82967ef97ac`) 和 `arladkr-bench-arm64-v2-20260818-cross`
(`ami-09c02ed1bf7b2b15b`)；`run_arladkr_cross_region.py` 每轮在实例上线后都会交叉编译当前
ARM64 `rladkrbench`，以 SHA-256 校验并经 SSM 原子安装。因此后续 r17 复测会运行本次提交的
二进制，不会误用 AMI 内旧版本；仅 OS、Go 版本或基础依赖变化时才重新 bake AMI。
