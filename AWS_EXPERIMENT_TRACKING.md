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

## 2026-08-19 修复后两区域 n=4 `r17` quorum smoke

本轮使用提交 `8ee3736` 的 candidate ACK、per-peer wait 和有界并行 fan-out 修复，拓扑仍为
`us-east-1:2`（`use1-az1`）和 `eu-west-1:2`（`euw1-az1`），四台均为 `c7g.xlarge` Spot，
AMI 与 r16 相同。实验名为 `paper-arl-use1-euw1-n4-r17`，run ID 为
`run-20260819-100628`。SSM/setup/cleanup barrier 均为 4/4，ARM64 binary digest 为
`e9759c848dae25893a0f2d67dcd9143201d4505ed6ce7535cbe04b86ffcedf4f`。

本轮只收集到 3/4 bench artifact：美国 slot 0、slot 1 和爱尔兰 slot 3 成功，爱尔兰
slot 2（`3.248.249.130`）在收集时仍显示 `running`，没有 bench 文件，随后由 finally cleanup
终止。三个成功节点 consensus hash 均为
`9632dc1e1011c1861a1b1715f17facb2a90b7bd6be484642c6284ca41fb8c6d9`，因此这是 quorum smoke，
不是完整四节点 latency 样本，标记为 `invalidated`，不纳入论文主表。

三个 artifact 的 service-grace-adjusted latency 为 `10293.00`、`10918.94`、`10975.26 ms`，
均值 `10729.07 ms`；raw 均值 `11729.81 ms`。与 r16 三个指标均值（`11533.14 ms`，完整
4/4）相比，方向性下降约 `7.0%`，但由于 r17 缺失一个节点且每轮只有一个 epoch，不能宣称
统计显著的性能提升。阶段均值（仅 3 个成功节点）为：leaf `804 ms`、component disperse
`615 ms`、candidate formation `4891 ms`、aggregate agreement `1219 ms`、recover shard
`3173 ms`（含约 `1001 ms` grace）、receipt/handoff `792 ms`。candidate formation 比 r16
的 `4725 ms` 略高，说明 ACK/fan-out 修复的主要收益目前出现在 handoff/control wait，candidate
formation 仍是下一步瓶颈。总发送/接收均值约 `1.30/1.29 MB`，没有观察到通信量异常下降。

本轮 AWS 资源已确认清理：四台实例均 `terminated`，两区 active Spot request 为零，root
EBS volume 不存在，Terraform VPC、subnet、security group、IGW、IAM role/profile 均已销毁。
按实际启动到终止时间、当时约 `$0.0738/h`（美国）和 `$0.0746/h`（爱尔兰）Spot 价、四个
公网 IPv4、30 GiB gp3 和少量 SSM/跨区流量，保守记本轮约 `$0.04`；累计量化成本由约
`$2.50` 更新为约 `$2.54`，最终以 Cost Explorer 为准。

## 2026-08-19 两区域 n=4 live 对照与运行中诊断

为验证“公网 RTT 是否足以解释 ARLADKR 的秒级额外延迟”，使用同一公网 topology
`us-east-1:2`（`use1-az1`）加 `eu-west-1:2`（`euw1-az1`）、四台 `c7g.xlarge Spot`、
同一 AMI、同一连续 NodeSlot 和同一跨区 `/32` ingress allowlist，运行 ARLADKR 后经
`cleanup-ready` barrier 运行 PracticalADKR。两套二进制均由本地当前源码交叉编译、经 SHA-256
校验后由 SSM 原子安装。测试期间不只等待 summary：通过逐 Region SSM 读取每节点的进程、监听端口、
artifact/status 文件和 transient systemd unit。

第一轮 `paper-compare-use1-euw1-n4-live` 运行时间为 `10:37:50Z--10:48:01Z`。ARLADKR 达到
`3/3` quorum，但美国 slot 0 未产生 bench artifact，故其结果不作正式样本。PracticalADKR 的四台
进程均在协议前退出；journal 明确显示 `flag provided but not defined: -base-port`。根因是人工调用时
给 `bench_latency` 传入了仅 ARL benchmark 支持的 `-base-port`，与公网、协议实现或 RTT 无关。
本轮标记为 **invalidated**，Terraform finally destroy 与 final cleanup 已完成。

修正参数后，第二轮 `paper-compare-use1-euw1-n4-live2` 于 `10:55:03Z--11:06:53Z` 成功：
`final_cleanup=cleanup-ready`、`cleanup=destroyed`。运行中观测显示 ARL 的三个节点约在一轮完成后
释放协议 listener；爱尔兰 slot 3 仍保有 `:30003`、`:30007` listener 和 benchmark 进程，直至
finally cleanup，因此 ARL 只有 3/4 artifact，不能作为完整四节点主表数据。Practical 四节点均完成，
无残留 protocol process 或 listener。

| 项目 | 完成 | 成功节点 latency | 均值 | 结论 |
| --- | --- | --- | ---: | --- |
| ARLADKR | 3/4 quorum | 9184.10、9705.32、10142.19 ms | 9677.20 ms | quorum smoke，排除论文主表 |
| PracticalADKR | 4/4 | 2936.43、3633.49、3712.80、3559.17 ms | 3460.47 ms | 完整但单 epoch smoke |

Practical 的跨区阶段数据为：DXT network wait `137--412 ms`、APDB `142--638 ms`、MVBA
`567--792 ms`、recovery `774--839 ms`。这再次说明跨大西洋 RTT 不是从约 3--4 秒直接变为约
10 秒的充分解释；ARL 的额外时间仍主要在 candidate formation（本轮约 `4.5--4.9 s`）以及后续
aggregate/recovery 等阈值等待。该对照也不能独立得出论文结论：每项仅一 epoch，ARL 缺一个节点，且
Practical 本轮未启用通信量统计。下一轮应保持相同 topology，启用两边的通信量统计，要求 4/4 artifact，
并连续至少 5 个 fresh epoch 后报告 median/p95 和分阶段分布。

两轮均为四台 Spot、约 10--12 分钟生命周期；按美国/爱尔兰历史 Spot 价、公网 IPv4、30 GiB gp3
和少量 SSM/跨区流量各保守记约 `$0.05`，新增约 `$0.10`，量化累计由约 `$2.54` 更新为约 **`$2.64`**。
第二轮的 Terraform state 记录已确认 destroy；最终 AWS API 复核时本地 SSO token 正好过期，待重新
`aws sso login --profile arladkr-sso` 后再执行只读的实例、Spot request、EBS、VPC 和 EIP 零资源复核。

## 2026-08-19 Candidate Path WAN 调度优化（待公网复测）

对第二轮 ARLADKR 的 phase 分解表明，`candidate_formation_ms` 的 `4.5--4.9 s` 并不等同于
单次 candidate relay；它覆盖 eligibility threshold coin、proposer component catalog recovery、PoolCert、
contributor coin、aggregate APDB Lock、validation certificate，以及首个 verified candidate 的传输与验证。
因此不能把该值直接归因于公网 RTT，也不应在论文的端到端 latency 中扣除这些协议阶段。

本地源码已作一项不改变协议语义的 WAN 调度优化：coin share 与 recipient-specific APDB Store offer
均改用已有的最多 16 路 bounded fan-out。原先的逐 peer 同步发送会把 TCP transport ACK 的等待串联为
多次 WAN 往返；现在仍发送相同的认证消息，仍要求原有的阈值，且 Store offer 仍按接收者独立构造。
candidate 的 ACK/retry 策略（最多四次，`250/500/1000/2000 ms`）没有改变，只新增观测。

`E2E_BENCH_RESULT` 现额外报告 `eligibility_coin_ms`、`proposer_slots_ms`、
`mean_coin_fanout_ms`、`aggregate_offer_send_ms`、`mean_candidate_ack_wait_ms`、
`mean_candidate_retry_wait_ms`、`mean_candidate_fanout_max_peer_ms`、
`mean_candidate_fanout_attempts` 和 `mean_candidate_fanout_retries`。其中前两项拆分 candidate 大阶段，
其余项用于定位发送与 ACK 重试的 WAN 放大；它们是解释性指标，不改变既有 E2E 口径（仍仅扣除 setup
和已定义的 recovery-service grace）。

此处尚无 AWS 复测，不能据此声称跨区 latency 已改善。下一次应使用同一
`us-east-1:2 + eu-west-1:2`、`n=4,f=1` fresh fleet，要求 4/4 artifacts，并重点比较上述字段与本节
之前记录的优化前基线；运行中继续用 SSM 观察各节点的进程、端口和 artifact 状态。

## 2026-08-19 Candidate Path 优化后两区域 n=4 复测

运行 `paper-arl-use1-euw1-n4-r18-20260819`，继续使用 `us-east-1:2 + eu-west-1:2`、
四台 `c7g.xlarge Spot`、公网 `/32` allowlist 和 `n=4,f=1`。ARLADKR 与 PracticalADKR 使用同一
fresh fleet；本地当前源码交叉编译后以 SHA-256 校验并原子安装。ARL 完成后，所有四台节点通过
`cleanup-ready` barrier，才启动 Practical。实验记录为 `success`，最终 `cleanup-ready` 和 Terraform
destroy 均完成。

必须区分 runner quorum 与完整样本：ARL 在 `3/3` 成功后，`aws_wait` 即返回并触发收集及下一协议的
cleanup；当时第四个节点仍为 `running`，其 `bench.txt` 为空。因此 Fabric 的 `collect 4/4` 只表示四台
主机的收集命令执行成功，并不表示存在四份成功 bench artifact。本轮 ARL 仍是 **3/4 quorum smoke**，
不能进入论文主表。Practical 为 4/4 成功。

| 项目 | 成功节点 service-grace-adjusted latency | 均值 | 样本状态 |
| --- | --- | ---: | --- |
| ARLADKR | 10131.64、10393.07、10555.22 ms | 10359.98 ms | 3/4 quorum smoke |
| PracticalADKR | 3105.12、3177.85、3549.13、3592.13 ms | 3356.06 ms | 4/4 单 epoch smoke |

ARL 三个成功节点的 candidate formation 为 `4090/4166/4273 ms`，均值 `4176.33 ms`；其中
eligibility coin 均值 `129.78 ms`，proposer slots 均值 `4046.76 ms`。相对前一次同 topology 的
candidate formation `4492/4616/4866 ms`（均值约 `4658 ms`），本轮方向性下降约 `10.3%`，但样本均
只有一个 epoch 且都缺一个节点，不能据此宣称统计显著改善。ARL 总延迟没有同步下降，恢复与 handoff
波动仍然很大：recover shard 均值 `3059 ms`，receipt 均值 `1222 ms`。

新增观测显示 aggregate Store offer 在实际发送节点为 `137--203 ms`；`mean_coin_fanout_ms` 为
`442--917 ms`，它累计该节点本 epoch 的多次 coin fan-out，不等同于 eligibility coin 单阶段延迟。
candidate ACK wait/retry wait 只有 `0.02--0.04 ms`，说明固定 `250/500/1000/2000 ms` backoff 没有成为
本轮秒级瓶颈。与此同时 attempts/retries 均为 `12/12`，这是因为当前计数把 proposer slot 被取消后立即
返回的未 ACK attempt 也算作 retry；该字段不能直接解释为 12 次真实超时重传。复测后已在本地修正：
取消的 wait 仍计入 attempt/ACK wait，但不再计入 retry，且发送循环在 context 或 service 取消后立即返回。
该修正尚未重新部署到 AWS，因此本轮 artifact 中的 retry 字段仍按旧观测定义解释。
当前证据把 candidate 的剩余主要成本进一步定位到 proposer slots 内部，尤其成功 proposer 的 component
recovery（本轮约 `1713--2015 ms`）及后续阈值证书路径，而不是 candidate relay ACK backoff。

Practical 的在线协议均值为 `3351.55 ms`，DXT network wait 均值 `393.71 ms`、APDB `442.44 ms`、
MVBA `599.52 ms`、recovery `769.29 ms`。本轮命令未启用 Practical 的 `-comm-metrics`，其字节字段为零，
不能用于通信量公平对照；延迟结果仍可作为同 fleet 的单 epoch smoke。

本轮资源生命周期为 `12:25:28Z--12:41:35Z`，约 16.1 分钟。按复核时 `c7g.xlarge` Spot 价格范围
（美国约 `$0.0526--0.0738/h`、爱尔兰约 `$0.0726--0.0775/h`）、四个公网 IPv4、120 GiB gp3 和少量
跨区流量，保守记约 `$0.06`；累计量化成本由约 `$2.64` 更新为约 **`$2.70`**，最终仍以 Cost Explorer
为准。AWS API 已复核两区 active 实例、open/active Spot request、实验 EBS volume 和实验 VPC 均为零。

## 2026-08-19 WAN 重发与 transport 队头阻塞修复（本地验证）

针对 r18 暴露的 `validation_request_wire_bytes=2631 B` 但实际发送约 `82--106 KB`、以及跨区
`candidate_formation_ms` 约 `4.2 s` 的实现层放大，完成了不改变协议语义的 P0/P1 修复：

- `CertifyPool`、`CertifyAggregate` 和 `runCoin` 首次使用 bounded fan-out，后续最多四轮
  `250/500/1000/2000 ms` 指数退避，并只向尚未贡献 share/signature 的 peer 重试；删除 PoolCert
  完成后的 5 秒全 fleet 后台重发。
- APDB stored/recovery response、coin reply、pool/validation signature、decision/aggregate share
  和 candidate ACK 改由每个 service 的有界 outbound worker queue 发送。dispatch 仍串行执行验证、
  去重和 one-shot signing，但不再等待 TCP transport ACK。
- TCP pooled connection 按 `(from,to,address,lane)` 建立 deterministic control/bulk 两 lane。
  APDB/recovery/组件/candidate 大消息走 bulk lane，coin、certificate、MVBA 等控制消息走 control
  lane；同 lane 顺序保持不变，跨 lane 不再互相阻塞。

协议阈值、采样、签名、验证、候选规则和 latency 报告口径均未修改；没有扣除 candidate 或 recovery
阶段，也没有降低 `n-f`/证书阈值。新增回归覆盖异步 candidate ACK、PoolCert 完成后无后台重发、非 validator
不重复收到 validation request、双 lane key 分类和 TCP pooled reconnect。

验证结果：

- `go test ./core -run` 针对 Pool/VCert/recovery/candidate：通过。
- `go test ./core -count=1`：通过，`433.711 s`。
- `go test ./... -run '^$'`：通过。
- `go test ./cmd/rladkrbench -run '^TestBenchMultiProcessFourNodePrivateStyleSubsets$' -count=1`：通过，`4.040 s`。
- 本地四节点严格 TCP benchmark 的四个节点均 `success_runs=1`，共识 hash 一致；service-grace-adjusted
  latency 为 `1947.55--2003.11 ms`，平均约 `1976 ms`。candidate formation 为 `615--1156 ms`，
  `mean_candidate_fanout_retries=0`，validation request 单节点发送量约 `0.8--12.9 KB`，不再出现
  r18 的 `82--106 KB` 级别重复广播。

这只是本地验证，不能替代 AWS 跨区复测；当前累计 AWS 成本仍为约 `$2.70`，本节没有新增 AWS 资源或费用。
下一轮应在同一 `us-east-1:2 + eu-west-1:2` fresh fleet 上要求 4/4 artifact，启用两边 comm metrics，
连续至少 5 个 epoch，再比较 r18 的 `10359.98 ms` ARL 基线与新的分阶段分布。

## 2026-08-19 下一步执行状态：AWS MCP 阻塞与本地回归

本轮按 r18 后续计划检查了跨区 n=4 配置
`practicaladkr_project_code/deployment/config.aws-cross-region-n4-use1-euw1.yaml`。配置仍为
`us-east-1:2 + eu-west-1:2`、`c7g.xlarge` Spot、公网 IPv4、SSM 管理、`allow_partial_fleet=false`，
并要求 4/4 节点完成后才作为正式样本。

当前 Codex 会话没有注册 `aws-api` 的 `call_aws`/`suggest_aws_commands` 工具，且 MCP resource/template
列表为空。依据 `cloud-operation` 技能的执行规则，本轮没有绕过授权直接运行 AWS CLI，也没有启动、修改或
销毁任何 AWS 资源。因此本轮新增 AWS 成本为 `$0.00`，累计量化成本保持约 **`$2.70`**；此前资源均已清理，
最终账单仍以 Cost Explorer 为准。

在等待可审计 AWS 通道期间完成了本地验证：

- `go test ./core -run 'Test(CVAPDB|CVCandidate|CVCertified|CVPool|CVValidation|CVSAPVSSRouter|TCPPool|TCPPooled|CVLaneNetwork|CVRunAgreement|CVComponentMaterialization|CVCoinOutput)' -count=1`：通过，`37.113s`。
- `git diff --check`：通过。
- `graft build --deep`：完成结构图刷新，`8970` 节点、`19695` 条边、`726` 个文件卡片；无 API key 时使用结构化构建。

上述 MCP 状态仅记录当时环境。随后在用户明确授权下，已按既有 Fabric/Terraform 流程完成本配置的 r19
复测，结果、清理和成本见下一节。

## 2026-08-19 WAN 调度修复后两区域 n=4 `r19` 完整 smoke

本轮不依赖 MCP，沿用 Fabric/Terraform 的既有可审计流程，实验名
`paper-arl-use1-euw1-n4-r19-20260819`，run ID `run-20260819-140900`。拓扑保持
`us-east-1:2`（`use1-az1`）加 `eu-west-1:2`（`euw1-az1`），四台均为 `c7g.xlarge` Spot、
公网 IPv4 和跨区 `/32` TCP allowlist。使用当前 ARM64 二进制（`rladkrbench` SHA-256
`e1c1b137ca134187b70be284fa0d0fcf24d0a977dbeb60c0fd4f0a314f0257d6`），并开启
`-strict-network -comm-metrics`；四节点 setup bundle digest 一致。

执行期实际观测到：`aws-up=4/4`、pre-launch `cleanup-ready=4/4`、同步启动前 runner readiness
为 `3/4`（协议阈值），协议完成后四台均已经退出并产出成功 artifact。收集结果为 **4/4**、
`success_runs=1`、一致 consensus hash
`09a1ffbd0dde65a44d26eaef69a4ed91bc912aaaad87a1fa7946d7338577f125`，不存在遗留 runner stderr。
finally cleanup 再次得到 `cleanup-ready=4/4`，两区 Terraform 都报告 destroy 完成；实例、EBS、VPC、
security group、IGW、IAM profile/role 与 Spot request 均由该 destroy 路径回收。

| 指标 | r19 四节点均值 | r18 quorum smoke | 说明 |
| --- | ---: | ---: | --- |
| service-grace-adjusted latency | `4660.29 ms` | `10359.98 ms` | r19 是完整 4/4 单 epoch smoke |
| raw latency | `5660.98 ms` | 未作为本比较口径 | 保留约 `1000 ms` recovery service grace 的原始值 |
| candidate formation | `1936.25 ms` | `4176.33 ms` | 约下降 `53.6%` |
| proposer slots | `1821.09 ms` | 约 `4046.76 ms` | candidate 的主要剩余时间 |
| leaf / component disperse | `808.25 / 468.00 ms` | `804 / 615 ms` | 同量级 |
| aggregate agreement / recover shard / receipt | `536.75 / 1403.25 / 301.00 ms` | `~1222 / 3059 / 1222 ms` | r18 的 3/4 样本不可作显著性结论 |
| total sent / recv per node | `1.188 / 1.179 MB` | 约 `1.30 / 1.29 MB` | 以 comm metrics 实测 |
| validation request sent | `12.53 KB` | 约 `82--106 KB` | 定向重发和去除后台广播已消除主要放大 |
| candidate fan-out retries | `0` | 旧观测口径不可靠 | r19 使用已修正的取消计数定义 |

各节点 adjusted latency 为 `4692.95`、`4670.36`、`4603.62`、`4674.22 ms`，因此这轮验证了 WAN
调度修复在同一公网 topology 下确实消除了 r18 的异常秒级放大。它仍仅有一个 epoch，不能作为论文
median/p95 或统计显著性结论；正式对照仍需在相同 fresh-fleet 拓扑下让 ARLADKR 和 PracticalADKR
各完成至少五个完整 epoch，并保留两边通信量指标。

实验记录的 provision-to-collection 区间为 `14:02:40Z--14:13:31Z`；随后两区实例终止和网络销毁
额外约数分钟。按四台实例约 `13--16` 分钟实际生命周期、追踪文档既用的 `c7g.xlarge` Spot 保守价、
四个公网 IPv4、`4 x 30 GiB` gp3 与约数 MB 的跨区实验流量估算，本轮记 **约 `$0.05`**。累计量化成本
由约 `$2.70` 更新为约 **`$2.75`**，最终以 AWS Cost Explorer 实际账单为准。

销毁完成后，以 `arladkr-sso` profile 对 `us-east-1` 和 `eu-west-1` 做了只读 API 复核：两区按
`ExperimentGroup=paper-arl-use1-euw1-n4-r19-20260819` 过滤的 non-terminated instance 均为零，
open/active Spot request 也均为零。

## 2026-08-19 百节点部署路径优化（本地验证）

为避免部署控制面成为 `n=100--256` 论文实验的主要等待来源，Fabric 的 SSM 批处理上限和默认并行度
均改为 `50`。SSM API 的一个 `send-command` 最多接受 50 个 instance ID；实现继续按 Region 并发，
每个 Region 内将超过 50 个节点切为连续批次，且每批可同时启动 50 个下载/安装命令。所有当前可编辑的
AWS 基础配置（含两区域 n=4 配置）也显式设为 `ssm_parallelism: 50`，历史 experiment state 不回写。
binary 与 shared setup 的 presigned artifact URL 默认有效期同步提升到 `3600s`（最低 `900s`），避免 256
节点在后续 SSM 批次开始前 URL 已过期。

`shared-public` setup 不再将 `public/` 与全部 `node-XXXXXX/` 目录打进一个 archive 后让每台节点下载。
现在流程为：上传一份仅含 `public/` 的 archive、每个 NodeSlot 一份独立 shard、以及一份短时 presigned
URL index；每个 SSM target 先并发下载公共 archive，再从 index 选择自己的 shard，逐项 SHA-256 校验后
原子安装。这样每节点接收量从 `P(n) + n*S` 降为 `P(n) + S`，集群总量从
`n*P(n) + n^2*S` 降为 `n*P(n) + n*S`，消除了全部私有 shard 的二次重复项。公共 registry `P(n)`
本身通常随 n 线性增长且每台协议节点都必须持有，因此严格的总下载复杂度仍可能为 `O(n^2)`；本修改不虚称
降为 `O(n)`，重点是减少无协议必要性的重复材料与部署尾部。节点磁盘上只安装本 NodeSlot 的材料；短时 index 仍可见所有 shard URL，
因此该模式仍是 academic shared-public
部署而不是生产级私钥隔离。它不改变 trusted-offline setup、协议消息、阈值或 latency 统计口径。

本地验证：`python3 -m unittest test_fabfile.py` 通过（`41` 项，约 `0.3s`），覆盖 51 个目标拆成 `50+1`
且第一批并发为 50、公共 archive 不含 node shard、每节点 shard/index 安装命令存在；`py_compile` 与
空白检查通过。此项仅修改编排代码与配置，未启动 AWS 资源，新增成本 `$0.00`，累计量化成本仍约 **`$2.75`**。

后续可继续简化但尚未实现的流程包括：将当前临时 S3 artifact 改为按源码 digest 缓存的固定实验 bucket；
为多 Region 在各 Region 复制同一不可变 binary/setup object；以及将多 epoch 同一 fleet 的 setup 与 binary
安装复用为一次。这三项均不应让 GitHub clone 或远端编译进入测量路径，以保持节点二进制、构建环境和实验
启动时间可复现。

## 2026-08-19 现有 AMI n=10 两区域 deployment smoke

为验证 AMI 不变时的新 SSM/shard 部署路径，新增并使用仅含两个 Region 的配置
`practicaladkr_project_code/deployment/config.aws-cross-region-n10-use1-euw1.yaml`：
`us-east-1:5`（`use1-az1`）加 `eu-west-1:5`（`euw1-az1`），总 `n=10,f=3`，全部为现有
`c7g.xlarge` Spot 和原 AMI（美国 `ami-0cee8a82967ef97ac`、爱尔兰 `ami-09c02ed1bf7b2b15b`）。
实验名经安全截断为 `paper-arl-use1-euw1-n10-deploy-r20-20`，run ID 为
`run-20260819-145457`。

部署链路验证结果：

- `aws-up=10/10`，两 Region 的 SSM target 全部可达。
- setup cache 生成 n=10/f=3 bundle，digest 为
  `e7ca89e3cf7dcb1734cc14061e1c2f814d5efa2990e4b9c6eb06425bc43211f3`。
- shared-public 新路径完成公共 archive、NodeSlot shard 和 index 分发，pre-launch
  `cleanup-ready=10/10`；没有重建 AMI，也没有远端编译。
- runner 启动 `10/10`，协议 readiness `7/10`，协议最终 `success=10/10`，收集 `10/10`。
- 十个 artifact 的 consensus hash 全部为
  `28470e01498da4ed8dd55d8b7970cc90f1617af8862b2c30f8798a0f3d5287db`，setup digest 一致，
  candidate fan-out retries 总数为 `0`。

本轮单 epoch ARL smoke 指标（只用于部署/规模 sanity check，不进入论文统计主表）：平均
service-grace-adjusted latency `10071.77 ms`，raw latency `11072.44 ms`，setup `119.23 ms`，
candidate formation `4995.80 ms`，每节点平均发送/接收 `3.451/3.372 MB`。n=10 的 candidate 和
recovery 成本明显高于 n=4，符合协议规模增长预期；这轮目标是证明现有 AMI 能承载新部署流程，不能
单独归因于 AMI 或宣布性能结论。

实验记录时间为 `14:50:25Z--15:00:26Z`，随后完成 `cleanup-ready=10/10` 和两区 Terraform destroy。
按十台 Spot 实例约 10--15 分钟生命周期、十个公网 IPv4、`10 x 30 GiB` gp3、SSM 与少量跨区流量，
本轮保守记 **约 `$0.14`**；AWS 只读复核显示两区 non-terminated instance 与 open/active Spot
request 均为零。累计量化成本由约 `$2.75` 更新为约 **`$2.89`**，最终以 Cost Explorer 为准。

结论：现有 AMI 足以支持优化后的百节点方向部署路径，当前没有重建 AMI 的必要。下一步若进入
`n>=100`，应先复用同一 AMI 做纯 setup/deployment soak，再决定是否把稳定 binary 预置进新 AMI；
AMI bake 不应与论文协议 latency 样本混在同一轮。

## 2026-08-19 PracticalADKR 同 topology 跨 Region smoke（r21）

为回答 ARL r20 的同 topology 对照问题，本轮新增并执行 Practical-only runner
`practicaladkr_project_code/deployment/run_practical_cross_region.py`。它复用了同一套 Terraform、
公网 `/32` allowlist、SSM shared-public setup、10 节点 cleanup-ready barrier 和 artifact collector，
没有先在同一 fleet 上运行 ARL，也没有重建 AMI。实验名为
`practical-use1-euw1-n10-r21-20260819`，拓扑与 ARL r20 完全一致：`us-east-1:5`（`use1-az1`）+
`eu-west-1:5`（`euw1-az1`），`n=10,f=3`，`c7g.xlarge` Spot，现有 AMI；参数为
`runs=1`、`paillier-bits=3072`、`kappa-profile=matched-lifetime`、`mvba-network=tcp`、
`strict-network=true`、`comm-metrics=true`。

部署和结果完整性：

- 两区 SSM `aws-up=10/10`，setup bundle digest 为
  `653b68ea4946e30e21a35f335ea5abf5e40232a8e91d92ed2ff31d87b067870f`，10/10 节点完成 cleanup-ready；
- Practical readiness `10/10`（quorum=7），最终 `success=10/10`，artifact 收集 `10/10`；
- 十个节点的 consensus hash 均为
  `3f3855face8f9948e583a805d7efb08c84d6d6c3a72c1a637983bf030c57da82`，fallback/timeout 均为 0；
- 运行从 `15:19:12Z` 到 `15:42:46Z`，随后两区 Terraform 资源全部销毁，最终 cleanup-ready barrier
  通过，non-terminated instance 和 Spot request 均为 0。

十个节点 artifact 的逐节点范围和均值如下。这里的均值是同一轮各节点报告的 local e2e latency
的算术平均；因为只有一个 epoch，它是 smoke 描述统计，不是论文主表的 median/p95 结论。

| 指标 | 节点范围 | 10 节点均值 |
| --- | ---: | ---: |
| `mean_latency_ms` | `6171.45--7480.80` ms | **`6541.07` ms** |
| `mean_online_protocol_ms` | `6163.63--7472.95` ms | **`6533.18` ms** |
| `mean_setup_ms` | `7.72--7.99` ms | **`7.86` ms** |
| `mean_dxt_dealing_ms` | `738.53--1352.42` ms | `938.50` ms |
| `mean_apdb_dispersal_ms` | `275.88--508.49` ms | `425.95` ms |
| `mean_mvba_agree_ms` | `1266.10--1267.67` ms | `1266.44` ms |
| `mean_recover_ms` | `1577.08--1752.84` ms | `1607.71` ms |
| `mean_derive_ms` | `1198.32--1917.33` ms | `1357.86` ms |
| `mean_aggregate_derive_ms` | `3615.58--4295.16` ms | `3764.31` ms |
| `mean_total_sent_bytes` | `984,441--1,050,770` B | **`1,033,708` B** |
| `mean_total_recv_bytes` | `1,002,636--1,046,333` B | **`1,028,170` B** |

### 对结果的判断

这轮 Practical 数据在协议和统计完整性上符合预期：所有节点成功、决定集合为 7、选择/验证数量为
`4/4`、共识 hash 一致，setup 也被明确排除在 online latency 外。它比同 AZ n=10 的既有
`4.10--4.44 s` smoke 高约 `2.1--2.4 s`，但仍低于同一跨区 topology 的 ARL r20
`10.07177 s`（约低 35%）。通信量约 `1.034/1.028 MB` 每节点，也与 Practical 的单 lane
协议结构相符，明显低于 ARL r20 的 `3.451/3.372 MB`；没有发现因 artifact 截断、fallback、
本地 shortcut 或 quorum 不足造成的虚低数据。

跨区增量不能简单解释成公网 RTT 本身。Practical 的 MVBA agree 在节点间几乎稳定在 `1.266 s`，
而 DXT dealing/network wait、APDB dispersal、recovery 和 derive/aggregate derive 的 barrier
会把跨区的几十毫秒级 RTT 放大为多轮等待；最高的 `7.481 s` 节点同时出现 `derive=1.917 s`、
`aggregate_derive=4.295 s`，说明尾部主要来自协议阶段和节点本地计算/调度，而不是单个 TCP 握手。
因此本轮结果“方向上合理”，但不能用单 epoch 证明固定的跨区开销，更不能把 6.541 s 直接作为论文
最终性能结论。正式比较仍应在该 fresh-fleet topology 下各运行至少 5--10 个 epoch，报告 median、
p95、阶段分布和通信量；ARL 与 Practical 必须继续使用相同 AMI、n/f、TCP、setup 排除口径和
cleanup barrier。

本轮十台 Spot 实例约 23.6 分钟生命周期，按两区 c7g.xlarge Spot、10 个 30 GiB gp3、临时公网
IPv4、SSM 和少量跨区流量保守计 **约 `$0.24`**，累计量化成本由约 `$2.89` 更新为约 **`$3.13`**；
最终账单以 Cost Explorer 为准。该轮仍属于实验 smoke，未修改协议设计。

## 2026-08-20 ARL 公网延迟异常审计（不启动 AWS）

本轮只做本地 A/B 和代码审计，没有创建实例，也没有新增 AWS 成本。审计对象是
`paper-arl-use1-euw1-n10-deploy-r20-20` 的 `n=10,f=3`、`us-east-1:5 + eu-west-1:5` 公网结果。

结论：数据不是统计脚本把 service grace 重复计入造成的。r20 的平均值为
`mean_latency=10071.77 ms`、`mean_raw_latency=11072.44 ms`、`service_grace=1000.18 ms`，
十个节点成功且 consensus hash 一致。candidate ACK 等待均值约 `63.91 ms`，重试为 `0`，
所以 candidate ACK backoff 不是主要瓶颈。

最可疑的代码路径是 `core/transport_tcp_loopback.go` 的 pooled TCP：每个 frame 写入后必须
等待远端 1-byte transport ACK；同一 `(from,to,tag)` 的 pooled connection 由 `pc.mu` 串行保护。
而 `cvRunSampledProposerSlotsV2` 同时运行多个 proposer，多个 component/APDB recovery 请求会
共享同一 peer/tag 连接。公网每条消息都引入一次 WAN RTT，本地 loopback 不会暴露该排队效应。
component INIT 还在 `disperseComponentWire` 中逐 holder 同步发送，进一步放大跨区 RTT。

对照结果：

- `ff91394` 的本地严格 TCP n=10 smoke 约 `6.13 s`，说明协议阶段本身并非固定 10 秒；
- 当前 `d63add8`/未提交 WAN 优化工作区的本地结果在 `8.0--10.5 s` 间波动，不能直接作为论文基线；
- 在 loopback 临时注入约 `35 ms` 单向延迟（约 `70 ms RTT`）时，基线一次运行达到约 `39.68 s`，
  仅 `7/10` 达到 quorum，且 proposer component recovery 累积约 `23.5 s`。实验结束后 qdisc
  已确认恢复为 `noqueue`。

因此，公网 r20 的约 10 秒是当前 transport ACK/连接串行化对 WAN RTT 的放大结果，数据并非虚低或
单纯报告错误。一个未改变协议语义的本地原型已按 recovery payload digest 将 bulk 消息稳定分到
3 条 pooled lane；在 `ff91394` 本地 n=10 上从约 `6.13 s` 降至约 `4.64 s`，并达到 `10/10`
完成。35 ms 单向 RTT 注入下，原型约 `36.68 s`，较单 lane 的约 `39.68 s` 有限改善，说明
连接并发确实命中瓶颈但不能单独消除 WAN 多轮等待。该原型仍需补充按 tag 的 ACK RTT、pool lock
wait、dial 次数和 recovery request 消息计数，再决定是否纳入正式实现；在此之前不应把 r20
与 Practical 的延迟直接作为论文最终结论，也不应重建 AMI。

## 2026-08-20 本地 n=10 recovery/scalar-exchange liveness 收口

本轮继续使用本地严格 TCP `n=10,f=3` 审计上述候选版，没有启动 AWS、没有创建云资源，新增 AWS
成本为 `$0`，累计量化成本仍约 **`$3.13`**。

首先修正了本地共享主机 harness 的启动条件：component listener 默认等待全部 `n` 个进程，独立
MVBA listener 默认等待全部 peer，并按 `host_cpus/n` 设置每节点 `GOMAXPROCS`。这些只是本地 artifact
收集与共享 CPU 调度规则；协议、AWS runner 和最终成功条件仍为 `n-f`。

随后通过 60 秒 settle 和 Go `SIGQUIT` 堆栈确认存在两条真实 liveness 问题：

- APDB aggregate recovery 首轮 transport send 只有 `3/4` 成功时立即返回。现在保留初始全 holder
  并行 fan-out，只对发送失败的 holder 做 4 次指数退避重试；recipient 集合和 `dataShards=4` 不变，
  collector 继续按认证 holder/index 幂等去重。
- `RecoverAndExchangeScalarShare` 和 `FinalizeDecision` 原来每 250 ms 向整个 roster 无限重发。早完成
  节点退出后，尾部节点可能永远达不到 `n-f=7` 并持续增加通信量。两条路径现在只向尚未贡献有效
  share 的 peer 做 4 次有界重试，阈值仍为 `n-f`；不足时返回明确错误，不再静默卡死。

本地共享主机上，500 ms route timeout 只保留约 1 秒 recovery-service grace，CPU 调度尾部会让 honest
receiver 在 holder 退出后才开始 aggregate recovery。将现有 route timeout 设为 1 秒会选择既有的
10 秒 holder-service grace，且报告口径已从 latency 中扣除此 grace。因此 `run_cv_cluster.sh` 现在仅对
本地 harness 默认使用 `1s`；AWS runner 未改，后续公网复测应显式记录该参数。

最终代码的本地严格 TCP 诊断轮为：

- `10/10` 节点成功，quorum=`7`，all-success=`true`，consensus hash 只有 1 个；
- quorum latency `8660.64 ms`，all-nodes latency `8724.17 ms`，节点均值 `8633.06 ms`；
- mean setup `145.72 ms`，平均发送/接收约 `4.891/4.809 MB` 每节点；
- 没有 `APDB recovery reached ... holders`、scalar-share threshold、decision threshold 或 timeout 错误。

该轮只证明 liveness 收口。共享主机多进程的 leaf/candidate 调度波动仍很大，同一候选版曾出现 quorum
约 `4.36 s` 的运行，因此 `8.66 s` 不能作为论文性能基线。下一步应先提交并推送当前候选版，再在
相同 `us-east-1:5 + eu-west-1:5` Spot topology 上复测 ARL `n=10`，同时记录 route timeout、service
grace、成功节点数、candidate/recovery 分解和通信量；在新公网数据稳定前不重建 AMI。

## 2026-08-20 ARL liveness 候选版两区域公网复测（r22）

上述候选版已提交并推送到 `origin/main`，提交为
`905679c Harden WAN recovery and share exchange liveness`。随后执行实验
`paper-arl-use1-euw1-n10-r22-20260820`，继续使用与 r20/r21 相同的
`us-east-1:5`（`use1-az1`）加 `eu-west-1:5`（`euw1-az1`）公网 Spot topology、现有 AMI、
`c7g.xlarge`、`n=10,f=3`。参数为 `runs=1`、`epochs=1`、`strict-network`、
`comm-metrics`、`route-send-timeout=1s`；因此 holder service grace 为约 10 秒，并按既定
`service_grace_adjusted` 口径从报告 latency 中扣除。setup/keygen 仍在 online latency 之外。

部署版本和完整性：

- 本地按 runner 相同的 `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath` 重新构建，
  `rladkrbench` SHA-256 为
  `9841a42f08e865a57dc17421d61c054aac42241c4cc78ff0e23287a1390d19ee`，与实验记录完全一致；
  Go build metadata 指向 `905679c`。
- 两区 SSM `aws-up=10/10`，setup bundle digest 为
  `ca0111697b1c165319dfbc94c5d77bdd3755b6f48583359ec7322cac620a3868`；pre-launch
  `cleanup-ready=10/10`、runner readiness `10/10`，成功门槛保持 `n-f=7`。
- 最终 `success=10/10`、artifact `10/10`，十个节点 consensus hash 均为
  `0de65ee061ad37275feb849bda46d9b0ecf0d9956796f8ffa80e4c7367a26b4f`；setup digest 和 timing
  metadata 一致，没有 timeout、threshold failure 或错误 summary。

本轮单 epoch 节点统计如下。quorum latency 是按十个节点 local latency 排序后的第七个值；它与
runner 的 `n-f` 成功条件一致。这里只作为候选版公网 smoke，不进入论文最终 median/p95 主表。

| 指标 | 节点范围/门槛 | 10 节点均值 |
| --- | ---: | ---: |
| service-grace-adjusted latency | `8935.16--9436.79` ms | **`9093.36` ms** |
| raw latency | `18935.53--19437.18` ms | `19093.95` ms |
| quorum / all-nodes adjusted latency | `9121.64 / 9436.79` ms | - |
| setup / online protocol | - | `119.23 / 8974.13` ms |
| leaf build | `1240--2676` ms | `2227.90` ms |
| component dispersal | `635--1026` ms | `789.70` ms |
| candidate formation | `3603--4794` ms | **`4017.80` ms** |
| aggregate agreement | `637--838` ms | `756.60` ms |
| aggregate recovery after decision | - | `138.37` ms |
| APVSS ACK / fallback count | - | `7.2 / 2.8` |
| candidate fan-out retries | all nodes `0` | `0` |
| total sent / received | - | **`4.106 / 4.020 MB` per node** |

### 对结果的判断

本轮证明 liveness 修复在公网路径成立：APDB holder 发送、scalar-share exchange 和 decision
finalization 都没有出现阈值不足或无限重发，10/10 节点完成，且新增有界 retry 实际没有触发。
两区节点的 adjusted latency 均值分别为 `9093.42 ms`（美国）和 `9093.31 ms`（爱尔兰），几乎相同，
不存在单一 Region 尾节点拖慢结果的现象。

相对 ARL r20，adjusted latency 从 `10071.77 ms` 降到 `9093.36 ms`，改善约 **9.7%**；candidate
formation 从 `4995.80 ms` 降到 `4017.80 ms`，改善约 **19.6%**。但这还没有把 ARL 降到同 topology
Practical r21 的 `6541.07 ms`：当前仍慢约 `2552 ms`（约 39%）。aggregate recovery 后的新
recovery/share exchange 仅约 `138 ms`，candidate retry 为 0，说明本轮刚修复的尾部重试路径已经不是
主要性能瓶颈。剩余差距主要集中在 leaf build（均值 `2.23 s`）和 candidate proposer slots（candidate
总计约 `4.02 s`），同时 ARL 通信量约 `4.106/4.020 MB` 每节点，仍约为 Practical r21
`1.034/1.028 MB` 的四倍。因此结论是“公网 liveness 问题已解决、WAN 性能部分改善”，不能写成
“ARL 已达到 Practical 延迟”。下一步应围绕 leaf/candidate 的计算与多轮公网等待做不改变协议设计的
profiling；在获得多 epoch 数据前仍不重建 AMI，也不把单轮 smoke 当作论文最终结果。

资源与成本：美国五台实例实际生命周期为 `08:20:54Z--08:34:23Z`（每台 809 秒），爱尔兰五台为
`08:21:58Z--08:32:43Z`（每台 645 秒）。按当时 `us-east-1a $0.0736/小时`、
`eu-west-1c $0.0752/小时` 的 Spot 价，计算费约 `$0.150`；加十个临时公网 IPv4、`10 x 30 GiB`
gp3 和少量 SSM/S3/跨区流量后，本轮保守记 **约 `$0.17`**。累计量化成本由约 `$3.13` 更新为约
**`$3.30`**，最终仍以 Cost Explorer 为准。实验结束后两区 Terraform 各销毁 21 个资源；AWS 只读
复核显示 non-terminated instance 与 open/active Spot request 均为 0。

## 2026-08-20 ARL 单区域同 AZ 私网对照（r23）

为隔离跨 Region 公网路径对 r22 的影响，执行实验
`paper-arl-private-use1-n10-r23-202608`。10 台 `c7g.xlarge` Spot 全部位于
`us-east-1f`（`use1-az5`），协议 roster 使用 `10.42.1.10--19` 私网地址；security group 只允许
同组节点私网互通，不开放公网协议 ingress。AMI 为 `ami-0cee8a82967ef97ac`，参数保持
`n=10,f=3,runs=1,epochs=1`、`strict-network`、`comm-metrics`、
`route-send-timeout=1s`。成功门槛仍为 `n-f=7`，holder service grace 仍按既定
`service_grace_adjusted` 口径扣除，setup/keygen 仍不计入 online protocol。

本轮为编排地址选择增加了显式 `use_private_ip` 支持，使 runtime roster 与 topology 配置一致；
该调整只改变实验网络地址，不改变 ARL 协议、安全阈值或 latency 口径。部署归档 SHA-256 为
`30a955ff13bc9223a5c3a54c961fe785f8bcd0452f7fe679dfa5ce18f295f7e4`，其中
`rladkrbench` SHA-256 为
`f41623d824ecbe0ed2c71177628de07a5f27c3639749b9ef6774c203177a4b33`。
setup bundle digest 为
`6078821bb505b642e723dcf63811c93482702f6f63cba7ad767a6e3acbb083ee`。

运行完整性：SSM、pre-launch cleanup、runner readiness 均为 `10/10`；最终 success 和 artifact
均为 `10/10`。十个节点 consensus hash 均为
`eefd8c4095681b2b44cd8c2aa5743ab7300ab196875d9c91036d51ac23a4f77f`，setup digest 和 timing
metadata 一致，没有 timeout 或错误 summary。以下仍只是单 epoch topology smoke，不进入论文最终
median/p95 主表。

| 指标 | 节点范围/门槛 | 10 节点均值 |
| --- | ---: | ---: |
| service-grace-adjusted latency | `4146.78--4863.10` ms | **`4407.50` ms** |
| raw latency | `14147.14--14863.42` ms | `14407.91` ms |
| quorum / all-nodes adjusted latency | `4435.64 / 4863.10` ms | - |
| setup / online protocol | - | `119.36 / 4288.13` ms |
| leaf build | `470--1031` ms | `855.80` ms |
| component dispersal | `36--51` ms | `39.80` ms |
| candidate formation | `2432--3132` ms | **`2704.40` ms** |
| proposer slots | `2409.81--2749.53` ms | `2629.95` ms |
| aggregate agreement | `195--204` ms | `200.30` ms |
| aggregate recovery after decision | `43.73--66.34` ms | `56.83` ms |
| APVSS ACK / fallback count | - | `9.1 / 0.9` |
| candidate fan-out retries | all nodes `0` | `0` |
| total sent / received | - | **`4.862 / 4.852 MB` per node** |

### 与两区域公网 r22 的对照

同 AZ 私网 adjusted latency 均值为 `4407.50 ms`，比 r22 的 `9093.36 ms` 低
`4685.86 ms`，约 **51.5%**；quorum latency 从 `9121.64 ms` 降至 `4435.64 ms`。
主要阶段也同步缩短：leaf build 从 `2227.90 ms` 降至 `855.80 ms`，candidate formation 从
`4017.80 ms` 降至 `2704.40 ms`，component dispersal 从 `789.70 ms` 降至 `39.80 ms`，aggregate
agreement 从 `756.60 ms` 降至 `200.30 ms`。candidate retry 在两轮均为零，因此差距不是 retry
退避造成；它表明公网跨区运行的主要额外代价位于多轮通信和远端数据获取路径，而不是最终
aggregate recovery。私网通信量均值略高于 r22（`4.862/4.852 MB` 对 `4.106/4.020 MB`），来自节点
角色分布和单轮消息到达顺序的差异；仅凭这两个单 epoch 样本不能断定通信量随 topology 的稳定变化。
两轮均报告相同的协议模式、阈值和主要 wire size，因此没有证据表明私网轮次通过跳过协议步骤降低 latency。

本结果也说明当前代码在同 AZ 私网下仍有约 `2.63 s` 的 proposer slots 和约 `0.86 s` 的 leaf
构建计算成本；因此 `4.41 s` 是当前实现的可信单轮基线，而不是网络近零时协议应瞬时完成。后续若要形成
论文数据，应在相同 AMI 和 topology 下运行多 epoch、多次独立 fleet，报告 median/p95，并用同样口径
运行 PracticalADKR 对照。

资源与成本：实例实际约在 `08:46:10--14Z` 启动、`08:58:56--58Z` 终止，累计约 7657
instance-seconds。按当时 `us-east-1f c7g.xlarge` Spot 价 `$0.0523/小时`，计算费约 `$0.111`；加十个
临时公网 IPv4（仅用于 SSM/部署）、`10 x 30 GiB` gp3 和少量 SSM/S3 流量后，本轮保守记
**约 `$0.13`**。累计量化成本由约 `$3.30` 更新为约 **`$3.43`**，最终仍以 Cost Explorer 为准。
实验后 cleanup-ready 为 `10/10`，Terraform 销毁 20 个资源；AWS 只读复核显示该 ExperimentGroup
的 non-terminated instance 和 open/active Spot request 均为 0。

## 2026-08-20 ARL TCP 传输层对照 PracticalADKR 的修复（本地验证）

针对 r22 公网与 r23 同 AZ 私网的阶段差异，进一步对照了 PracticalADKR 的传输实现。Practical 的
MVBA pooled TCP 在一条连接上只等待完整 frame 写入，不等待额外的 transport ACK；接收端持续读取
length-prefixed frame，并把消息交给协议 inbox。Practical 的 application-level DXT/APDB 仍通过
receipt、certificate ACK 和阈值消息完成可靠性，因此没有把每个通用 TCP frame 都变成 stop-and-wait
RPC。

ARL 原先的 `core/transport_tcp_loopback.go` 在每个 frame 写入后等待远端 1-byte ACK，并在同一
`(from,to,tag,lane)` pooled connection 上持锁直到 ACK 返回。跨 Region 时，这会把多个 proposer、coin、
certificate 和 recovery 消息串成 WAN RTT 队列；同 AZ 私网中则几乎不显现。该路径与协议层 candidate ACK、
APDB receipt 不是同一种确认，属于传输层重复确认。

本次实现调整保持协议 wire、认证封装、阈值和密码学检查不变：

- ARL TCP `Send` 改为写入完整 frame 后返回，连接锁只覆盖写入；删除冗余的 transport ACK 读写。
- pooled connection 的接收端在 idle read timeout 时继续等待，并在 inbox 满时施加 TCP 自然反压，不再
  静默丢弃消息；这与 Practical 的 `readConn` 行为一致。
- pooled connection 并发建连时保留先进入连接池的连接，关闭重复连接，避免 WAN 下连接替换抖动。
- CV lane offer 从逐 receiver 顺序发送改为已有的最多 16 路 bounded fan-out；仍发送相同 offer、仍要求
  原有 ACK quorum 和 fallback 规则。
- 本地 `deployment/docker/run_proc_sim.py` 删除已经从 `rladkrbench` 移除的旧
  `-fallback-policy force` 注入，并在启动计时前生成共享 CV setup、为每个进程设置独立 secret/state 目录。
  这是实验编排修复，不改变协议设计或论文 latency 口径。

验证结果：`go test ./core -run 'TestTCP|TestCVACKSettleGrace|TestCVAPDBNetwork|TestCV.*Lane|TestWaitForRemoteNodeReadiness|TestNewTCPLoopback' -count=1`
通过；`go test ./... -run '^$'` 编译检查通过；新增测试覆盖 write-only remote send、idle pooled connection
和 inbox backpressure。随后本地严格 TCP proc-sim 使用当前二进制运行：`n=10,f=3` 达到 `8/10` 成功、
共识 hash 一致，`n=4,f=1` 达到 `3/4` 成功；失败节点分别出现在 APDB recovery 或 MVBA 尾部，而不是
参数解析、setup、listener 或 frame 丢包。由于 proc-sim 中每个节点完成本地 epoch 后会独立退出，快节点
退出可能使慢节点在最终 recovery/MVBA 阶段失去服务者；因此这些本地轮次只作为传输回归 smoke，不作为
性能或全节点成功数据。

该修复尚未在 AWS 公网重测，未产生 AWS 费用，也不应把 r22/r23 结果回写为修复后的公网性能。下一轮应在
fresh fleet、相同 `us-east-1:5 + eu-west-1:5` topology 下使用新二进制运行 ARL，并同时运行 Practical
对照；必须确认 `10/10` artifact、单一 consensus hash、协议 listener 在最终 cleanup barrier 前保持可用，
再比较 adjusted latency、candidate formation、component dispersal、recovery 和通信量。

## 2026-08-20 ARL TCP 修复版两区域公网 fresh-fleet 复测（r24）

使用实验 `paper-arl-use1-euw1-n10-r24-20260820` 在与 r22 完全相同的公网 topology 上复测当前本地
TCP/fan-out 修复：`us-east-1:5`（`us-east-1a`）加 `eu-west-1:5`（`eu-west-1c`），10 台
`c7g.xlarge` Spot，`n=10,f=3,runs=1,epochs=1`，启用 `strict-network`、`comm-metrics` 和
`route-send-timeout=1s`。协议 roster 使用公网地址；成功门槛仍为 `n-f=7`，holder service grace
仍按既定 `service_grace_adjusted` 口径扣除，setup/keygen 仍不计入 online protocol。未重建 AMI，runner
从当前工作树重新构建并分发 ARM64 二进制；`rladkrbench` SHA-256 为
`4cf49546c2a2d8838ff6623a3195547f96771760062d3af73351ff09595a0420`。

运行完整性：两区 SSM、pre-launch cleanup 和 runner readiness 均为 `10/10`；setup bundle digest 为
`0a3ab4245f85efa853709954a5c4fbe8545795148657904548ea1c82a95407a3`，十个节点一致。最终 success 和
artifact 均为 `10/10`，十个节点 consensus hash 均为
`285c83457579b38395caff5566c4381f80e0a15f0b70f63b93f9ba78d8e8d84d`，没有 timeout、错误 summary
或 candidate retry。以下仍是单 epoch fresh-fleet smoke，不进入论文最终 median/p95 主表。

| 指标 | 节点范围/门槛 | 10 节点均值 |
| --- | ---: | ---: |
| service-grace-adjusted latency | `5892.95--6854.25` ms | **`6530.37` ms** |
| raw latency | `15893.13--16855.21` ms | `16530.63` ms |
| quorum / all-nodes adjusted latency | `6680.00 / 6854.25` ms | - |
| setup / online protocol | - | `119.29 / 6411.09` ms |
| leaf build | `838--1295` ms | **`1071.90` ms** |
| component dispersal | `225--639` ms | **`404.10` ms** |
| candidate formation | `3257--3482` ms | **`3371.20` ms** |
| eligibility coin / proposer slots | - | `42.57 / 3328.62` ms |
| candidate ACK wait / max-peer fan-out | - | `1.64 / 15.79` ms |
| aggregate agreement | `653--719` ms | `684.80` ms |
| aggregate recovery after decision | `69.68--70.07` ms | `69.85` ms |
| APVSS ACK / fallback count | `8--9 / 1--2` | `8.7 / 1.3` |
| candidate fan-out retries | all nodes `0` | `0` |
| total sent / received | - | **`4.959 / 4.951 MB` per node** |

### 与 r22 和 r23 的判断

在相同公网 topology 下，r24 adjusted mean 从 r22 的 `9093.36 ms` 降至 `6530.37 ms`，下降
`2562.99 ms`，约 **28.2%**；quorum 从 `9121.64 ms` 降至 `6680.00 ms`，all-nodes 从
`9436.79 ms` 降至 `6854.25 ms`。分阶段看，leaf build 下降约 **51.9%**，component dispersal
下降约 **48.8%**，candidate formation 下降约 **16.1%**，aggregate agreement 下降约 **9.5%**，
decision 后 aggregate recovery 下降约 **49.5%**。candidate ACK wait 均值只有 `1.64 ms`，retry 为
零，说明删除通用逐 frame transport ACK、缩短连接锁范围和 lane bounded fan-out 确实命中了 r22 的
WAN 串行等待，而没有通过放宽协议 ACK、阈值或密码验证获得数字。

r24 adjusted mean 与相同 topology 的 Practical r21 单轮均值 `6541.07 ms` 接近，但不能据一个 epoch
宣称两者性能等价：ARL 本轮每节点通信量约 `4.959/4.951 MB`，仍约为 Practical r21
`1.034/1.028 MB` 的 4.8 倍，而且两套协议的密码工作和安全口径不同。相对同 AZ 私网 r23，公网 r24
仍高 `2122.87 ms`；主要差异位于 candidate、component、agreement 和远端恢复通信，已经不再呈现 r22
那种额外 transport ACK 造成的近一倍放大。正式论文数据仍应在 clean commit 上对 ARL 与 Practical
分别执行多次独立 fresh fleet，并报告 attempt 成功率、median 和 p95。

资源与成本：美国五台实例约从 `10:04:48--49Z` 运行到 `10:14:25--26Z`，每台约 577 秒；爱尔兰
五台从 `10:05:36Z` 运行到 `10:13:09Z`，每台约 453 秒。按当时
`us-east-1a c7g.xlarge $0.0731/小时` 和 `eu-west-1c $0.0752/小时` 的 Spot 价，计算费约
`$0.106`；加临时公网 IPv4、短时 `10 x 30 GiB` gp3、SSM/S3 和少量跨区流量，本轮保守记
**约 `$0.12`**。累计量化成本由约 `$3.43` 更新为约 **`$3.55`**，最终仍以 Cost Explorer 为准。
实验完成后两区 Terraform 各销毁 21 个资源；AWS API 复核两区 non-terminated instance 和
open/active Spot request 均为 0。

## 2026-08-20 百节点公网前置扩展性修复（仅本地代码验证）

在 r24 证明逐 frame transport ACK 已移除后，继续针对 `n>=100` 的实现瓶颈完成了不改变协议
消息、密码学关系和阈值的扩展性修复。本轮没有启动 AWS 资源，因此新增费用为 `$0`，累计量化成本
仍为约 `$3.55`。

ARL 修改如下：

- 保留并纳入当前提交的 write-only pooled TCP、idle connection 和 inbox backpressure 修复；
- `cvAPDBNetworkServiceV2` 将 receiver lane offer 与 certified candidate 的重密码学验证移入同一个
  有界 worker queue，主 dispatch 继续顺序处理 coin、receipt、certificate 和 recovery 控制消息；
- lane offer 按 `(dealer,receiver)` 去重，candidate 按 canonical digest 去重；candidate delivery ACK
  仍在进入验证队列前发送，不改变 ACK 的“认证 envelope 已到达”语义；
- candidate fan-out 不再固定 4 路，而按 peer 数使用 `8/16/24/32` 路并发，最大 64，支持
  `RLADKR_CANDIDATE_FANOUT_PARALLEL` 覆盖；
- crypto queue 最小 64、最大 2048，worker 数继续受 `RLADKR_CRYPTO_WORKERS` 和现有 CPU 上限约束。

PracticalADKR 修改如下，并已同步到 ARL 仓库的 `experiments/practical-adkr` 镜像：

- DXT transcript 接收不再为每个连接同时执行无界 full verification，而是进入有界队列，默认使用
  `GOMAXPROCS-1`、最多 4 个 worker；可用 `PRACTICAL_DXT_VERIFY_WORKERS` 覆盖；
- DXT deadline 从固定 4 秒改为随委员会规模增长：`n<32` 为 8 秒，随后在
  `32/64/96/128/192` 起使用 `30/90/180/300/600s`；仍可由 `PRACTICAL_DXT_TIMEOUT_MS` 覆盖；
- `bench_latency` 未显式传入 timeout 时使用 `90/300/600/900/1200/1800s` 的规模化预算。

AWS 编排修改如下：

- Fabric 会为 ARL 和 Practical 显式补齐 scale-aware `-timeout`，cross-region wait timeout 至少比
  binary timeout 多 300 秒；
- 公网来源不超过 48 时保留每节点 `/32` allowlist；超过 48 时 Terraform 自动切换为一个临时
  large-fleet CIDR rule，默认 `0.0.0.0/0`，避免 SG 默认入站规则额度阻止 n=100 apply；该 CIDR
  可配置，实验记录会写入实际 ingress mode；
- large-fleet rule 只覆盖协议端口，并随本轮 Terraform state 销毁。该模式依赖协议认证，仅用于
  临时论文实验，不作为生产安全组方案。

本地验证：ARL transport/candidate/APDB 定向测试通过，约 25 秒；Practical DXT 与 benchmark timeout
测试通过，约 8 秒；Fabric `44/44` 测试通过；Terraform `fmt -check` 和 `validate` 通过。尚未运行
百节点 AWS 数据，因此这些修改只能说明已移除已知实现和编排硬限制，不能预先宣称 n=100 latency
已经符合预期。下一轮仍应按 `n=32 -> 64 -> 96 -> 128` 逐档记录 phase、CPU、RSS、连接数、重传和通信量。
