# ARLADKR 与 PracticalADKR AWS 公网实验推荐流程

## 1. 目标与范围

本文描述如何在 AWS 上对以下三组实验进行可复现比较：

- ARLADKR；
- PracticalADKR，默认 `matched-lifetime` 采样；
- PracticalADKR，`high-assurance` 采样。

目标是测量真实 EC2 网络和真实多进程 TCP 路径，不使用 `public20`、延迟矩阵或其他协议内
人工传播延迟。当前 ARLADKR 和内置 PracticalADKR 已删除协议内模拟延迟支持。AWS 配置中的
`fault_injection.netem.enabled` 必须保持为 `false`。

本文面向学术论文实验，不把部署系统扩展成长期在线服务。基础设施应当是短生命周期、可重复
创建、实验结束后可完整删除的临时资源。

## 2. 实验口径

### 2.1 三类网络实验

建议把实验拆成三个层次，分别报告，不合并为一组结果：

| 层次 | 节点通信地址 | 主要用途 | 是否属于真实 WAN |
|---|---|---|---|
| 单 AZ | 私网 IP | 计算与协议扩展性基线 | 否 |
| 同 Region 多 AZ | 私网 IP | 区域内真实网络与跨 AZ 成本 | 否 |
| 多 Region | 私网互联或公网 IP | 广域网延迟与跨 Region 流量 | 是 |

同 Region 的 EC2 即使使用公网 IP，也不能代表独立运营商之间的互联网。论文中应写明 Region、
AZ 分布、地址类型和实测 RTT，不能只写“公网”。

### 2.2 节点与实例映射

当前 AWS setup provisioner 强制一台主机只拥有一个 old-committee 逻辑节点。对应的 new
receiver `n+i` 与 old node `i` 位于同一台实例。因此：

- `n=16` 需要 16 台实例；
- `n=64` 需要 64 台实例；
- `n=256` 需要 256 台实例，而不是 512 台；
- `f=floor((n-1)/3)`，因此 `n=256` 时 `f=85`。

不要为了降低成本在最终论文实验中把多个逻辑节点装进同一实例。这样会引入共享 CPU、内存、
loopback 和内核调度优势，破坏与一节点一实例结果的可比性。

### 2.3 公平比较要求

三组实验必须保持以下条件相同：

- EC2 实例类型、CPU 架构、AMI、Go 版本和构建参数；
- Region/AZ 分布、Security Group 和地址类型；
- `n`、`f`、epoch 数量、超时和通信量统计开关；
- 离线 setup 是否计时、缓存冷暖状态和日志级别；
- 每个数据点的独立运行次数和失败数据处理规则。

ARLADKR 与 PracticalADKR 的安全参数不是同一个变量。两者的 `original` 和 `high-assurance`
必须先对应同一个总失败预算 `Delta`，再分别由各自的公式求解样本；不能只凭 profile 名称判定等价。
ARL runner 会输出总预算、每项 `Delta/2`、精确失败概率和实际 proposer/validator sample。

每个远端进程使用 `runs=1`、一个新 epoch。重复测量通过多个独立 `run_id` 完成，不在同一进程
中连续运行多个 epoch。

Fabric 会在未显式给出 `-timeout` 时按协议和委员会规模写入 timeout，而不是依赖二进制的小规模默认值。
当前 AWS 预算为：ARL 在 `n=64/96/128/192` 起分别使用 `120/180/300/600s`；Practical 在
`n=32/64/96/128/192` 起分别使用 `300/600/900/1200/1800s`。这些数值只是失败判定预算，不从
成功轮次 latency 中扣除，也不能用于掩盖协议停滞。

ARL 的重密码学 dispatch 使用有界 worker queue；默认 worker 数复用 `RLADKR_CRYPTO_WORKERS`，
candidate fan-out 可用 `RLADKR_CANDIDATE_FANOUT_PARALLEL` 覆盖。Practical 的 DXT transcript
验证使用最多 4 个 worker，可用 `PRACTICAL_DXT_VERIFY_WORKERS` 覆盖；单连接 DXT deadline 随
委员会规模增长，也可用 `PRACTICAL_DXT_TIMEOUT_MS` 显式覆盖。正式数据必须记录这些环境变量。

## 3. 推荐的规模推进顺序

不要直接从 n=4 跳到 n=256。建议按以下门槛推进：

| 阶段 | n | 进入下一阶段的最低条件 |
|---|---:|---|
| 功能 smoke | 4 | 4/4 成功、单一 consensus hash |
| 小规模公网 | 16 | 至少 `n-f` 成功，无 timeout/fallback |
| 中规模 | 32 | 三种配置均完成至少 3 次独立运行 |
| 扩展性 | 64 | CPU、内存、流量和端口无明显异常 |
| 大规模 | 128 | 延迟和通信量增长可以解释 |
| 最大规模 | 256 | 配额、Spot 容量和预算均已验证 |

n=256 使用 `c7g.xlarge` 时需要 1024 个 vCPU。应提前申请对应 Region 的 Standard
On-Demand vCPU 和 Standard Spot vCPU 配额。还应检查：

- 单次 Spot Fleet/EC2 Fleet 请求容量；
- 每个 Region 的运行实例数和 EBS 容量；
- VPC、子网可用 IP 数量；
- 公网 IPv4、Elastic IP 和 Security Group rule quota；
- SSM managed instance 和 CloudWatch/S3 配额。

公网协议 Security Group 现在有两种自动模式：来源数不超过 48 时继续使用每节点 `/32`
allowlist；来源数超过 48 时使用一个临时的大规模实验 CIDR，避免默认每个 SG 约 60 条入站规则的
额度在 Terraform apply 阶段被耗尽。默认大规模 CIDR 为 `0.0.0.0/0`，可通过
`aws.security.ingress.large_fleet_protocol_cidr` 收紧；它只开放本轮协议端口，协议 wire 仍执行现有
身份认证，并随 fresh fleet 一起销毁。这是论文公网实验的临时编排模式，不是生产部署建议。

## 4. 基础设施设计

### 4.1 Terraform 或 EC2 Fleet 的职责

单 Region 论文实验推荐使用 `fab aws-paper-run`。该任务调用配置指定的 Terraform module 创建和销毁
本轮 EC2 基础设施；Terraform 仍是资源声明与 state 的唯一所有者，Fabric 负责串联实验生命周期。
手工流程或多 Region 流程也可以直接使用 Terraform、CloudFormation 或 EC2 Fleet 创建：

- VPC、子网、route table 和必要的互联网出口；
- IAM role 与 instance profile；
- Security Group；
- Launch Template；
- AMI、EBS 和 256 台以内的 EC2 实例；
- 实验 tags 和销毁策略。

`deployment/config*.yaml` 中的 `instance`、`placement`、`storage` 和 `terraform` 字段会被
`aws-paper-run` 转换为当前 smoke module 的变量；module 不支持的字段仍只用于 inventory 和结果元数据，
不能替代真实基础设施声明。

### 4.2 AMI

推荐使用统一的 arm64 Graviton AMI，并固定 AMI ID。基线实例类型为 `c7g.xlarge`：4 vCPU、
8 GiB 内存。相较 2 vCPU 配置，它能让 ARL 默认密码学 worker 并行度更接近协议实际计算需求。
所有三种协议必须使用同一个 AMI 和实例类型。

当前 `us-east-1` 基线镜像为 `ami-08952339a071d1772`
（`arladkr-bench-arm64-v4-20260821`），是 Amazon Linux ARM64，使用 Go `1.26.5`，并包含提交
`b50bcaf` 的 ARL scalar responder 和 Practical MVBA/APDB 阈值修复。AMI 至少包含：

- Amazon Linux ARM64；
- 固定版本的 Go（当前为 `1.26.5`）；
- Python 3、`boto3`、Fabric/Invoke 和 PyYAML；
- AWS CLI v2；
- SSM Agent；
- `chrony`；
- `/opt/rladkr`、`/etc/rladkr`、`/var/lib/rladkr/artifacts` 和 `/var/log/rladkr`；
- 已下载的 Go modules 和预构建 benchmark binaries。

AMI 不得包含 AWS access key、SSH private key、节点 setup 或历史实验 artifact。论文实验使用的
setup 在控制机按本轮 n/f 和源码身份生成，再由 `aws-provision-setup` 分发，不进入镜像。

现有辅助任务为：

```bash
cd /home/yzc/arladkr/practicaladkr_project_code
fab aws-bake-prewarm \
  --config-path=deployment/config.aws-arm64-ssm.yaml
fab aws-create-image \
  --config-path=deployment/config.aws-arm64-ssm.yaml
```

这两个任务操作已有的 image-source 实例，不负责创建该实例。

### 4.3 IAM

实例通过 IAM role 获取临时凭证，不在文件中保存静态凭证。最小权限至少包括：

- 按指定 tags 执行 `ec2:DescribeInstances`；
- SSM managed instance 所需权限；
- 只访问本实验 S3 prefix 的读写权限；
- 可选的 CloudWatch Logs 写权限。

控制机账号需要创建/停止/终止实验实例、创建 AMI 和读取实例 inventory 的权限。创建基础设施与
运行实验最好使用不同 role。

### 4.4 Security Group

同 Region 私网实验推荐使用 Security Group self-reference：

- 节点间协议 TCP：source 为本 Security Group；
- SSH：只允许控制机固定 CIDR，或完全使用 SSM；
- 不允许 `0.0.0.0/0` 访问协议端口；
- egress 只开放系统更新、S3/SSM 和节点通信所需范围。

不要手写猜测端口范围。先生成 inventory，并读取 `recommended_public_port_range`：

```bash
cd /home/yzc/arladkr/practicaladkr_project_code
fab show-inventory \
  --config-path=deployment/config.aws-public-ssm.yaml
```

单 Region 私网模式下，协议端口不需要暴露到公网。若使用现有 public-IP SSH 管理任务，实例仍需
公网 IPv4 和受限的 SSH ingress。

单 Region 公网协议模式使用 Terraform 的 `enable_public_protocol=true`。Terraform 在实例获得公网
IPv4 后，为每个本地节点生成一条 source 为该节点 `/32` 的 TCP ingress rule；不得用
`0.0.0.0/0` 代替。端口上下界必须与 inventory 的 `recommended_public_port_range` 一致。管理面仍使用
SSM，不需要开放 22 端口。

跨 Region 时，每个 regional stack 自动加入本 Region 节点的 `/32`，并通过
`protocol_public_peer_cidrs` 显式接收其他 Region 的 `/32`。peer 列表不得重复包含本 stack 自己的
地址，否则 AWS 会拒绝重复的 Security Group rule。

### 4.5 单 AZ、多 AZ和多 Region

最终结果必须固定 topology，不允许 Fleet 在不同重复实验中任意改变 AZ 比例。

- 单 AZ：所有实例放在同一子网；适合计算基线，节点私网流量通常不产生跨 AZ 费用。
- 多 AZ：预先指定每个 AZ 的节点数；记录每个节点的 AZ，并计算跨 AZ 流量。
- 多 Region：每个 Region 使用独立 VPC/AMI copy，并保存 Region 到 node ID 的固定映射。

当前 Terraform smoke 默认保留既有的 `10.42.1.0/24` 节点子网，并从 host offset 10 开始按
`NodeSlot` 分配确定性私网地址。`/24` 在 AWS 保留 5 个地址后不能容纳 256 个实例；n=256 时必须
显式传入不小于 `/23` 的 `node_subnet_cidr`。regional stack 可通过 `node_slot_offset` 为节点分配
全局不重叠的 slot 范围。

当前 `discover-peers.sh` 和 `discover-peers-pub.sh` 只查询实例自身 Region，当前 Fabric 自动发现
不能直接形成统一的多 Region roster。多 Region 正式实验之前必须增加跨 Region inventory
编排，或生成包含所有 Region 节点的静态地址表。未完成该项前，不应声称现有命令支持多 Region。

Fabric 的 `aws-cross-region-suite` 现已提供静态统一 roster 编排。配置使用 `aws.regions` 固定每个
Region 的 `instance_count`、连续 `node_slot_offset`、AZ ID 和区域 AMI。任务先创建各 regional
stack，读取其公网地址，再第二次 apply，把其他 Region 的节点 `/32` 写入本地 Security Group；
随后在同一 fleet、同一 NodeSlot-to-Region 映射上依次运行 ARLADKR 和 PracticalADKR。协议切换仍
经过 cleanup-ready 屏障。任何阶段失败时，任务逆序销毁所有已创建的 regional stacks。

n=10 三洲 smoke 的固定映射是：`us-east-1` slots 0-3、`eu-west-1` slots 4-6、
`ap-southeast-1` slots 7-9。配置文件为
`practicaladkr_project_code/deployment/config.aws-cross-region.yaml`，执行入口为：

```bash
cd /home/yzc/arladkr/practicaladkr_project_code
fab aws-cross-region-suite \
  --config-path=deployment/config.aws-cross-region.yaml \
  --experiment-name=cross-n10-YYYYMMDD-r01
```

该任务只用于公网真实网络实验，不注入 netem。最终结果必须同时保存区域 roster、两套协议 artifact
和清理状态；任一协议未达到 n-f 成功节点时，该协议轮次不得进入性能比较。

## 5. Spot 与 On-Demand 策略

### 5.1 推荐用法

- smoke、容量验证、超时调优：Spot；
- n=64/128/256 预跑：Spot；
- 论文最终延迟数据：优先 On-Demand；
- 预算不足时可使用 Spot，但必须将任何 interruption 对应的整轮结果作废。

Spot 建议使用 `capacity-optimized` allocation strategy。为了保持硬件一致性，最终对比不要混用
不同实例 family。即使协议可以容忍 f 个节点失效，Spot interruption 后产生的延迟也不是正常
网络样本，不能当作成功实验保留。

### 5.2 Launch Template/Fleet 必备设置

- 固定 AMI ID 和 `c7g.xlarge`；
- `DeleteOnTermination=true`；
- IMDSv2 required；
- 绑定实验 IAM instance profile；
- 使用唯一 `ExperimentGroup` tag；
- 实例启动失败时不自动换成不同 CPU family；
- Spot interruption notice 进入日志；
- 设置实验最大存活时间或外部 TTL cleanup。

## 6. AWS 配置文件

不要覆盖当前 DigitalOcean 配置。单 Region 私网基线使用
`practicaladkr_project_code/deployment/config.aws-arm64-ssm.yaml`；单 Region 动态公网协议使用
`practicaladkr_project_code/deployment/config.aws-public-ssm.yaml`。两者都使用 SSM 管理，区别只在
协议 roster 选择私网还是公网地址。`aws-paper-run` 会生成唯一 ExperimentGroup 并同时写入 Terraform
和运行时配置；实验名只允许 IAM 安全字符且最长 37 个字符。手工流程仍需自行保持两者一致。

以下是最小配置骨架：

```yaml
schema_version: 2
mode: aws

network:
  node_count: 16
  node_port_base: 30000
  protocol_port_offsets:
    main: 0
  open_port_count: 22000

aws:
  region: us-east-1
  management: ssm
  use_private_ip: false
  static_ips: []
  ssh_user: ec2-user

  tags:
    protocol_suite: rla
    experiment_group: paper-n16-a

  placement:
    strategy: single-az
    availability_zones: [us-east-1a]
  instance:
    type: c7g.xlarge
    architecture: arm64
    ami: ami-REPLACE_ME
    purchase_option: spot
  image:
    prebaked: true
  terraform:
    module_dir: ../ARL-ADKR-CV-sAPVSS-handoff-2026-07-23/arladkr/deployment/terraform/aws-smoke
    state_dir: deployment/aws-state
    availability_zone_id: use1-az5
  storage:
    root_gb: 30
    volume_type: gp3

  security:
    ingress:
      management: ssm
      ssh_cidrs: []
      protocol_cidrs: []
    node_to_node: public-cidr-allowlist

  runner:
    work_dir: /opt/rladkr
    artifact_dir: /var/lib/rladkr/artifacts
    env_dir: /etc/rladkr
    log_dir: /var/log/rladkr
    service_user: ec2-user
    bench_timeout_seconds: 1800

  fault_injection:
    netem:
      enabled: false
      delay_ms: 0
      jitter_ms: 0
      loss_pct: 0
      rate_limit_mbit: 0

  cleanup:
    auto_stop_after_collect: true
    auto_terminate: false
    terminate_protection: true

projects:
  practical-adkr:
    path: practical-adkr
    local_path: practical-adkr
    remote_path: practical-adkr
  arladkr:
    path: arladkr
    local_path: ../ARL-ADKR-CV-sAPVSS-handoff-2026-07-23/arladkr
    remote_path: arladkr
```

示例中的 `placement`、`instance` 和 `storage` 必须与 Terraform/Fleet 的真实结果一致。实例发现
统一使用 `tags` 生成 `ProtocolSuite` 和 `ExperimentGroup` filters，不再依赖另一份可漂移的
自由格式 `aws.filters`。

## 7. 部署前检查

### 7.1 控制机

```bash
aws sts get-caller-identity
aws configure get region
cd /home/yzc/arladkr/practicaladkr_project_code
fab --list
fab show-config \
  --config-path=deployment/config.aws-public-ssm.yaml
fab show-inventory \
  --config-path=deployment/config.aws-public-ssm.yaml
```

检查输出中的节点数、IP、实例类型、端口范围、Region/AZ 和 tags。n 个节点必须解析为 n 个不同
主机，每台主机只有一个 node ID。

### 7.2 Fabric 安全门槛

正式创建大规模 Fleet 前必须执行所有 AWS 命令的 `--dry-run`。当前外层 `fabfile.py` 已不再向
ARL 参数添加已删除的 `-fallback-policy auto`，因此 `aws-run-bench` 可以用于 ARL。启动前仍需：

- 显式提供论文记录所需的完整参数；
- 保持 `fault_injection.netem.enabled=false`，Fabric 对 AWS workflow 会强制检查；
- 使用唯一且非空的 `ProtocolSuite` 和 `ExperimentGroup` tag value；
- 任何生成命令出现未知 flag 时立即停止，不允许在 256 节点上继续尝试。

旧的 `aws-check-pub` 会在 SSH 检查前读取 EC2 metadata，适用于 legacy public-SSH 路径。SSM 论文流程
使用 `aws-up`、`aws-resolve` 和按 `NodeSlot` 的动态 roster 检查；任意地址缺失、slot 重复或实例
未在线都会在 benchmark 启动前失败。

### 7.3 实例检查

单 Region 推荐先 dry-run，再用一条命令完成创建、运行、收集和销毁：

```bash
cd /home/yzc/arladkr/practicaladkr_project_code
export AWS_PROFILE=arladkr-sso

fab aws-paper-run \
  --project=practical-adkr \
  --bench-args='-n 10 -f 3 -runs 1 -timeout 60s -paillier-bits 3072 -mvba-network tcp -strict-network=true -comm-metrics=true' \
  --config-path=deployment/config.aws-public-ssm.yaml \
  --experiment-name=p10-use1-repeat01 \
  --timeout-s=300 \
  --dry-run
```

确认后去掉 `--dry-run`。每轮状态、运行配置、tfvars、inventory、artifact 和 JSON 记录分别写入
`practicaladkr_project_code/deployment/aws-state/<experiment>/`；该目录包含本地 Terraform state，
不得提交或在不同实验间复用。任务默认在成功、失败或 Ctrl-C 后执行 Terraform destroy；仅调试时可
显式传 `--keep-fleet`，并必须在完成后从该独立 state 立即 destroy。

需要排查基础设施时，也可以手工创建动态公网地址和严格白名单：

```bash
cd /home/yzc/arladkr/ARL-ADKR-CV-sAPVSS-handoff-2026-07-23/arladkr/deployment/terraform/aws-smoke
terraform apply \
  -var-file=public.tfvars.example \
  -var experiment_group=paper-public-n10-use1-REPLACE \
  -var ami_id=ami-0cee8a82967ef97ac
terraform output -json node_roster
```

`node_roster` 按整数 `NodeSlot` 输出 instance ID、私网 IP、公网 IP、Region 和 AZ。公网地址只固定于
本次 fleet 生命周期；Spot replacement 后必须废弃当前轮次并重新生成 roster。不要把旧公网地址手工
保留在配置里。

Fabric 运行 ARL 时会自动把 `network.node_port_base` 注入为 `-base-port`，并据此生成 old actor 与
receiver actor 的固定端口映射；如果手工直接启动二进制，必须显式传入同一个 `-base-port`，否则本地
监听器会使用随机端口而与公网 roster 不一致。

```bash
fab aws-up \
  --config-path=deployment/config.aws-public-ssm.yaml
fab aws-resolve \
  --config-path=deployment/config.aws-public-ssm.yaml
fab render-inventory \
  --config-path=deployment/config.aws-public-ssm.yaml
```

动态发现强制要求运行实例具有唯一、连续的 `NodeSlot=0..n-1`，并按整数 slot 生成 peer map；不能按
IP 字符串排序。`aws-discover`/`aws-discover-pub` 是旧 SSH 脚本路径，SSM 论文流程不需要运行它们，
也不得在同一轮中混用旧 discover 生成的 env 文件。

继续前应确认：

- 所有主机 SSH/SSM 在线；
- 三个 benchmark binary 均存在且可执行；
- `/etc/rladkr/arladkr.env` 和 `practical-adkr.env` 中 node ID 唯一；
- peer map 有且只有 n 个节点；
- NTP/chrony 同步正常；
- 协议端口没有被旧进程占用；
- 所有实例报告相同 AMI、instance type、Go 版本和 git commit。

## 8. Provision trusted setup

在控制机一次生成本轮 setup。当前学术实验的 `shared-public` 模式把同一 archive 安装到所有节点，
用于排除逐节点密钥生成和串行分发的编排开销；这些材料在本实验威胁模型中允许公开，setup/keygen 不计
入在线协议延迟。该做法不应直接用于生产密钥部署。

示例使用 n=16、f=5：

```bash
CFG=deployment/config.aws-public-ssm.yaml
N=16
F=5

fab aws-provision-setup \
  --config-path="$CFG" \
  --project=arladkr \
  --bench-args="-n $N -f $F" \
  --dry-run

fab aws-provision-setup \
  --config-path="$CFG" \
  --project=practical-adkr \
  --bench-args="-n $N -f $F -paillier-bits 3072" \
  --dry-run
```

检查 dry-run 后去掉 `--dry-run`。保存两个 `setup_bundle_digest`。所有节点必须报告与对应协议一致的
digest。Practical 默认与 high-assurance 只改变采样策略，可以在相同 n/f 和 Paillier modulus 下
复用同一份 Practical setup；必须在结果中记录这一点。

### 8.1 32 台及百节点 setup 控制面

`shared-public` setup 在大 fleet 上使用两级屏障。`aws-up` 和直接调用的
`aws-provision-setup` 都会先等待完整 roster 的 EC2 实例进入 running 且 SSM agent 报告
Online；轻量 `SSM_READY` 命令全部成功后，才开始下载和安装 setup。setup 命令按有界批次
执行，同一批中成功实例的结果会保留，后续只重试失败实例，不会重复覆盖已成功节点。

32 台单 Region 配置建议保留：

```yaml
aws:
  runner:
    ssm_parallelism: 50
    ssm_ready_timeout_seconds: 600
    ssm_setup_timeout_seconds: 600
    ssm_setup_batch_size: 16
    ssm_setup_retries: 2
    artifact_url_ttl_seconds: 3600
```

`ssm_ready_timeout_seconds` 是新实例注册的总等待时间，`ssm_setup_timeout_seconds` 是每次
setup command 的执行上限，两者不能用较短的普通管理命令 timeout 代替。AWS SSM 每个
`send-command` 最多接收 50 个 instance ID；100--256 台建议每 Region 使用 16--25 台 setup
批次、最多 50 并发，并保证 presigned URL 的 TTL 覆盖所有批次与重试。跨 Region 调用按 Region
并发，各 Region 内再分批，避免 command ID 和 SSM client 跨区混用。

当前分发只让每台实例下载一份公共 archive 和自己的 NodeSlot shard，去掉了全部私有 shard 在
每台机器上的重复下载。公共 registry 本身随 n 增长且每台节点都需要，因此集群总下载量仍可能是
`O(n^2)`，不能把整个 setup 路径描述成 `O(n)`。进入 100+ 正式实验前，先做不运行协议的
setup soak，并检查每批耗时、重试实例 ID、S3 URL 剩余 TTL 和所有节点的 setup digest。

下一阶段优化按收益排序如下：使用固定加密 artifact bucket 和内容 digest 复用不可变对象，避免
每轮创建/删除 bucket；将公共 setup object 复制到各实验 Region，减少跨区下载尾部；让 100+ 节点
artifact 直接上传 S3 后生成集中 manifest，避免控制机逐节点分块拉取。以上尚未实现，不应写入
正式实验的已完成能力清单。

SSM command 的列表接口存在最终一致性窗口：AWS 后端可能已经显示全部 invocation 成功，但
`ListCommandInvocations` 暂时少列少数实例。轮询 deadline 后必须对缺失 instance ID 使用
`GetCommandInvocation` 逐实例对账，不能把“列表未出现”等同于命令失败。对账只用于确认同一个
command ID 的最终状态，不得掩盖明确的 Failed、TimedOut 或 Cancelled。

32 节点实测中，逐节点分块拉取 journal 和 benchmark artifact 已成为失败轮的主要控制面尾部。
100+ 节点正式运行应改为每个节点上传到实验专属的加密 S3 prefix，控制机收集 manifest、digest、
大小和错误摘要，再按需下载完整日志；在该路径实现前应为 artifact collection 单独预留时间，且
不能把收集耗时计入协议 latency。

## 9. 三组实验参数

### 9.1 ARLADKR

功能 smoke 可以使用 `-cv-failure-target smoke`。正式实验使用论文 profile：`original` 对应
`Delta=1e-10`，`high-assurance` 对应 `Delta=2^-64/525600`。runner 将总预算平分为 proposer 与
validator 的 `Delta/2`，并根据实际 `n,f` 的精确有限总体概率选择最小样本。

```bash
ARL_ARGS="-n $N -f $F -runs 1 -epochs 1 \
  -transport tcp-distributed -strict-network=true -comm-metrics=true \
  -timeout 900s -cv-failure-target original"
```

额外运行 high-assurance 曲线时只将最后一个参数改为 `high-assurance`。不要通过手工降低 sample、
关闭验证或启用 ablation 来强行得到结果。

ARL scalar-share responder 必须覆盖慢节点进入 exchange 的偏斜。节点达到 `n-f` 后可以释放本地
collector，但在 epoch service grace 结束前仍须保留已验证 aggregate 和本地 share，以便验证并
回复晚到 peer。只增大整轮 `-timeout` 或固定 retry 次数不能修复 responder 已停止回复的问题。
报告 `recover_shard_ms` 时同时记录 `mean_recover_service_grace_ms`；主 adjusted latency 应扣除
纯 responder grace，避免把固定服务窗口解释为密码计算或网络恢复耗时。

### 9.2 PracticalADKR 默认配置

```bash
PRACTICAL_ARGS="-n $N -f $F -runs 1 -timeout 900s \
  -paillier-bits 3072 -strict-network=true -comm-metrics=true \
  -fallback-policy off -kappa-profile matched-lifetime \
  -kappa-security-bits 128 -kappa-lifetime-epochs 525600"
```

Practical 的 MVBA proposal 有两个不同阈值：dealer/certificate 项数为 `2f+1`，每份 APDB
certificate 的 receipt 数为 `n-f`。测试必须至少包含一个 `n>3f+1` 的参数点；只测
`n=3f+1` 会使两个数相等，无法发现阈值混用。

### 9.3 PracticalADKR high-assurance

```bash
PRACTICAL_HA_ARGS="-n $N -f $F -runs 1 -timeout 900s \
  -paillier-bits 3072 -strict-network=true -comm-metrics=true \
  -fallback-policy off -kappa-profile high-assurance \
  -kappa-security-bits 64 -kappa-lifetime-epochs 525600"
```

每次运行保存最终选择的 `kappa`、per-epoch failure probability、lifetime union bound 和 security
bits。不能只保存 profile 名称。

## 10. 交替运行

为了减少时间段、Spot host 和 AWS 背景负载偏差，三种配置使用轮换顺序：

| 重复 | 第 1 个 | 第 2 个 | 第 3 个 |
|---|---|---|---|
| 1 | ARL | Practical | Practical HA |
| 2 | Practical | Practical HA | ARL |
| 3 | Practical HA | ARL | Practical |

不再手工停止 unit、杀进程或检查端口。`fab aws-run-bench` 在每次启动前自动执行全节点
`cleanup-ready` barrier：停止并回收所有 `rladkr-*.service`，杀掉遗留 benchmark/runner 脚本，
轮询 `pgrep` 确认相关进程为 0，用 `ss -lntp` 检查 ARL 与 Practical 两套协议的所有声明端口，
清除上一轮 start/ready/status/cleanup-ready marker，并在节点上写入和校验本轮 env/address map。
只有全部 n 个节点返回 `cleanup-ready` 后，Fabric 才设置新的同步启动时间；任一节点失败则不启动，
保留节点和端口诊断。setup 仍是只读材料：

```bash
fab aws-run-bench --config-path="$CFG" --project=arladkr --bench-args="$ARL_ARGS"
```

该 barrier 同时适用于 SSM 和 legacy SSH 管理面，清理与 runner 上传使用 Fabric 的有界并行；不需要
人工逐节点执行 shell。`aws-cleanup-pub` 仅保留为旧公网 SSH 路径的兼容任务，不应与同一轮
`aws-run-bench` 混用。

当前 `aws-run-bench` 的单项目 fresh-fleet 路径已验证；同一 fleet 上从 ARL 切换到 Practical 的
一次 n=10 验证出现 Practical 全节点 timeout，已标记 invalidated。因而在 runner unit、残留进程和
端口释放被独立验证前，不能把下面的交替顺序用于正式同 fleet 数据。正式数据暂应采用独立 fresh fleet
轮次，并记录 topology 元数据；验证通过后再恢复同 fleet 交替，以减少背景负载偏差。

启动示例：

```bash
fab aws-launch \
  --config-path="$CFG" --project=arladkr --bench-args="$ARL_ARGS"

fab aws-launch \
  --config-path="$CFG" --project=practical-adkr --bench-args="$PRACTICAL_ARGS"

fab aws-launch \
  --config-path="$CFG" --project=practical-adkr --bench-args="$PRACTICAL_HA_ARGS"
```

一次只启动一个配置。记录命令输出中的 `run_id`，等待该 run 完成并收集后，再清理和启动下一个。

## 11. 等待与收集

```bash
PROJECT=arladkr
RUN_ID=run-REPLACE_ME

fab aws-wait \
  --config-path="$CFG" --project="$PROJECT" --run-id="$RUN_ID" \
  --timeout-s=1800 --interval-s=15

fab aws-collect \
  --config-path="$CFG" --project="$PROJECT" --run-id="$RUN_ID" \
  --out-dir="deployment/aws-artifacts/$RUN_ID"
```

对 Practical 两个 profile 使用各自独立的 `run_id` 和 artifact 目录。不要把三组日志写入同一目录。

每轮至少验收：

- 成功节点数至少为 `n-f`；
- 所有成功节点只有一个 `consensus_hash`；
- `setup_bundle_digest` 一致；
- timing metadata 一致；
- `fallback_runs=0`、`timeout_runs=0`；
- strict network 开启；
- 没有本地 shortcut 或 ablation；
- sent/received bytes、setup、online、MVBA、recovery 和 derive 分项完整。

主延迟指标使用第 `n-f` 个成功节点完成时刻，即 quorum latency。全节点最大延迟作为次要指标。
ARLADKR 默认报告应扣除 recovery service grace，同时保留 raw latency 字段供审计。

失败轮不能只删除失败节点后计算均值。应保存完整日志，标记失败原因，并重新执行整轮。

## 12. RTT、系统与成本元数据

每轮实验保存：

- node ID -> instance ID/private IP/public IP/Region/AZ；
- AMI ID、instance type、purchase option 和 Spot request/Fleet ID；
- git commit、Go version、kernel、CPU model、vCPU 和内存；
- 全节点或抽样节点间 RTT 的 p50/p95；
- CPU、RSS、磁盘、网络接口 bytes 和协议层 bytes；
- 实验 UTC 起止时间；
- Spot interruption notice；
- AWS Cost and Usage Report 或实验 tags 对应的成本。

流量成本估算使用实际测得 bytes：

```text
跨 AZ 成本约等于 跨 AZ 双向 GB × 对应 Region 的每 GB 单价
跨 Region 成本约等于 各 Region 出站 GB × 源 Region 到目标 Region 单价
公网成本约等于 公网出站 GB × EC2 Data Transfer Out 单价
```

不要用 n=10 的通信量直接宣称 n=256 成本。至少先测 n=32、64、128，分别拟合每节点和全网
通信量增长。

实例预算至少包含：

- EC2 compute；
- 256 个公网 IPv4 的小时费（如果使用）；
- EBS gp3；
- 跨 AZ/Region 或公网流量；
- NAT Gateway（应避免承载节点间协议流量）；
- S3、CloudWatch 和 AMI snapshot。

## 13. 实验结束与清理

先确认 artifact 已下载并校验，再停止或终止实例：

1. 检查三个配置的本地 artifact 目录；
2. 校验 summary、manifest、节点数、digest 和 consensus hash；
3. 将原始日志与 resolved inventory 上传到长期保存位置；
4. 停止或终止 Fleet；
5. 删除临时 EBS、过期 AMI snapshot、临时公网 IPv4 和过期 S3 object；
6. 检查 Cost Explorer 中实验 tag 是否仍有运行资源。

优先使用 Terraform destroy 或按本次 Fleet/instance ID 精确终止。Fabric 终止任务默认受
`aws.cleanup.terminate_protection=true` 保护。确认 artifact 已保存后，将当前实验配置中的该值临时
改为 `false`，先预览精确目标：

```bash
fab aws-terminate --config-path="$CFG" --dry-run
fab aws-terminate --config-path="$CFG"
```

任务只查询同时匹配当前 `ProtocolSuite`、`ExperimentGroup` 且状态为 running 的实例。dry-run
会列出完整 instance ID，不调用 terminate API。正式终止后立即把保护值恢复为 `true`。

使用 `aws-paper-run` 时，上述收集与 destroy 已包含在 finally 路径中；在非 `keep-fleet` 的真实
运行中，finally 会先尝试全节点 cleanup-ready，再执行 Terraform destroy。即使 cleanup-ready 因
节点失联失败，destroy 仍会继续，并将 `final_cleanup` 与 `cleanup` 分别写入 experiment record。
运行结束仍要按
ExperimentGroup 复核 EC2、VPC、EBS、EIP、NAT Gateway 和临时 S3 均已清空。`--keep-fleet` 只用于
短时诊断，不是论文批量实验的默认选项。

## 14. 最终发布检查表

- [ ] 三种协议配置使用同一 AMI、实例类型和 topology。
- [ ] 没有 `public20`、delay matrix 或 netem。
- [ ] 一台实例只有一个 old node 和配对的 new receiver。
- [ ] n、f、kappa/sample 与 failure bound 已记录。
- [ ] setup provisioning 不计入在线延迟，且 digest 一致。
- [ ] 每轮使用新 `run_id` 和一个 fresh epoch。
- [ ] 每个数据点至少三次独立成功运行。
- [ ] 主指标为 `n-f` quorum latency。
- [ ] 成功节点 consensus hash 唯一。
- [ ] 原始日志、manifest、inventory 和系统元数据完整。
- [ ] Spot interruption 对应整轮已作废。
- [ ] 所有临时 AWS 资源已停止或删除。

## 15. 当前尚未自动化的事项

在把本流程用于正式 n=256 数据前，还需要单独完成或验证：

1. Spot interruption 自动标记整轮无效；
2. 多 Region 统一 roster、跨 Region SSM 启动和结果收集；
3. 自动 RTT matrix 和 Cost Explorer 快照；
4. 三配置轮换调度与论文表格汇总。

单 Region Terraform apply/destroy、SSM 检查、setup、benchmark、等待、收集、独立 state/record、
确定性私网地址、`NodeSlot` roster 和本 fleet 动态公网 `/32` 白名单已经由 `aws-paper-run` 串联。
SSM 源码同步/AMI 预热也已使用一次归档、一次临时 S3 object 和全节点校验，不再要求 SSH；普通
预构建 AMI 实验不会每轮重复同步源码。`protocol_public_peer_cidrs` 只提供跨 Region 安全组的两阶段
输入，不能替代尚未完成的统一多 Region Fabric 编排。

这些是实验编排缺口，不是 ARLADKR 或 PracticalADKR 密码学协议的一部分。
