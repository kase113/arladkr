<!-- -*- coding: utf-8 -*- -->
# Aggregate RL-ADKR：面向自适应腐蚀的聚合优先异步动态密钥更新

## 摘要性主张（思路稿）

这里不保留正式论文摘要，只保留后续可展开成摘要的一组核心句子：

- network-adaptive ADKR 不能只锁 generic availability object；对象必须同时满足公开可检查、未来可恢复、以及恢复绑定。**本文将此语义推广到聚合对象 AggRLO**。
- 本文的对象层回答是 **recoverability-locked `AggHeader + AggLock`**（聚合级 RLO）。
- 核心颠覆：在共识前由旧委员会内部完成聚合锁定 `LockAgg`，产生单个 AggRLO；共识和恢复都仅围绕这 1 个对象。
- 引入 **AggLock** 原语，旧委员会成员对聚合后份额 $\widehat{sh}_u$ 的存储承诺签名，解决了 per-dealer Lock 的 holder-intersection 难题。
- 安全闭环上：在 **静态旧委员会腐蚀 + dealer erasure + 聚合层锁后自适应分析** 的模型下，本文主分析对象仍是 AggRLO 及其三项语义；在此基础上，额外引入 receiver-side transport forward secrecy，用于封闭 posterior corruption 下从 `RecoverAgg` 到接收方解密的最后一段安全缺口。
- 相较于非聚合逐对象设计中对 $\kappa$ 个对象分别执行 agreement 与 recovery 的做法，本文将主路径压缩为单个 AggRLO，通信复杂度从 $O(\kappa\lambda n^2)$ 降至 $O(\lambda n^2)$。

## 0. 论文范围与定位

本文只保留一条主线：**fresh-key 模式的、aggregate 的、network-adaptive asynchronous distributed key reconfiguration (ADKR)**。  
旧委员会 $\mathcal{M}_{old}$ 已拥有既有门限密码基础设施；协议结束后，新委员会 $\mathcal{M}_{new}$ 生成一套**全新的**主私钥 $x_{new}$、主公钥 $pk_{new}$ 与对应门限份额。

本文正文只讨论一个主协议点，即以 AggRLO 为核心的 aggregate network-adaptive fresh-key ADKR。  
本文的单一主张是：

> **在 ADKR 中，如果希望同时实现快路径锁定、异步回退、锁后恢复与密钥派生，那么共识层锁定的对象必须比 generic availability object 更强：它需要同时支撑公开检查、未来可恢复与恢复绑定。更进一步，通过在共识前聚合为单个 AggRLO，可以把非聚合逐对象设计中的 object-level repetition 压缩为单对象主路径。**

为避免问题表述漂移，全文只保留一个科学问题；其正式版本在第 `1.2` 节给出：

> **在异步网络下，能否设计一种支持乐观快路径的 ADKR 协议，同时保持其安全性与可恢复性，并把 recovery 之前的 agreement object 压缩到单个聚合对象？**

围绕这一主张，本文采用如下组织原则：

1. **只保留一个正文协议点**：面向现实性能的 `aggregate network-adaptive asynchronous fresh-key ADKR`。
2. **不把论文组织成“统一覆盖多个 operating points”的框架**：避免主线被多条半成熟路线稀释。
3. **把 novelty 压缩到一个尖锐命题**：  
   不是“给 Practical ADKR 加快路径”，而是识别并形式化：  
   **ADKR 的 network-adaptive 执行需要比普通 BFT 更强的共识对象语义，且该语义可以在共识前聚合为单个 AggRLO。**
4. **安全边界清楚收窄**：  
   正文主协议不宣称 erasure-free fully adaptive old-dealer security；旧委员会基础模型为静态腐蚀，仅在 dealer erasure 成立后对聚合层给出条件性的锁后自适应安全分析。
5. **贡献结构压缩为三点**：  
   （i）aggregate recoverability-locked object 及其安全语义；  
   （ii）基于该对象的一种新的 aggregate-first ADKR 范式；  
   （iii）实验评估。  
   其中，（i）给出对象层的最早充分语义、AggLock 机制以及在 posterior corruption 下的完整安全闭环；（ii）给出 `LockAgg -> AgreeAgg -> RecoverAgg -> Derive` 的范式级改写；（iii）验证单对象主路径相较于非聚合逐对象设计的系统收益与设计必要性。

### 安全定位补充

本文只保留正文主协议这一安全定位：

1. **正文主协议**采用 recoverability-locked `AggHeader + AggLock` 对象，强调对象语义统一、Fastlane/Fallback 共享同一 admissibility predicate，以及清晰的聚合恢复绑定证明。本文的主安全分析围绕 AggRLO 展开；其中，dealer erasure 与 AggLock holder commitments 用于支撑对象层与恢复层安全，而 receiver-side transport forward secrecy 只作为补充机制，用于处理接收方 posterior corruption 下的历史传输保密性问题。

因此，Aggregate RL-ADKR 的安全层级取决于底层承诺、签名、可验证加密、擦除纪律与 recovery-binding 组件。本文不宣称 erasure-free fully adaptive old-dealer security。正文基础敌手模型对旧委员会采用静态腐蚀；在此之上，仅对满足 dealer erasure 时序的锁后聚合阶段给出条件性的 post-erasure adaptive corruption 分析。

为避免符号混乱，全文统一记：

- $\lambda$：计算安全参数；
- $n_o, n_n$：旧/新委员会规模；
- $f_o, f_n$：旧/新委员会可容忍的拜占庭节点数；
- $K=f_o+1$：最终聚合 dealer 集合的基数，即 $|S|=K$；
- $L=n_o-f_o$：component lock、ready pool 与 AggLock 的 holder quorum；
- $\tau_{\mathsf{rec}}=n_o-2f_o$：fresh Reed--Solomon 恢复门槛；
- $S$：被纳入聚合对象的 $K$ 个 dealer 的集合；
- $\widehat{S}$：签发 AggLock 的 holder 集合。

其中，$\kappa$ 不再作为 Aggregate RL-ADKR 的协议参数出现；若后文仍出现 $\kappa$，仅用于指代**非聚合逐对象基线**中需要分别处理的对象数。

---

## 1. 研究背景与科学问题

### 1.1 背景

异步 BFT 系统越来越依赖既有门限密码原语来实现公共硬币、阈值认证与法定证书。  
一旦系统需要执行委员会轮换，就必须回答一个核心问题：

> 在完全异步环境下，如何将旧委员会的既有门限能力安全、可验证、低开销地迁移到新委员会？

这正是 ADKR 所处理的问题。

现有文献已经给出了 ADKG / ADKR 的成熟密码学主线：

- `Practical Asynchronous Distributed Key Generation` 通过 ACSS/PVSS + agreement 组织异步密钥生成；
- `Practical Asynchronous Distributed Key Reconfiguration and Its Applications` 进一步提出 `share-dispersal -> agree -> recast` 执行链，将复杂度降到近似二次级。

因此，**ADKR 的基本安全目标与纯异步执行链本身并不缺失**。  
真正缺失的是如下设计空间中的一个问题：

> **当 ADKR 不再局限于纯异步 execution，而是希望实现“好网络下快路径锁定、坏网络下异步回退”的 network-adaptive 执行时，共识层到底应该锁定什么对象，才能不破坏后续 transcript 恢复、份额验证与新密钥派生？**

这不是普通 BFT 的标准问题，因为在 ADKR 中，共识层锁定的对象最终还要进入：

- transcript 恢复；
- share correctness 验证；
- key derivation。

因此，ADKR 中“可被快速锁定的对象”必须带有 ADKR-specific 的恢复语义，而不能只依赖通用共识层的 validated object。

### 1.2 科学问题

本文聚焦如下唯一科学问题：

> 在 ADKR 中，如果希望同时实现快路径锁定与异步回退，共识层锁定的对象必须满足什么语义，才能在不恢复完整 transcript 的前提下，安全地保证后续可恢复性与密钥派生正确性？

本文对这一科学问题的回答是：

> 我们提出 **recoverability-locked 的 `AggHeader + AggLock` 聚合共识对象（AggRLO）**，  
> 并基于此构造一个**聚合优先的网络自适应 ADKR**。  
> AggRLO 将聚合时机从“共识之后”前移到“共识之前”，  
> 使得共识和恢复都仅围绕单个聚合对象展开，不再引入非聚合逐对象设计中的多对象编排开销。  
> 进一步地，为了使这条 `lock -> recover -> decrypt` 执行链在接收方 **posterior corruption** 威胁下保持完整安全性，  
> 我们补充引入 **receiver-side transport forward secrecy**；  
> 它不是独立主贡献，而是 AggRLO 安全语义落到完整执行链时所必需的最后一环。

### 1.3 与 prior work 的差异定位

本文不主张重新定义 ADKR 的核心安全目标，也不主张发明一种与 `Practical ADKR` 完全不同的密码学范式。  
本文真正推进的是：**把 ADKR 中“agreement on what”这件事做成 network-adaptive 执行下的核心问题，并进一步把该对象从 per-dealer 粒度压缩为单个聚合对象。**

### 1.3.1 与通用共识对象和 Practical ADKR 的对比光谱

| 对象语义 | 代表方案 / 逻辑层级 | 能否支撑网络自适应 ADKR |
|:---|:---|:---|
| Generic validated availability object | Dumbo-MVBA / validated MVBA 风格 | ✗ 不保证 ADKR-specific future recoverability 与 recovery binding |
| **Aggregate Recoverability-Locked Object (AggRLO)** | **Aggregate RL-ADKR（本文）** | **✓ 同时满足三要求，并将 agreement object 压缩为单个聚合对象** |
| Finished dispersal | Practical ADKR | ✓ 但 agreement frontier 偏晚 |

### 1.3.2 与异步自适应 DKG/ADKR 的关系

- **Practical ADKR**：共享 `share-dispersal -> agree -> recast` 主线，但本文把 agreement 输入对象从 finished dispersal 前移到单个 AggRLO。
- **Optimistic Asynch. DPSS / APVSS 相关路线**：提供聚合或乐观执行的原语启发，但不直接解决 ADKR 中的 aggregate recoverability 与 binding。
- **安全边界说明**：本文正文采用较保守的实例化边界。若底层使用普通高效 DLog-based PVSS / verifiable encryption，则旧委员会 dealer 的 secrecy 仍应依赖擦除纪律与辅助假设陈述，不能直接拔高到 erasure-free fully adaptive security。

---

## 2. 为什么 ADKR 需要 recoverability-locked agreement object：必要性叙事

### 2.1 问题不在于 finality，而在于 post-lock pipeline

在普通 BFT 中，只要某个对象可被一致排序和终局确认，就足够支撑状态机复制。  
但在 ADKR 中，共识锁定不是终点；锁定后的对象还要进入：

- `Recover`
- `Share Verification`
- `Key Derivation`

因此，一个“能被快速确认”的对象，若不能唯一支撑后续恢复与派生，就仍然不足够。

### 2.2 对象语义必要性：三个最低要求

对于 network-adaptive ADKR，任何能够在 recovery 之前进入 agreement 的对象，都至少必须同时满足三个语义要求：

1. **共识前公开可检查**；
2. **锁定后未来可恢复**；
3. **恢复结果与锁定对象绑定**。

这三点共同构成 ADKR 中 agreement object 的最低对象语义。

#### 要求一：共识前公开可检查

ADKR 的快路径希望在不恢复完整 transcript 的情况下先锁定共同对象。  
因此，一个对象若要进入 agreement，必须能让所有副本在共识前检查：

$$
\mathsf{Admit}(O)=1.
$$

这个检查不能依赖完整 payload 恢复，否则 fast path 就退化成先完成重型恢复再 agreement。

#### 要求二：锁定后未来可恢复

只满足公开可检查还不够。  
若对象在锁定时不能推出未来可恢复性，那么后续恢复阶段就可能抽中一个“看起来合法但实际上无法恢复”的 transcript。

因此，ADKR agreement object 在进入 agreement 前必须附带一种证据，说明：

> 足够多旧委员会副本已经持有并持久化了与该对象绑定的恢复材料。

#### 要求三：恢复结果与锁定对象绑定

即使对象可公开检查、也有 future recoverability，还需要第三个条件：  
后续恢复出的 payload 必须就是先前被锁定对象的展开。

否则会出现如下风险：

- agreement 阶段锁定的是对象 $O$；
- recovery 阶段恢复出另一个与 $O$ 只有弱关联的 payload；
- key derivation 使用了恢复阶段的新对象，而不是 agreement 阶段已经共同锁定的对象。

因此，必须要求：

$$
\mathsf{BindingCheck}(O,\mathsf{Payload})=1.
$$

#### 三个要求的组合关系

这三个要求分别对应 ADKR 执行链中的三个时间点：

| 时间点 | 需要保证什么 |
|:---|:---|
| agreement 前 | 对象可公开判定是否有资格进入 agreement |
| agreement 后、recovery 前 | 对象未来一定可以被恢复 |
| recovery 后、derive 前 | 恢复结果就是先前锁定对象的展开 |

因此，ADKR 中一个合格的 pre-recovery agreement object 至少需要满足：

$$
\mathsf{PublicCheckability}
\quad+\quad
\mathsf{FutureRecoverability}
\quad+\quad
\mathsf{RecoveryBinding}.
$$

### 2.3 为什么通用 availability / validated descriptor 不够

若仅锁 generic availability certificate，则至多表明：

- 某对象已被若干节点见证为“可用”或“可拉取”。

但 ADKR 还需要：

- transcript metadata legality；
- root 与 payload 的绑定；
- future recoverability 的 quorum-backed 保证；
- recovery 到 derive 的唯一绑定。

也就是说，generic availability object 可回答“数据大概率能取到”，但不自动回答：

> “这个对象是否已经足以作为 ADKR 中合法、可恢复、可派生的新密钥构件？”

### 2.4 本文的核心回答

因此，本文将共识层锁定对象设计为 recoverability-locked aggregate object。  
核心不变的是：**agreement 前对象必须先被提升到 future-recoverable 状态。**

### 2.5 Lock 不是弱 root 可用性证明

`Lock` 或 `AggLock` 的关键不是“有人看见了 root”，而是：

> 已有 quorum-backed storage evidence 托底，且诚实持有者在未来可以响应恢复请求。

这使它与 generic availability certificate、dealer-local completion bit 或轻量 metadata endorsement 根本不同。

### 2.6 Recoverability-Locked Object 是 Earliest Sufficient Agreement Frontier

对本文关心的对象语义而言，recoverability-locked object 是在 recovery 之前可安全进入 agreement 的最早充分对象：

1. 仅有 metadata / commitment：可公开检查，但不保证未来可恢复；
2. generic availability certificate：不绑定 ADKR-specific metadata legality 与恢复绑定；
3. finished heavy object：当然足够，但 agreement frontier 太晚；
4. recoverability-locked object：恰好在 recovery 之前同时满足三要求。

本文将这一最早充分边界具体实例化为单个聚合对象 `AggHeader + AggLock`。

### 2.7 更深的机制挑战：从 sender-completion qualification 到 quorum-held recoverability qualification

network-adaptive ADKR 需要的，不是 dealer 自己说“我发完了”，而是协议层能公开确认：

> 该对象已经被一个足够大的 honest-heavy holder 集合托底，因此恢复在未来具有制度性保证。

这正是 RL 范式相对于 generic optimistic shell 的根本区分点。

### 2.8 为什么需要聚合优先对象

§2.2 中建立的三个语义要求（公开可检查、未来可恢复、恢复绑定）对于 **任何** ADKR agreement object 都是必要的，无论它是 per-dealer 粒度的还是聚合粒度的。

然而，逐 dealer recoverability lock 存在一个结构性问题：

> 对每个 $i$，都可能存在一个 holder 集合持有 $shard_{i,\cdot}$；但这些集合未必是同一个集合。

这意味着：

- 共识必须逐个验证 $\kappa$ 个独立对象，导致 $O(\kappa\lambda n^2)$ 通信；
- 恢复必须对 $\kappa$ 个对象分别采样，每个对象可能由不同的 holder 子集持有；
- 在 `Fallback` 中需要复杂的 descriptor 编码、解码与裁剪。

AggRLO 的解决方案是：**在共识前**，先让旧委员会成员各自计算聚合份额

$$
\widehat{sh}_u = \sum_i \rho_i \cdot shard_{i\to u},
$$

并对**同一个 holder 集合**（即签名 AggLock 的那些 holder）的存储义务进行证书化。这同时满足三个语义要求，并将原本需要分别编排的多对象 agreement / recovery 主路径压缩为 1 个对象。

**本节结论。**  
对 network-adaptive ADKR 而言，agreement object 的问题不是“能否在 recovery 前先锁一个轻对象”，而是“该轻对象是否已经足以制度性地支撑后续恢复与派生”。  
逐对象的 recoverability lock 只能提供 component-wise recoverability；它并不推出单个聚合对象所需的 common-holder aggregate recoverability。  
因此，若希望把 agreement frontier 前移到 recovery 之前，并进一步把非聚合逐对象设计中的多对象输入压缩为 1 个对象，则协议必须新增一种聚合级 recoverability lock。本文将这一必要对象实例化为 `AggHeader + AggLock`。

---

## 3. 贡献概述

### 贡献一：Aggregate Recoverability-Locked Object（AggRLO）及其安全语义（核心理论创新）

- 定义 **聚合级 AggRLO** = `(AggHeader, AggLock, S)` 作为正文唯一共识对象。
- 引入 **AggLock 原语**：旧委员会成员对聚合份额 $\widehat{sh}_u$ 的存储承诺签名，解决 per-dealer Lock 的 holder-intersection 难题。
- 证明 AggRLO 满足网络自适应 ADKR 的三个充分语义要求（公开可检查、未来可恢复、恢复绑定），并将原本需要分别编排的多对象 agreement 主路径压缩为单对象 agreement。
- 论证 AggLock 与 APVSS aggregation 的本质区别（holder storage commitments vs. transcript aggregation）。
- 进一步指出：AggRLO 只解决“agreement on what”以及 lock-to-recover 的对象安全性；若缺失 receiver-side transport forward secrecy，则敌手仍可在协议完成后通过 posterior corruption 回溯解密历史 transport ciphertext。
- 在 dealer erasure 与 AGM 假设下给出 AggRLO 的条件性 post-erasure adaptive corruption 安全分析，并将 **receiver-side transport forward secrecy** 作为锁后执行阶段的补充机制纳入 end-to-end 安全闭环，而非独立主贡献。

### 贡献二：一种新的 aggregate-first ADKR 范式：`LockAgg -> AgreeAgg -> RecoverAgg -> Derive`（协议层创新）

我们提出一种不同于传统 `share-dispersal -> agree -> recast` 组织方式的 aggregate-first ADKR 执行范式，其核心变化不是简单加入快路径，而是将**聚合、锁定、共识与恢复的边界整体前移并重组**：

- **`LockAgg`**：在旧委员会内部先把 $K=f_o+1$ 个有效 dealer 贡献压缩为单个 AggRLO，并通过 AggLock 将其提升到 future-recoverable 状态；
- **`AgreeAgg`**：Fastlane 与 Fallback 都只对单个 AggRLO 执行 agreement，共享统一谓词 $\mathsf{AdmitAgg}$；
- **`RecoverAgg`**：恢复对象从非聚合逐对象设计中的多 payload 恢复，改为 1 个聚合 payload 恢复；恢复请求也从多组 holder 子集改为针对同一 $\widehat{S}$；
- **`Derive`**：密钥派生不再承担内部聚合职责，而只对聚合恢复结果执行解密、验证与输出。

该范式的关键不在于“再加一个 optimistic shell”，而在于：**agreement frontier 从 finished per-dealer objects 改写为 pre-consensus aggregated recoverability-locked object**，从而把共识与恢复的主路径都压缩到单对象层级。

### 贡献三：实验评估与分析（系统验证）

- 在广域网环境进行大规模部署测试。
- 与 Practical ADKR、以及去除 AggLock、去除 posterior-corruption 安全闭环补充机制的消融变体进行对比。
- 测量 ready-object density、fast-lane fill ratio、good-case latency、fallback 触发率与 total communication 等指标，验证对象语义变更带来的系统收益。
- 新增消融实验：`Aggregate ADKR w/o AggLock`（仅聚合承诺但不检查 AggLock 签名），验证 AggLock 对恢复成功率的必要性。

---

## 4. 系统模型与敌手模型

### 4.1 系统模型

系统由旧委员会 $\mathcal{M}_{old}$ 与新委员会 $\mathcal{M}_{new}$ 组成：

- $|\mathcal{M}_{old}| = n_o$，容忍 $f_o < n_o/3$ 个拜占庭节点；
- $|\mathcal{M}_{new}| = n_n$，容忍 $f_n < n_n/3$ 个拜占庭节点。

旧委员会已拥有既有门限密码基础设施，可支持：

- threshold signature / certificate；
- threshold coin / beacon。

新委员会在每个 epoch 使用独立接收状态：

- epoch-specific public key；
- epoch-specific decryption state。

### 4.2 网络模型

协议的**基础安全模型**是全局异步网络：

- 敌手控制调度器；
- 可任意延迟、重排、选择性交付消息；
- 对诚实节点之间的消息，唯一保证是最终送达。

协议的 safety 与 worst-case liveness 都只依赖这一异步模型。

同时，协议采用 optimistic asynchronous 设计：

- 若某个有限窗口内 leader 诚实且诚实节点间时延足够小，则 `Fastlane` 可在常数个真实网络延迟内完成锁定；
- 若乐观条件不满足，则诚实节点在本地 timeout 后退出 `Fastlane`，进入纯异步 `Fallback`；
- timeout 只影响是否继续尝试快路径，不影响安全性。

因此，本文不是 partial synchrony 协议，而是：

> **异步基础模型 + 乐观性能层**

### 4.3 威胁模型

**术语约定。**  
为避免 “adaptive” 一词造成歧义，本文区分三种不同层面的适应性：

1. **network-adaptive execution**：指协议在良好网络下走 optimistic fast path、在一般异步网络下退回 pure asynchronous fallback；
2. **old-committee corruption model**：正文基础模型采用静态腐蚀；仅在 dealer erasure 成立后，对聚合层分析 post-erasure 的条件性自适应腐蚀风险；本文不宣称 erasure-free fully adaptive old-dealer security；
3. **receiver-side posterior corruption**：指新委员会接收方在 `Update+Erase` 完成后被事后腐蚀时，历史 epoch 的 transport ciphertext 仍保持机密性。

这三者分别对应执行层、旧委员会秘密保持层、以及接收方传输层，不应混同。

本文在威胁模型上采用较保守的 practical operating point：旧委员会的基础 dispersal 与 dealer 侧 secrecy 采用静态腐蚀模型；仅在诚实 dealer 于本地 recoverability lock 形成后立即擦除的前提下，本文进一步分析聚合层在 **post-erasure corruption** 下的条件性安全。

### 4.3.1 旧委员会腐蚀（静态敌手模型）

本文对核心 ADKR 协议的基础敌手采用 **静态腐蚀模型（static corruption）**：

- 敌手必须在协议执行前确定腐化集合，且总数不超过 $f_o$。
- 对每个旧委员会诚实 dealer，定义擦除边界 $\tau_i^{erase-old}$（在生成 `Lock_i` 后立即擦除多项式、随机数及明文份额）。
  - 若敌手在 $\tau_i^{erase-old}$ 之前腐化该节点，可获得完整 dealer 状态；
  - 若在 $\tau_i^{erase-old}$ 之后腐化，则仅能获得擦除后残留状态。
- 本文不声称 erasure-free fully adaptive old-dealer security，这一选择与所使用的高效 DLog-based PVSS 方案仅在静态敌手下安全一致。

**新增的自适应安全分析（用于 AggRLO）**：

- 在 Aggregate RL-ADKR 中，dealer erasure 的时序约束更严格：诚实 dealer 必须在本地 recoverability lock 形成后**立即**擦除，且擦除必须在任何 `LOCK-SHARE^agg` 签发**之前**完成。
- 这保证了即使敌手在 AggLock 形成后自适应腐蚀 dealer，也无法获取已擦除的秘密多项式。
- 在 AGM 下，我们区分 5 种敌手事件，将聚合不可预测性归约到 COMDL 假设（见 §8 Lemma 2）。

#### 为什么还需要 receiver-side transport forward secrecy

AggRLO 解决的是 recovery 之前的 agreement object 安全性：对象可以先被锁定，再在之后恢复并进入接收方解密。  
但这条执行链本身也引入了一个新的攻击窗口：

> 被锁定对象的恢复与接收方解密发生在 agreement 之后，因此历史 transport ciphertext 与接收方本地解密状态之间存在一个可被后验腐蚀利用的时间断面。

如果接收方长期持有静态或可回溯的 epoch 解密状态，则敌手即使没有在协议在线执行期间腐蚀接收方，也可以在协议完成后通过 posterior corruption 获得旧 epoch 的解密能力，从而回溯打开历史 transport ciphertext，恢复当时接收的明文 share 与 witness。

因此，AggRLO 本身并不自动提供 post-recovery confidentiality。  
为了使 `AggRLO -> RecoverAgg -> receiver-side decryption` 这条执行链在 posterior corruption 下形成完整安全闭环，必须额外要求接收方在每个 epoch 结束后执行 `Update + Erase`，从而获得 receiver-side transport forward secrecy。

### 4.3.2 新委员会腐蚀与 receiver-side posterior corruption

基于上述动机，本文对新委员会成员额外引入一个 **后验腐蚀（posterior corruption）** 威胁模型，用于刻画接收方在协议结束后被腐蚀时，历史 transport ciphertext 是否会被回溯打开：

- 新节点 $P'_u$ 维护 epoch-specific 接收状态 $st_{u,e}$。
- 完成本轮密钥派生后，按协议执行 `Update + Erase`，推进至 $st_{u,e+1}$ 并不可逆地删除 $st_{u,e}$ 及所有临时明文、witness、recovery 缓存。
- **Online corruption**：在 `Erase` 前腐化，敌手获得当前 epoch 解密能力。
- **Posterior corruption**：在 `Erase` 后腐化，敌手仅能获得后续 epoch 状态，无法恢复旧 epoch 传输密文明文。

### 4.3.3 Receiver-side posterior corruption and forward secrecy

对每个诚实新委员会成员 $P'_u$，考虑按 epoch 演化的本地接收状态 $st_{u,e}$。

- 在 epoch $e$ 的 key derivation 完成后，$P'_u$ 执行原子的 `Update+Erase`；
- 状态推进到 $st_{u,e+1}$；
- 同时擦除 $st_{u,e}$、明文 share、witness 和恢复阶段的临时 buffer。

敌手可在两个时间点腐蚀接收方：

- `online corruption`：擦除前腐蚀，可获得当前 epoch 接收状态；
- `posterior corruption`：擦除后腐蚀，只能获得新状态 $st_{u,e+1}$ 和残余持久状态，不能用来回溯解密 epoch $e$ 的 transport ciphertext。

### 4.4 本文明确不承诺的性质

为避免过度承诺，本文明确不声称：

- 正文主协议的 erasure-free fully adaptive security；
- 不将 `network-adaptive execution` 解释为 `fully adaptive corruption security`；
- 不恢复 payload 即可验证最终密钥正确性；
- 对长期驻留型 endpoint compromise 给出通用防护；
- 不依赖 dealer erasure 即可获得旧委员会完全自适应安全。

这些边界写清楚，比模糊拔高更稳。

---

## 5. AggRLO：聚合优先的协议对象

### 5.1 为什么需要 AggRLO

若 agreement 输入是非聚合逐对象设计中的多个 recoverability-locked descriptors，则每个对象的 Lock 只独立保证“存在某个 holder 集合持有 $shard_{i,\cdot}$”，但不同对象的 holder 集合可能不同。这导致：

- 共识需要逐个验证 $\kappa$ 个对象，通信复杂度为 $O(\kappa\lambda n^2)$；
- 恢复需要 $\kappa$ 次独立采样，通信复杂度为 $O(\kappa\lambda n_o n_n)$；
- `Fallback` 需要复杂的 descriptor 编码、解码与裁剪。

Aggregate RL-ADKR 的核心做法是：**在共识前，将 $K=f_o+1$ 个 dealer 贡献聚合为 1 个 AggRLO**，后续所有阶段仅围绕这 1 个对象展开。

### 5.2 AggRLO 的定义

$$
\mathsf{AggRLO} = (S,\ \mathsf{AggHeader},\ \mathsf{AggLock})
$$

其中：

| 字段 | 内容 | 说明 |
|:---|:---|:---|
| $S$ | $K=f_o+1$ 个 dealer 的索引集合 | 公开可验证基数和成员合法性 |
| $\mathsf{AggHeader}$ | $(S,\widehat{rt},\widehat{C},\{\mathsf{Header}_i\}_{i\in S})$ | $\widehat{rt}$ 是聚合 payload 的 Merkle root；$\widehat{C}=\prod_{i\in S} C_i^{\rho_i}$ |
| $\mathsf{AggLock}$ | $(\widehat{S},\widehat{\Sigma})$ | $\widehat{S}\subseteq\mathcal{M}_{old}$，且 $|\widehat{S}|\ge L=n_o-f_o$；$\widehat{\Sigma}$ 是对 $H(\mathsf{AggHeader})$ 的聚合签名 |

### 5.3 为什么 AggRLO 满足三个语义要求

AggRLO 统一满足了 §2 中建立的 pre-recovery agreement object 三要求：

| 要求 | AggRLO 实现 | 具体机制 |
|:---|:---|:---|
| 共识前公开可检查 | $\mathsf{AdmitAgg}(\mathsf{AggRLO})$ | 检查 $|S|$、各 dealer 的公开合法性与本地 recoverability lock、承诺同态、AggLock 签名，均无需恢复 payload |
| 锁定后未来可恢复 | $\mathsf{AggLock}$ 的签名语义 | 至少 $\tau_{\mathsf{rec}}=n_o-2f_o$ 个诚实 holder 已持久化 $\widehat{sh}_u$，恢复时从 $\widehat{S}$ 收集 $\tau_{\mathsf{rec}}$ 个 fragment 即可重构 |
| 恢复结果绑定 | $\mathsf{BindingCheck}(\mathsf{AggHeader},\widehat{\mathsf{Payload}})$ | $\widehat{rt}=\mathsf{MerkleRoot}(\widehat{\mathsf{Payload}})$，并由 `AggLock -> AggHeader -> \widehat{rt} -> \widehat{\mathsf{Payload}}` 形成绑定链 |

### 5.4 AggLock 的语义（关键创新）

> **AggLock 不能从 per-dealer Lock 的逻辑 AND 推导出来。**

per-dealer Lock 只保证“对每个 $i$，存在某个 holder 集合持有 $shard_{i,\cdot}$”，但不保证是**同一个** holder 集合。AggLock 用以下过程解决此问题：

1. 旧委员会成员 $P_u$ 计算聚合份额
   $$
   \widehat{sh}_u = \sum_{i\in S} \rho_i \cdot shard_{i\to u}.
   $$
2. $P_u$ 验证 $\widehat{sh}_u$ 与 $\mathsf{AggHeader}$ 的一致性并持久化。
3. $P_u$ 签发：
   $$
   \sigma_u^{agg} \leftarrow \mathsf{Sign}_{sk_u}(CTX,e,\mathsf{AggHeader},\text{``}\widehat{sh}_u\text{ is stored''}).
   $$
4. 收集 $L=n_o-f_o$ 个签名形成：
   $$
   \mathsf{AggLock}=(\widehat{S},\widehat{\Sigma}).
   $$

签名绑定链条为：

$$
\mathsf{AggLock}
\xrightarrow{\text{binds to}}
\mathsf{AggHeader}
\xrightarrow{\text{binds to}}
\widehat{rt}
\xrightarrow{\text{binds to}}
\widehat{\mathsf{Payload}}.
$$

### 5.4.1 为什么 AggLock 是必要的：从 per-dealer recoverability 到 aggregate recoverability

这里需要明确区分两个不同强度的命题：

- **弱命题**：对每个 dealer $i\in S$，存在某个集合 $S_i$ 持有 $shard_{i,\cdot}$；
- **强命题**：存在**同一个集合** $\widehat{S}$，其每个成员都持有与同一 $\mathsf{AggHeader}$ 绑定的有效聚合份额 $\widehat{sh}_u$，从而能够恢复同一个聚合 payload。

前者并不推出后者。

**Structural Proposition 1 (Necessity of AggLock).**  
设 $S$ 为被纳入聚合对象的 dealer 集合。仅假设对每个 $i\in S$，存在一个有效的 per-dealer recoverability lock $\mathsf{Lock}_i$，则一般**不能推出**存在一个统一的 holder 集合 $\widehat{S}$，使得：

1. 每个 $u\in\widehat{S}$ 都持有与同一 $\mathsf{AggHeader}$ 绑定的有效聚合份额 $\widehat{sh}_u$；
2. 从 $\widehat{S}$ 中任取 $k$ 个诚实 holder 即可恢复唯一的聚合 payload $\widehat{\mathsf{Payload}}$。

因而，per-dealer Locks 的逻辑合取只给出 **component-wise recoverability**，并不给出 Aggregate RL-ADKR 所需的 **common-holder aggregate recoverability**；后者必须由额外的 AggLock 证书化。

这里不展开正式证明，只给出一个对思路已经足够硬的反例模板。  
考虑两个 dealer $i,j$。设它们各自的有效 lock signer set 为 $S_i,S_j$，满足

- $|S_i|, |S_j| \ge n_o-f_o$；
- 对应的诚实持有者集合 $H_i \subseteq S_i,\ H_j \subseteq S_j$ 满足 $|H_i|, |H_j| \ge n_o-2f_o$；
- 但 $|H_i \cap H_j| < k$，其中 $k$ 是聚合恢复所需的最小诚实持有者门槛。

则：

- $i$ individually future-recoverable；
- $j$ individually future-recoverable；
- 但不存在一个统一的 honest-heavy holder 集合，可同时为同一聚合对象提供不少于 $k$ 个诚实聚合 fragments。

这正是 holder-intersection 问题。也就是说，per-dealer future recoverability 只推出 **component-wise recoverability**，并不推出 Aggregate RL-ADKR 所需的 **common-holder aggregate recoverability**。AggLock 的作用不是压缩已有 lock，而是把“共同持有同一聚合对象”的缺失语义显式证书化。

### 5.4.2 为什么 AggLock 不是 batching

AggLock 不是对 $\{\mathsf{Lock}_i\}_{i\in S}$ 的压缩编码，也不是对它们的批量验证包装。

**Structural Proposition 2 (AggLock is not a batching artifact).**  
AggLock 不是对 per-dealer Locks 的打包或 batch verification 外壳。其认证语义从

$$
\forall i\in S:\; \text{“某个 quorum 持有 } shard_{i,\cdot}\text{”}
$$

变为

$$
\text{“同一个 quorum 持有与同一 } \mathsf{AggHeader}\text{ 绑定的 } \widehat{sh}_u\text{”}.
$$

前者是逐对象存在性陈述的合取，后者是针对单个聚合对象的共同存储义务陈述；两者在逻辑上与协议语义上均不等价。

| 维度 | batching / logical AND of per-dealer Locks | AggLock |
|:---|:---|:---|
| 认证对象 | 多个独立 dealer object | 单个 AggRLO |
| 持有语义 | 对每个 $i$，存在某个 holder 集合 | 同一 $\widehat{S}$ 持有聚合份额 |
| 可推出的恢复性质 | component-wise recoverability | single-object aggregate recoverability |
| 是否需要重新计算持有物 | 否 | 是，必须显式形成 $\widehat{sh}_u$ |
| 是否解决 holder-intersection | 否 | 是 |
| 是否可直接支持单对象 `RecoverAgg` | 否 | 是 |

这里需要再额外堵住一个常见误解：AggLock 也不是“在已有 per-dealer locks 之上，再让一组共同 holder 补一个 stronger batch certificate”。  
原因在于：如果这组共同 holder 只是共同签名、却没有显式形成并持久化 $\widehat{sh}_u$，那么它们对聚合对象的恢复义务并没有被证书化；而一旦它们显式形成并持久化 $\widehat{sh}_u$，协议语义上就已经新增了一层独立于 per-dealer lock 的 **aggregate recoverability layer**。这正是 AggLock 的本质，而不是 batching 的外壳。

### 5.5 AdmitAgg：共识前验证谓词

定义：

$$
\mathsf{AdmitAgg}(\mathsf{AggRLO}) \to \{0,1\}.
$$

其返回 1，当且仅当：

1. $|S| = K=f_o+1$；
2. 对所有 $i \in S$，$\mathsf{VerifyHeader}(\mathsf{Header}_i)=1$；
3. 对所有 $i \in S$，$\mathsf{VerifyLock}(\mathsf{Lock}_i,\mathsf{Header}_i)=1$；
4. $\widehat{C} = \prod_{i\in S} C_i^{\rho_i}$；
5. $\mathsf{VerifyAggLock}(\mathsf{AggLock},\mathsf{AggHeader}) = 1$。

其中 $\mathsf{VerifyAggLock}=1$ 表示：

- $\widehat{\Sigma}$ 是对 $H(\mathsf{AggHeader})$ 的有效聚合认证；
- 签名者集合 $\widehat{S}$ 满足 $|\widehat{S}| \ge L=n_o-f_o$；
- 恢复门槛为 $\tau_{\mathsf{rec}}=n_o-2f_o$；
- 每个诚实签名者都仅在持久化与 $\mathsf{AggHeader}$ 绑定的 $\widehat{sh}_u$ 后才签发 `LOCK-SHARE^agg`。

### 5.6 与 APVSS 的关系

AggLock 借鉴了 APVSS（Bacho-Loss, CCS 2023）“聚合优先于验证”的设计哲学，但构造上根本不同：

| | APVSS | AggLock |
|:---|:---|:---|
| 聚合对象 | 公开 PVSS transcripts | holder storage commitments |
| 聚合层面 | 数学承诺线性组合 | 协议层 quorum 背书 |
| 安全目标 | aggregated unpredictability | aggregate recoverability + binding |

---

## 6. 协议总览：聚合优先的四阶段 ADKR

**范式声明。**  
Aggregate RL-ADKR 不应被理解为“在 Practical ADKR 上增加一个聚合优化”，而应被理解为一种新的 aggregate-first ADKR 执行范式：

$$
\text{LockAgg} \rightarrow \text{AgreeAgg} \rightarrow \text{RecoverAgg} \rightarrow \text{Derive}.
$$

该范式的结构特征是：聚合发生在 agreement 之前，agreement 作用于单个 AggRLO，recover 只针对单个聚合对象执行，而 derive 不再承担内部聚合。

Aggregate RL-ADKR 将原六阶段协议重构为四个阶段：

```text
┌──────────────────────────────────────────────────────────┐
│                  Aggregate RL-ADKR                       │
├──────────┬──────────┬──────────────┬─────────────────────┤
│ LockAgg  │ AgreeAgg │ RecoverAgg   │ Derive              │
│ (聚合锁定)│ (共识聚合)│ (恢复聚合对象)│ (派生新密钥)         │
├──────────┼──────────┼──────────────┼─────────────────────┤
│ 旧委员会  │ 旧委员会  │ 新←旧委员会   │ 新委员会             │
│ 内部完成  │ 共识单个  │ 单对象恢复    │ 解密 + 输出          │
│ AggRLO   │ AggRLO   │              │                     │
└──────────┴──────────┴──────────────┴─────────────────────┘
```

### 阶段对应关系

| 非聚合逐对象设计 | Aggregate RL-ADKR | 变化程度 |
|:---|:---|:---|
| Disperse | LockAgg（前半） | 不变（per-dealer dispersal） |
| LockSet | LockAgg（后半） | 重写（增加 AggLock 收集） |
| Agree（多对象） | AgreeAgg（1 个对象） | 中度修改（Gate -> AdmitAgg，Fallback 简化） |
| Recover（多次恢复） | RecoverAgg（1 次） | 重写（单对象恢复，不再有逐对象重复恢复） |
| Derive | Derive | 小改（取消内部聚合步骤） |

### 不变量

与 recoverability-locked 设计原则一致：

> **只有已经被 recoverability-locked 的 transcript object 才能进入后续 recover 与 key derivation。**

但现在这个 object 是 **1 个 AggRLO**，而非非聚合逐对象设计中的多个 per-dealer RLO。

---

## 7. 详细协议

### 7.1 LockAgg：聚合锁定阶段

LockAgg 在旧委员会内部完成，输出单个 $\mathsf{AggRLO}$。

#### 7.1.1 Dealer Dispersal + Local Lock（前半）

对每个 dealer $P_i \in \mathcal{M}_{old}$ 并行执行：

```text
1. 采样双变量多项式 F_i(x,y)，承诺 C_i
2. 构造 Header_i = (C_i, rt_i, π_i^deal, {ct_{i,u}}_{u∈[n_n]})
3. 向 P_u 发送 (shard_{i→u}, π_{i→u}^merkle)
4. 收集 n_o - f_o 个 LOCK-SHARE，形成 Lock_i
5. 立即擦除本地秘密（F_i, 随机数）
6. 广播 (Header_i, Lock_i)
```

#### 7.1.2 旧委员会成员处理（后半，新设计）

每个旧委员会成员 $P_u \in \mathcal{M}_{old}$ 执行：

```text
// Step A: 验证 per-dealer 对象
for each received (Header_i, Lock_i):
    assert VerifyHeader(Header_i) = 1
    assert VerifyLock(Lock_i, Header_i) = 1
    验证自己的 shard_{i→u} 与 rt_i 绑定
    持久化 shard_{i→u}

// Step B: 确定 S 并计算聚合份额
当本地 ready pool 已有至少 L 个有效 dealer objects：
    S ← CanonicalDealerSet(ready pool, K)  // 按公开规则规范选取 K 个
    AggHeader ← CanonicalComputeAggHeader(S)
    ŝh_u ← ∑_{i∈S} ρ_i · shard_{i→u}
    验证 ŝh_u 与 AggHeader 的一致性
    持久化 ŝh_u

// Step C: 签发并预广播 LOCK-SHARE^agg
    σ_u^agg ← Sign_{sk_u}(CTX, e, AggHeader, "ŝh_u is stored")
    向 M_old ∪ {Leader} 多播 σ_u^agg
```

#### 7.1.3 Leader 收集 AggLock

Leader 执行：

```text
1. 从 ready pool 按公开规则选取 K 个 dealer，确定 S
2. 计算 AggHeader：
   rt_hat ← MerkleRoot(SharedPayloadHat)
   C_hat  ← ∏_{i∈S} C_i^{ρ_i}
   AggHeader ← (S, rt_hat, C_hat, {Header_i}_{i∈S})
3. 收集 L = n_o - f_o 个 σ_u^agg（绑定到 h_hat = H(AggHeader)）
4. 形成 AggLock ← (S_hat, Sigma_hat)
5. 广播 AggRLO ← (S, AggHeader, AggLock)
```

#### 7.1.3A Fallback 前提：聚合对象的规范化与可组装视图

这里不把 `Fallback` 的唯一性写成正式证明，只记录这个思路必须满足的三个 design constraints。

第一，`dealer` 集合 $S$ 必须从至少含 $L$ 个 ready objects 的候选池中规范选取 $K$ 个。  
节点先通过 `CallHelp` 与已有广播材料补齐这个**可比较的候选池**，再对其中通过 `VerifyHeader ∧ VerifyLock` 的对象应用公开固定顺序，得到 canonical dealer set。

第二，`AggLock` 的签名者集合 $\widehat{S}$ 也必须规范化。  
即使诚实节点已经认同同一个 `AggHeader`，它们先看到的 `LOCK-SHARE^agg` 子集仍可能不同；因此 `Fallback` 不能把“先看到的任意 $n_o-f_o$ 个签名”直接拼成 `AggLock`，而应先在本地补齐可验证签名池，再按公开固定顺序选出 canonical signer set。

第三，`AggRLO` 的字节串编码必须唯一。  
`{Header_i}_{i∈S}` 的排列顺序、`(\widehat{S},\widehat{\Sigma})` 的聚合顺序、以及最终 `AggLock` 的编码格式都应固定，否则即便逻辑对象相同，也可能产生不同 digest。

因此，本文在思路层面引入一个更准确的前提：

> `Fallback` 并不要求诚实节点在任意时刻立即拥有相同局部视图；它只要求节点在 `help-fetch + LOCK-SHARE^agg` 预广播的帮助下，最终补齐到同一批可验证材料超集后，再应用同一套 canonicalization 规则，从而归一到同一个 AggRLO。

换言之，single-digest `Fallback` 的唯一性来源不是“消息恰好到得一样”，而是“共享候选池 + 确定性规范化”。

#### 7.1.4 Dealer Erasure 的时序（关键安全点）

```text
Timeline:
  t1: dealer 采样多项式
  t2: dealer 发送 shard_{i→u}
  t3: dealer 收集 Lock_i
  t4: dealer 擦除本地秘密        ← 必须在 AggLock 形成之前
  t5: holders 计算 ŝh_u 并签发 LOCK-SHARE^agg
  t6: Leader 收集 AggLock
```

安全保证为：

- 敌手在 $t_6$ 之后腐蚀 dealer $i$，无法恢复已擦除的 $F_i$；
- 敌手在 $t_5$ 之前腐蚀 dealer $i$，其获胜能力在 AGM 下归约到 COMDL；
- AggLock 的有效性依赖于 holder 在 $t_4$ 之后签发，从而切断 dealer 侧状态残留与聚合恢复之间的后门。

#### 7.1.5 AggLock 与 per-dealer Lock 的独立性

| | per-dealer Lock | AggLock |
|:---|:---|:---|
| 签名者 | 旧委员会成员（作为 per-dealer shard 持有者） | 旧委员会成员（作为聚合 shard 持有者） |
| 签名语义 | “我持有 $shard_{i\to u}$” | “我持有 $\widehat{sh}_u = \sum \rho_i \cdot shard_{i\to u}$” |
| 收集者 | 各 dealer 独立收集 | Leader 或分布式协调者收集 |
| 绑定对象 | 单个 `Header_i` | 聚合 `AggHeader` |
| 能否相互推导 | — | 不能从 per-dealer Lock 的 AND 推出 AggLock |

### 7.2 AgreeAgg：共识聚合对象阶段

AgreeAgg 的结构仍采用 `Fastlane + Fallback` 双路径，但 Gate 谓词从检查多对象逐项候选简化为检查单个 AggRLO。

#### 7.2.1 Fastlane

```text
Leader：广播 AggRLO = (S, AggHeader, AggLock)

各节点 P_u：
    收到 AggRLO：
        补齐缺失的 per-dealer (Header_i, Lock_i)（通过 CallHelp）
        assert AdmitAgg(AggRLO) = 1
        发送第一轮确认 <ACK1, H(AggRLO)>_u

    收集 2f_o + 1 个 ACK1 → Cert1
    验证 Cert1 → 发送第二轮确认 <ACK2, H(AggRLO)>_u
    收集 2f_o + 1 个 ACK2 → Cert2
    锁定 AggRLO
```

#### 7.2.2 Fallback

```text
各节点：
    继续通过 CallHelp 与预广播材料补齐本地候选池
    当视图满足 FallbackReady：
        S* ← CanonicalDealerSet(valid dealer pool, K)
        AggHeader* ← CanonicalComputeAggHeader(S*)
        S_hat* ← CanonicalSignerSet(valid agg-signature pool for AggHeader*)
        AggLock* ← CanonicalAssembleAggLock(S_hat*)
        AggRLO* ← CanonicalEncode(S*, AggHeader*, AggLock*)

        调用 MVBA_fb[id](H(AggRLO*))
        输出共同 AggRLO
```

这里的 `FallbackReady` 只是一条思路层面的接口约束：节点不应在任意局部残缺视图上过早提交 digest，而应在本地已经补齐到“可规范化”的候选池后再进入单对象 MVBA。

#### 7.2.3 Fastlane -> Fallback 切换

| 触发条件 | 处理 |
|:---|:---|
| Leader 的 AggRLO 未通过 `AdmitAgg` | 各节点转入 `CallHelp + canonicalization`，在 `FallbackReady` 后提交 digest |
| Leader 超时 | Timeout 后继续补齐候选池，在 `FallbackReady` 后提交 digest |
| Leader 诚实但网络分区 | 部分节点锁定，其余进入 Fallback；MVBA 保证最终统一 |

关键点在于：`LOCK-SHARE^agg` 已在 `LockAgg` 末尾预广播，因此 Fallback 不需要重新发起一轮 holder 交互；它真正新增的只是“补齐共享候选池并做规范化”的本地整理过程，而不是新的对象层往返。

### 7.3 RecoverAgg：恢复聚合对象阶段

RecoverAgg 只恢复 1 个聚合对象 $\widehat{\mathsf{Payload}}$。

这里的 $\widehat{\mathsf{Payload}}$ 不是抽象的“聚合 transcript”占位符，而应理解为：针对固定 dealer 集合 $S$ 形成的**逐接收方聚合传输向量**。它的第 $u$ 个分量对应新委员会成员 $P'_u$ 的聚合密文；因此 `RecoverAgg` 的任务是恢复这一整条聚合向量，而 `Derive` 的任务是由各接收方分别解开自己的分量并得到 $\widehat{s}_u$。

| 维度 | 非聚合逐对象恢复 | RecoverAgg（1 次） |
|:---|:---|:---|
| 恢复对象 | 多个逐 dealer payload | 1 个 $\widehat{\mathsf{Payload}}$ |
| 请求范围 | 每次向不同 holder 子集请求 | 向 $\widehat{S}$ 中统一请求 |
| Holder 返回 | $(shard_{i\to u}, \pi_{i\to u}^{merkle})$ | $(\widehat{sh}_u, \pi_u^{agg})$ |
| 通信复杂度 | $O(\kappa \lambda n_o n_n)$ | $O(\lambda n_o n_n)$ |

#### 7.3.1 协议流程

```text
新委员会成员（恢复者）：

// Step 1: 请求
向 S_hat 中所有 holder 发送 <RECOVER-AGG, H(AggRLO)>

// Step 2: Holder 响应
Holder P_u:
    从持久化存储中取出 ŝh_u
    构造 π_u^agg：
        - 各 i∈S 的 Merkle 证明 π_{i→u}^merkle
        - 聚合等式证明 g^{ŝh_u} = ∏ (g^{shard_{i→u}})^{ρ_i}
        - 聚合 payload Merkle 证明
    返回 (ŝh_u, π_u^agg)

// Step 3: 重构
收集 tau_rec 个有效 fragment（tau_rec = n_o - 2f_o）
通过 Reed-Solomon 解码重构 SharedPayloadHat

// Step 4: 绑定检查
assert MerkleRoot(SharedPayloadHat) == rt_hat
```

#### 7.3.2 聚合 Fragment 证明

利用编码方案的线性性质，聚合份额的编码等于各 per-dealer 份额编码的线性组合。因此，$\pi_u^{agg}$ 的大小虽然包含多个 per-dealer witness，但其数量级仍与原 per-dealer fragment 证明同量级，可记为 $O(\lambda K)$。

### 7.4 Derive：密钥派生阶段

`Derive` 阶段几乎不变，唯一结构性变化是：

- 非聚合逐对象设计：
  $$
  sk'_u = \sum_{i\in S} s_{i\to u};
  $$
- 新方案：
  $$
  sk'_u = \widehat{s}_u.
  $$

也就是说，聚合已经在 `LockAgg` 中完成，因此 `Derive` 不再承担内部聚合职责，只需解密、验证并输出。

从接口角度看，`RecoverAgg -> Derive` 传递的也不再是“一组待再聚合的 dealer payload”，而是“一个已经完成 dealer-side aggregation 的 receiver-indexed payload vector”。这一步写清楚后，`LockAgg -> RecoverAgg -> Derive` 的闭环会更明确：前者负责把逐 dealer 贡献压成单对象，后者只负责恢复并解开该单对象。

### 7.5 Update + Erase

这一部分与本文其余阶段正交：

- 新委员会在完成 `RecoverAgg / Verify / Derive` 后执行 `RFS.Update + RFS.Erase`；
- 删除旧 epoch 接收状态、恢复期明文、witness 与临时 buffer；
- 由此维持 receiver-side transport forward secrecy。

---

## 8. 安全性质与证明主线

### 8.1 安全假设

| 假设 | 用途 |
|:---|:---|
| COMDL (AGM) | 聚合秘密的不可预测性 |
| Signature EUF-CMA | AggLock 与本地 recoverability lock 不可伪造 |
| Hash as Random Oracle | 签名绑定、承诺绑定 |
| VE IND-CPA | 加密份额的机密性 |
| Dealer Erasure | 自适应腐蚀下的 backward secrecy |

### 8.2 AggRLO 的三个安全属性

**属性一：聚合公开可检查（Aggregate Public Checkability）**

任何节点通过 $\mathsf{AdmitAgg}(\mathsf{AggRLO})$ 即可在共识前验证 AggRLO 合法性，无需恢复完整 payload。

**属性二：聚合未来可恢复（Aggregate Future Recoverability）**

若 $\mathsf{AdmitAgg}(\mathsf{AggRLO}) = 1$，则 $\widehat{\mathsf{Payload}}$ 可在未来由 $\widehat{S}$ 中的持片者恢复。证明路径与通常的 quorum-held recoverability 论证一致，但应用在聚合 shard 上。

**属性三：聚合恢复绑定（Aggregate Recovery Binding）**

`RecoverAgg` 输出与 $\mathsf{AggRLO}$ 唯一绑定：$\mathsf{AggLock} \to \widehat{h} = H(\mathsf{AggHeader}) \to \widehat{rt} \to \widehat{\mathsf{Payload}}$。

### 8.3 核心引理（4 个）

以下安全性引理建立在 §5 的两个结构性命题之上：其一，per-dealer Locks 不推出 common-holder aggregate recoverability；其二，AggLock 不是 batching artifact，而是新增的 aggregate recoverability layer。基于这两个对象层前提，正文安全分析只保留真正的安全性引理。

**Lemma 1（诚实持有者保证）**  
若 $\mathsf{VerifyAggLock} = 1$，则至少 $n_o-2f_o$ 个诚实旧成员已持有与 $\mathsf{AggHeader}$ 绑定的有效 $\widehat{sh}_u$ 并已持久化。

**Lemma 2（聚合不可预测性）**  
在自适应腐蚀 + dealer erasure 模型下，给定 $\mathsf{AggRLO}$，PPT 敌手无法以不可忽略优势输出聚合秘密贡献。证明在 AGM 下区分 5 种事件，并归约到 COMDL。

**Lemma 3（AdmitAgg 过滤恶意 Leader）**  
恶意 Leader 构造的 $\mathsf{AggRLO}$ 通过 $\mathsf{AdmitAgg}$ 的概率为 $\mathsf{negl}(\lambda)$，除非伪造签名或破坏承诺绑定。

**Lemma 4（Dealer Erasure 时序正确性）**  
诚实 dealer 的擦除在所有 `LOCK-SHARE^agg` 签发**之前**完成，因此 AggLock 不会建立在未擦除 dealer 状态之上。

### 8.4 阶段安全性定理（3+1）

**Theorem 1（LockAgg 安全性）**  
`LockAgg` 同时满足 Safety（聚合秘密不可预测）、Liveness（有效 AggRLO 产出）与 Binding（与 $\widehat{\mathsf{Payload}}$ 绑定）。

**Theorem 2（RecoverAgg 安全性）**  
若 `AdmitAgg=1` 且恢复门槛为 $\tau_{\mathsf{rec}}=n_o-2f_o$，则 `RecoverAgg` 可从 $\widehat{S}$ 恢复唯一的 $\widehat{\mathsf{Payload}}$，且通信复杂度为 $O(\lambda n_o n_n)$；在本文正文协议中，不再出现逐对象恢复所带来的 multiplicity 参数。

**Theorem 3（AgreeAgg 安全性）**  
`AgreeAgg` 满足 Fastlane Safety、Fallback Termination 与 Path Consistency：Fastlane 与 Fallback 若均输出，则输出的是同一个 AggRLO。

**Theorem 4（端到端 ADKR 安全性）**  
Aggregate RL-ADKR 满足：

1. Aggregate Agreement；
2. Key Validity；
3. Threshold Secrecy；
4. Optimistic Responsiveness + Asynchronous Liveness。

### 8.5 Receiver-side Transport Forward Secrecy：posterior corruption 下的补充安全闭环

本节不引入新的主对象语义，而是补充分析一个独立于 AggRLO object validity 之外的风险：  
即使 AggRLO 已经保证了 agreement、recoverability 与 recovery binding，若接收方在协议结束后被 posterior corruption，敌手是否仍能回溯解密历史 transport ciphertext。  
为此，我们通过一个 epoch-based 挑战游戏定义 receiver-side transport forward secrecy。

**Game.**  
敌手选择目标接收方 $u^\star$、目标 epoch $e^\star$ 以及两条等长消息
$m_0,m_1$。挑战者使用目标接收方在 epoch $e^\star$ 的公开接收密钥生成挑战密文
$ct^\star$，其中明文为 $m_b$。  
在挑战密文生成之后，诚实接收方继续按协议执行，
并在完成当前 epoch 的 `Recover / Verify / Derive` 后执行 `Update+Erase`。  
敌手只能在擦除发生之后腐蚀目标接收方，
此时它获得的是后继状态 $st_{u^\star,e^\star+1}$ 与擦除后残余状态，
而不是旧状态 $st_{u^\star,e^\star}$。  
若敌手仍能以非忽略优势区分 $b$，则游戏获胜。

**Theorem (Receiver-side transport forward secrecy).**  
若底层 key-evolving PKE 满足 forward security，
且诚实接收方在每个 epoch 结束时正确执行 `RFS.Update + RFS.Erase`，
则 Aggregate RL-ADKR 满足 receiver-side transport forward secrecy。

**Proof sketch.**

1. 挑战密文的机密性首先规约到底层 epoch-specific 接收密钥上的 IND security；
2. 一旦诚实接收方完成 `Update+Erase`，敌手在 posterior corruption 中看不到旧状态 $st_{u,e}$；
3. 底层 key-evolving PKE 的更新单向性保证从 $st_{u,e+1}$ 无法恢复 $st_{u,e}$；
4. 因而，敌手在擦除后腐蚀时获得的信息不足以解开 epoch $e$ 的 transport ciphertext。

### 8.6 Layered Public Verifiability

本文只主张两层 public verifiability：

- **metadata-level**：验证被锁定对象具备公开合法性与未来可恢复性；
- **recovery-level**：在聚合恢复之后，验证恢复结果与先前锁定对象一致，并据此验证 $pk_{new}$。

这里需要特别强调：

- **metadata-level** 不主张 payload correctness 已在 agreement 前被完整验证；它只主张：被锁定对象已通过 `Header` / `AggHeader` legality 检查，且 `Lock` / `AggLock` 已将该对象提升到 future-recoverable 状态。
- **recovery-level** 则进一步通过 `BindingCheck` 验证恢复出的 $\widehat{\mathsf{Payload}}$ 与先前锁定对象一致，并据此支持后续 key derivation 的公开可验证性。

这一分层与 recoverability-locked 对象的一般论证结构一致，只是对象粒度在本文中固定为聚合 transcript。

### 8.7 安全性证明层次

```text
主定理：端到端 ADKR 安全性
│
├── 依赖 §5 的 Structural Proposition 1:
│   Per-dealer Locks do not imply aggregate recoverability
├── 依赖 §5 的 Structural Proposition 2:
│   AggLock is not a batching artifact
│
├── Theorem 1: LockAgg
│   ├── Lemma 1: 诚实持有者保证
│   ├── Lemma 2: 聚合不可预测性 -> COMDL (AGM)
│   ├── Lemma 3: AdmitAgg 过滤
│   ├── Lemma 4: Erasure 时序
│   └── Lemma 5: AggLock EUF-CMA 归约
│
├── Theorem 2: RecoverAgg
│   ├── Lemma 1 (复用)
│   └── Lemma 6: 恢复通信上界
│
├── Theorem 3: AgreeAgg
│   ├── Lemma 7: Fastlane Safety
│   ├── Lemma 8: Fallback Termination
│   └── Lemma 9: Path Consistency
│
└── Theorem 4: End-to-End
    ├── Corollary 1: Aggregate Agreement
    ├── Corollary 2: Key Validity
    ├── Corollary 3: Threshold Secrecy
    └── Corollary 4: Liveness + Optimistic Responsiveness
```

---

## 9. 复杂度分析

### 9.1 通信复杂度对比

| 阶段 | 非聚合逐对象设计 | Aggregate RL-ADKR | 改进 |
|:---|:---|:---|:---|
| Per-dealer dispersal | $O(\lambda K n_o^2)$ | $O(\lambda K n_o^2)$ | 相同 |
| Lock 收集 | $O(\lambda K n_o^2)$ | $O(\lambda K n_o^2) + O(\lambda n_o^2)$ | 增加一轮 AggLock 预广播 |
| 共识（Agree） | $O(\kappa \lambda n_o^2)$ | $O(\lambda n_o^2)$ | 不再有 $\kappa$-many object agreement |
| 恢复（Recover） | $O(\kappa \lambda n_o n_n)$ | $O(\lambda n_o n_n)$ | 不再有 $\kappa$-many recovery sessions |
| **总计** | $O(\lambda n_o^2(K + \kappa) + \kappa \lambda n_o n_n)$ | $O(\lambda n_o^2(K + 1) + \lambda n_o n_n)$ | — |

### 9.2 从 $\kappa$-scale 对象重复到单对象主路径

| 来源 | 非聚合逐对象基线中 $\kappa$ 的作用 | Aggregate RL-ADKR 如何改写 |
|:---|:---|:---|
| 共识 | $\kappa$ 个 per-dealer RLO 逐个验证 | 1 个 AggRLO，`AdmitAgg` 一次检查 |
| 恢复 | $\kappa$ 次独立采样恢复 | 1 次聚合恢复 |
| Fallback | $\kappa$ 个对象的 descriptor 编码/解码/裁剪 | 单 digest，无需裁剪 |

### 9.3 额外开销与净收益

| 开销项 | 大小 | 说明 |
|:---|:---|:---|
| `LOCK-SHARE^agg` 预广播 | $O(\lambda n_o^2)$ | $n_o$ 个成员各发送 1 个签名 |
| $\pi_u^{agg}$ 证明 | $O(\lambda K)$ per fragment | 编码线性性质保证与 per-dealer 同量级 |
| `AdmitAgg` 验证 | $O(K)$ 群运算 + $O(L)$ 签名验证 | 分别对应 dealer set 与 AggLock holder quorum |

**净收益**：以 $O(\lambda n_o^2)$ 的 `LockAgg` 额外通信，换取 agreement 与 recovery 从 $\kappa$-many object orchestration 收缩为单对象主路径。当非聚合逐对象基线中的 $\kappa \gg 1$ 时，这一收益尤为显著。

### 9.4 Good case / Bad case 分析

本节沿用相同的 good-case / bad-case 分析框架，但将“descriptor-based fallback”替换为“single-digest fallback”：

- **Good case**：`LockAgg + Fastlane + RecoverAgg + Derive`，控制面和恢复面都不再带有逐对象重复编排；
- **Bad case**：`LockAgg + MVBA(digest) + RecoverAgg + Derive`，仍保持纯异步终止性，但因输入是单对象 digest，回退路径比原 descriptor MVBA 更紧凑。

---

## 10. 评估设计

### 10.1 实验要回答的四个问题

1. `LockAgg` 的额外预广播通信是否显著小于非聚合逐对象基线中的多对象编排成本？
2. `AgreeAgg` 对单对象执行 Fastlane/Fallback 时，是否明显提高成功率和降低时延？
3. `RecoverAgg` 是否真的把恢复通信从 $O(\kappa \lambda n_o n_n)$ 压缩到 $O(\lambda n_o n_n)$？
4. Dealer erasure 与 `Update+Erase` 的时序约束在实现中是否可控？

### 10.2 从 frontier 前移到系统收益：一个分析性量化模型

本节沿用同一套分析性量化模型，但将对象层级替换为聚合优先视角。核心问题不变：

> agreement frontier 若更早、且 agreement object 从多对象输入压缩到 1 个聚合对象，系统层收益会体现在哪里？

本文仍建议从以下角度量化：

- agreement eligibility time；
- fastlane viability；
- good-case latency；
- total communication。

### 10.3 Ready Object Density：定义、测试过程与比较

对非聚合逐对象设计，`ready object density` 度量的是在窗口 $W$ 内具备 `VerifyHeader ∧ VerifyLock` 资格的对象数量。  
对 Aggregate RL-ADKR，则可把该指标改写为：

- **per-dealer ready density**：底层 dispersal 的完成速度；
- **aggregate ready time**：单个 AggRLO 第一次满足 `AdmitAgg=1` 的时间；
- **aggregate fastlane fill ratio**：leader 在窗口 $W$ 内是否已具备完整 AggRLO 提议资格。

这一改写保留了原指标的系统意义，但更直接对应单对象 agreement 的执行特征。

### 10.4 Baselines / Ablations

保留以下对比协议，每组直接服务于三个贡献的验证：

| 基线 | 目的 |
|------|------|
| `Practical ADKR` | 展示 finished-dispersal 对象下的纯异步性能（贡献一对标） |
| **`Aggregate RL-ADKR (full)`** | 本文完整协议 |
| `Aggregate RL-ADKR w/o forward secrecy` | 验证 posterior corruption 安全闭环所需的附加机制及其实现代价 |
| `Aggregate RL-ADKR w/ weak gate` (仅 VerifyHeader+VerifyLock，不检查 AggLock) | **关键消融**：证明 AggLock 对恢复成功率和密钥一致性的必要性 |
| `Finished-object fastlane shell` | 仅给 Practical ADKR 套上快路径外壳，证明仅换执行框架而不换对象语义无法获得相同收益 |

### 10.5 场景

至少覆盖：

- 64 / 128 / 256 节点 WAN；
- 正常网络 + honest leader；
- 恶意 leader / 提议冲突；
- 高延迟 / 抖动 / 带宽受限；
- payload withholding / `CallHelp` 压力增大场景。

### 10.6 指标

至少包括：

- 端到端 epoch latency；
- `Fastlane` 锁定延迟；
- `Fallback` 终止延迟；
- 总通信量；
- 每节点收发字节；
- `VerifyHeader` / `VerifyLock` / `AdmitAgg` / `RecoverAgg` / `FSDec` / `RFS.Update` / `RFS.Erase` CPU 时间拆分；
- agreement eligibility time / ready object density / fastlane fill ratio；
- 被恢复 payload 总字节量；
- `LOCK-SHARE^agg` 预广播开销；
- 内存与持久化开销。

---

## 11. 伪代码组织

### 11.1 可直接复用的基础模块

以下模块**不需要修改**：

| 模块 | 说明 |
|:---|:---|
| $\mathsf{PVSS.Deal}$ | per-dealer 多项式采样、承诺、密钥加密 |
| $\mathsf{VerifyHeader}$ | per-dealer 公开验证 |
| $\mathsf{VerifyLock}$ | per-dealer Lock 验证 |
| $\mathsf{CallHelp}$ | 消息补齐 |
| $\mathsf{VE.Enc}$ / $\mathsf{VE.Dec}$ | 可验证加密 |
| $\mathsf{MerkleVerify}$、$\mathsf{RS\_Decode}$ | 基础验证与重构 |

### 11.2 新增模块

#### LockAgg（新）

```text
def LockAgg_Holder(Header_i, Lock_i, shard_{i→u}, π_{i→u}^merkle):
    for each received (Header_i, Lock_i):
        assert VerifyHeader(Header_i)
        assert VerifyLock(Lock_i, Header_i)
        assert MerkleVerify(rt_i, shard_{i→u}, π_{i→u}^merkle)
        store(shard_{i→u})

    when valid_set size ≥ L:
        S ← 按公开规则选取 K 个
        AggHeader ← ComputeAggHeader(S, {Header_i})
        ŝh_u ← Σ_{i∈S} ρ_i · shard_{i→u}
        store(ŝh_u)
        σ_u^agg ← Sign(sk_u, (CTX, epoch, AggHeader, "aggregate-shard-stored"))
        multicast_to(M_old ∪ {Leader}, σ_u^agg)

def ComputeAggHeader(S, {Header_i}_{i∈S}):
    C_hat ← ∏_{i∈S} C_i^{ρ_i}
    rt_hat ← ComputeAggregateMerkleRoot({rt_i}, S)
    return (S, rt_hat, C_hat, {Header_i})

def LockAgg_Leader():
    S ← 确定(dealer_lock_set)
    AggHeader ← ComputeAggHeader(S, ...)
    收集 L 个 σ_u^agg → AggLock
    AggRLO ← (S, AggHeader, AggLock)
    broadcast(AggRLO)
```

#### AdmitAgg（新）

```text
def AdmitAgg(AggRLO):
    assert |S| == K
    for i in S:
        assert VerifyHeader(Header_i) and VerifyLock(Lock_i, Header_i)
    assert C_hat == ∏_{i∈S} C_i^{ρ_i}
    assert VerifyAggLock(AggLock, AggHeader)
    return True
```

#### AgreeAgg（修改）

```text
def AgreeAgg_Fastlane(AggRLO):
    assert AdmitAgg(AggRLO)
    # 两轮确认（同原方案）
    ...

def AgreeAgg_Fallback():
    补齐 valid dealer pool 与 valid agg-signature pool
    assert |valid dealer pool| ≥ L
    S* ← CanonicalDealerSet(valid dealer pool, K)
    AggHeader* ← CanonicalComputeAggHeader(S*)
    S_hat* ← CanonicalSignerSet(valid agg-signature pool for AggHeader*)
    AggLock* ← CanonicalAssembleAggLock(S_hat*)
    AggRLO* ← CanonicalEncode(S*, AggHeader*, AggLock*)
    digest ← H(AggRLO*)
    return MVBA_fb[id](digest)
```

#### RecoverAgg（重写）

```text
def RecoverAgg(AggRLO):
    向 S_hat 请求 → 收集 tau_rec 个 (ŝh_u, π_u^agg)
    验证每个 π_u^agg → RS_Decode → SharedPayloadHat
    assert MerkleRoot(SharedPayloadHat) == rt_hat
    return SharedPayloadHat
```

#### Derive（小改）

```text
def Derive(SharedPayloadHat, AggHeader):
    for each P'_u:
        ŝ_u ← VE_Dec(sk'_u, SharedPayloadHat[u])
        assert VerifyShare(C_hat, ŝ_u, u)
        sk'_u ← ŝ_u
    pk_new ← ExtractPublicKey(AggHeader)
    UpdateAndErase()
    return (pk_new, {sk'_u})
```

### 11.3 旧式多对象 Fallback 接口

以下旧式多对象 fallback 接口在 Aggregate RL-ADKR 中**不再需要**：

- $\mathsf{BuildDescriptor}$；
- $\mathsf{DecodeDescriptor}$；
- $\mathsf{SelectTopL}$；
- $\mathsf{ValidateDescriptor}$（被 $\mathsf{AdmitAgg}$ 替代）。

其余基础接口（如 `CallHelp`）完全复用。

---

## 12. 讨论

### 12.1 Receiver-side transport forward secrecy 在 Aggregate RL-ADKR 中的角色

receiver-side transport forward secrecy 不是与 AggRLO 并列的第二主贡献，而是贡献一的补充安全机制。  
AggRLO 解决的是：在 recovery 之前，什么对象已经足够安全地进入 agreement，并在锁定后可恢复、可绑定地进入后续执行。  
但它并不自动保证：接收方在协议完成后被腐蚀时，历史 transport ciphertext 仍不能被回溯打开。

如果缺失 forward secrecy，则协议在静态腐蚀或在线腐蚀模型下仍可成立；  
但一旦考虑 posterior corruption，敌手就可能通过获取旧 epoch 的接收方解密能力，回溯解开历史 ciphertext，恢复当时收到的明文 share 与 witness。  
因此，forward secrecy 的作用不是重新定义对象语义，而是为 `RecoverAgg -> receiver-side decryption` 这最后一段执行链补上 posterior-corruption 下的保密性闭环。

### 12.2 为什么 AggRLO 足以支撑 fast path

AggRLO 继承了 recoverability-locked object 的三层语义：

1. `AggHeader` 给出 pre-consensus public legality；
2. `AggLock` 给出 quorum-backed future recoverability，且解决了 holder-intersection 问题；
3. `BindingCheck` 保证锁后恢复结果不偏离先前锁定对象。

AggRLO 的独特价值在于：它将三层语义统一到**单个聚合对象**上，使 Fastlane 只需检查

$$
\mathsf{AdmitAgg}(\mathsf{AggRLO}) = 1
$$

即可进入两轮确认，无需逐对象验证和集合对齐。

### 12.3 与 Practical ADKR 的本质差异

Aggregate RL-ADKR 与 Practical ADKR 的差别在于 agreement 对象层级被进一步前移并压缩：

- `Practical ADKR`：agreement on **finished dispersal objects**；
- **`Aggregate RL-ADKR`（本文）**：agreement on **single AggRLO**。

aggregation 从“Derive 阶段的密钥聚合”前移到了“LockAgg 阶段的份额聚合 + AggLock 证书化”，从而把非聚合逐对象设计中的多对象 agreement / recovery 主路径压缩为单对象主路径。
因而，Aggregate RL-ADKR 与 Practical ADKR 的差异不只是 agreement object 更轻，而是其顶层执行范式已从
`share-dispersal -> agree -> recast`
改写为
`LockAgg -> AgreeAgg -> RecoverAgg -> Derive`。

### 12.4 为什么 posterior corruption 风险是协议级而非实现级问题

这里的风险不是实现中“状态没擦干净”这么简单，而是协议执行结构本身带来的：  
对象先被锁定，之后才恢复，最后才进入接收方解密。只要接收方在这一阶段持有可回溯的 epoch 解密状态，历史 transport ciphertext 就天然暴露在 posterior corruption 风险下。

因此，这不是一个可交给实现层“自己注意擦除”的附属问题，而必须在协议模型中显式写入：

- epoch-specific decryption state；
- `Update + Erase` 的时序要求；
- posterior corruption 下的安全游戏。

从这个意义上说，forward secrecy 不是新的主对象语义，但它确实是 end-to-end security claim 的协议级组成部分。

### 12.5 AggLock 与 APVSS 的关系（新增）

AggLock 借鉴了 APVSS（Bacho-Loss, CCS 2023）“聚合优先于验证”的设计哲学，但构造上根本不同：

- APVSS 聚合公开 PVSS transcripts（数学层面的承诺线性组合）；
- AggLock 聚合 holder storage commitments（协议层面的 quorum 背书）；
- APVSS 安全目标是 aggregated unpredictability，AggLock 安全目标是 aggregate recoverability + binding；
- AggLock 不依赖 APVSS 作为黑盒原语。

### 12.6 Leader 驱动模式的讨论（新增）

LockAgg 的 Leader 驱动模式具有如下权衡：

- **优势**：$S$ 的确定和 AggLock 收集由单一节点协调，易于形成单对象快路径提议；
- **风险**：Leader 可能恶意排除诚实 holder 的签名，或延迟广播有效 AggRLO；
- **缓解**：
  1. 所有 holder 预广播 `LOCK-SHARE^agg`；
  2. `Fallback` 中可使用本地收集的签名组装 AggRLO；
  3. `AdmitAgg` 阻止 leader 提议缺少 recoverability backing 的伪聚合对象。

---

## Appendix A. Fallback 的单对象 MVBA 具体化

在 Aggregate RL-ADKR 中，Fallback 的 MVBA 输入从 descriptor 集合简化为单个 $\mathsf{AggRLO}$ digest。各节点不需要在进入 Fallback 的瞬间就拥有完全相同的局部视图；更准确的要求是：它们能够借助 `LockAgg` 中的预广播材料与 `CallHelp` 最终补齐到可规范化的候选池，因此 MVBA 只需对

$$
H(\mathsf{AggRLO})
$$

达成一致。

具体地，每个副本 $P_u$ 的本地输入为：

$$
v_u = H(\mathsf{AggRLO}_u)
$$

这里不应把 single-digest `Fallback` 理解成“诚实节点天然在任意时刻拥有相同局部视图”。更准确的思路是：诚实节点先借助 `CallHelp` 与 `LOCK-SHARE^agg` 预广播补齐到同一批可验证材料超集，再对 dealer 集合 $S$、签名者集合 $\widehat{S}$ 和 `AggRLO` 编码应用同一套公开确定性的 canonicalization 规则。由此，即使异步网络导致消息到达顺序不同，诚实节点最终仍会归一到同一个 canonical $\mathsf{AggRLO}^\star$ 及其 digest。

MVBA 的外部有效性谓词简化为：

$$
\mathsf{ValidateDigest}(d)=1
\iff
\text{对应的 AggRLO 可通过 }\mathsf{AdmitAgg}.
$$

因此，这里的 `Fallback` 前提不是“大家碰巧看到同样的前缀消息”，而是“大家最终补齐到同一可验证材料超集后，做出同样的规范化结果”。这一简化消除了旧式多对象 fallback 中复杂的 descriptor 编码、解码与裁剪流程，也使 `Fallback` 的说明更接近本文真正的 scientific point：

> **bad case 下 agreement on what 仍然是 recoverability-locked object，只是该对象已经被压缩成单个聚合 digest。**
