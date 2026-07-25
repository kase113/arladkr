# Adaptively Secure (Aggregatable) PVSS and Application to

# Distributed Randomness Beacons

Renas Bacho

Julian Loss

CISPA Helmholtz Center for Information Security,

Universität des Saarlandes

Saarbrücken,Germany

renas.bacho@cispa.de

## ABSTRACT

Publicly Verifiable Secret Sharing (PVSS) is a fundamental primi-tive that allows to share a secret S among n parties via a publicly verifiable transcript T. Existing (efficient) PVSS are only pproven secure against static adversaries whomust choose who to corrupt ahead of a protocol execution. As a result, any protocol (e.g.,a distributed randomness beacon) that builds on top of such a PVSS scheme inherits this limitation. To overcome this barrier, we revisit the security of PVSS under adaptive corruptions and show that, surprisingly, many protocols from the literature already achieve it in a meaningful way:

·We propose a new security definition for aggregatable PVSS, i.e.,schemes that allow to homomorphically combine mul-tiple transcripts into one compact aggregate transcript AT that shares the sum of their individual secrets. Our notion captures that if the secret shared by AT contains at least one contribution from an honestly generated transcript, it should not be predictable. We then prove that several exist-ing schemes satisfy this notion against adaptive corruptions in the algebraic group model.

·To motivate our new notion, we show that it implies the adaptive security of two recent random beacon protocols, SPURT (S&P '22) and OptRand (NDSS '23),who build on top of aggregatable PVSS schemes satisfying our notion of unpredictability. For a security parameter $λ$ , our result im-proves the communication complexity of the best known adaptively secure random beacon protocols to $O\left(λ^{2}\right)$ for synchronous networks with $t<n/2$ corruptions and par-tially synchronous networks with $t<n/$ 3 corruptions.

## CCS CCONCEPTS

**·Security and privacy → Public key (asymmetric) techniques;**

**·Theory of computation→Cryptographic protocols.**

## KEYWORDS

### Adaptive Security, Randomness Beacon, Aggregatable PVSS,Pairing-Based Cryptography

Permission to make digital or hard copies of all or part of this work for personal or classroom use is granted without fee provided that copies are not made or distributed for profit or commercial advantage and that copies bear this notice and the full citation on the first page. Copyrights for components of this work owned by others than the author(s) must be honored. Abstracting with credit is permitted. To copy otherwise, or republish, to post on servers or to redistribute tolists, requires prior specific permission and/or a fee. Request permissions from permissions@acm.org.

CCS '23, November 26-30,2023,Copenhagen,Denmark

©2023 Copyright held by the owner/author(s). Publication rights licensed toACM.

ACM ISBN 979-8-4007-0050-7/23/11...&#36;15.00

https://doi.org/10.1145/3576915.3623106

### CISPA Helmholtz Center for Information Security

Saarbrücken,Germany

lossjulian@gmail.com

#### ACM Reference Format:

Renas Bacho and Julian Loss. 2023. Adaptively Secure (Aggregatable) PVSS and Application to Distributed Randomness Beacons. In Proceeddings of the 2023 ACM SIGSAC Conference on Computer and Communications Security (CCS '23), November 26-30,2023, Copenhagen, Denmark. ACM, New York, NY,USA,14 pages. https://doi.org/10.1145/3576915.3623106

## 1 INTRODUCTION

In publicly verifiable secret sharing (PVSS) [33], a dealer D shares a secret S among $n$  parties $P_{1}\cdots P_{}$ by broadcasting a transcript T consisting of encrypted shares $\vec {E}=\left(E_{1},\cdots ,E_{n}\right)$ along with a proof $\pi$ .Any subset of $+1$ parties can pool their (decrypted) shares to reconstruct S, whereas t or fewer shares give no information about S. Using $\pi$ , anyone can efficiently determine whether the shares in $\vec {E}$ can be decrypted by the appropriate parties and indeed yield a sharing of S. This sets PVSS apart from the more common notion of verifiable secret sharing (VSS) [13],wvhich typically re-quires expensive communication among parties to ensure that the sharing is correct. As such, PVSS is an important building block in high-performance distribouted protocols that aim to minimize com-munication. Recent examples of such protocols include distributed randomness beacons [7,8,16,30] and distributed key generation (DKG) [2,21]. In these types of protocols, one typically assumes a malicious adversary who can corrupt some $t<n$ of the parties and make them behave arbitrarily. Most of the literature considers a static adversary who must commit to its corruptions before the protocol execution begins. However, a recent trend in this area has been toward considering a stronger adaptive adversary who can corrupt parties dynamically over the course of the protocol execution [1,4,8,15].

Unfortunately, protocol designers currently face the following limitation: existing (efficient) PVSS schemes are only proven se-cure with respect to static corruptions. Hence, adaptively secure protocols muist often resort to less efficient (but adaptively secure) alternatives such as VSS. To ameliorate this unsatisfactory state of affairs, we ask the following question: Are there efficient and adaptively secure PVSS protocols?

### 1.1 Our Contribution

In this work, we provide a nuanced answer to the above question. Our contributions are summarized in the following.

New Security Notions for Aggregatable PVSS. One particularly useful feature supported by some PVSS schemes is the ability to homomorphically aggregate sharings. In more detail, suppose that we are given $t+1$ PVSS transcripts $T_{1},\cdots T_{t+1}$  sharing respective

<!-- 1791 -->

<!-- CCS '23, November 26-30, 2023, Copenhagen,Denmark -->

<!-- Renas Bacho & Julian Loss -->

secrets $S_{1},\cdots ,S_{n}$ . Then aggregation allows to efficiently combine them into a compact transcript $T$  sharing $S=\sum _{i}S_{i}$ 

Aggregate PVSS has served as an indispensible building block in many higher-order constructions, most notably leader-based randomness beacons [7,8,16]. In such constructions, a designated leader L aggregates PVSS transcripts of different parties and com-mits them to consensus. To ensure that a malicious leader cannot propose a self-chosen value, T should prove that at least one honest party has contributed to the combined secret S. This, intuitively, ensures that S remains unpredictable. We observe that while several constructions from the literature already have this property, it is usually proven as part of a security proof for a broader system (see, e.g., the recent work of Bhat et al. [7]). Given the importance of aggregated PVSS as a modular building block, we believe that it is useful to capture the above unpredictability property in a new standalone security notion that we call aggregated unpredictability. While aggregatable unpredictability does not ensure full secrecy in the sense of previous indistinguishability-based notions [22],we show that it is sufficient to prove the security of recent distributed randomness beacons (see below).

We prove that several existing aggregatable PVSS protocols achieve our notion of unpredictability against adaptive corruptions in the algebraic group model (AGM). Here, we rely on techniques from the recent work of Bachoand Loss [4], who gave the first adap-tive security analysis of the threshold BLS signature [9,10].Our proof faces many additional challenges compared to theirs that we elaborate on in more detail in our technical overview. In particular, our proofs are complicated by the fact that the adversary obtains partial information about the secret S from the encrypted shares $\vec {E}$ .Therefore, it must be argued that it cannot use this information to cancel out honest parties' contribution to the aggregated secret S and render it predictable.

Applications to Randomness Beacons.We conclude by showing that our newly introduced notion of unpredictability for PVSS suf-fices to prove the security of two recent distributed randomness beacon protocols, SPURT [16] and OptRand [7]. Recall that the objective of a distributed random beacon protocol is for $n$ parties $P_{1},\cdots ,P_{}$ to agree on an a sequence of (computationally) uniformly random values $σ_{1}$ σ2,....The crucial property of a randomness beacon is that an adversary controlling some minority of $t<n$ par-ties can neither predict these values too early before they are output nor bias them. While both SPURT and OptRand achieve these prop-erties (under different network conditions and corruption regimes), both of them are proven secure only with respect to static adver-saries. We observe, however, that this limitation is directly inherited from the respective (statically secure) PVSS schemes that they are built on. Hence, it is plausible that their security can be improved to the same number of adaptive corruptions if the underlying PVSS provides such security guarantees. We confirm this intuition by introducing a weak unpredictability notion for randomness bea-cons and showing that both SPURT and OptRand achieve it against adaptive adversaries. In our new notion, a beacon produces values that remain unpredictable, yet possibly not uniformly distributed from the perspective of the adversary, up to a certain point before being output. However, since most beacon protocols assume the random oracle model [6] (ROM) anyway, it is trivial to transform an unpredictable beacon into one fully-fledged one. To do so,each party simply hashes each value that it outputs from the weak(i.e., unpredictable) beacon to obtain its final output. In this manner, one immediately obtains the first adaptively secure randomness bea-cons achieving $O\left(λn^{2}\right)$ communication complexity per computed value $λ$  denotes a security parameter) in the synchronous regime with $t<n/$ 2 corruptions and in the partially synchronous regime with $t<n/3$ corruptions. Previously, adaptively secure randomness beacons in these settings relied on (more expensive) VSS [8],thus incurring at least $O\left(λ^{3}\right)$ communication per output.

Our proofs also give a modular template which allows to infer unpredictability of leader-based beacon protocols in a black-box fashion from the unpredictability of the underlying PVSS scheme. Thus, we believe that our new security notions will be of use to the design of randomness beacons in the future.

### 1.2 Technical Overview

We proceed with a brief overview of our techniques. We remark that the discussion below is informal and as such does not depend on particular components of the PVSS we consider in this work. For example,non-interactive zero-knowledge proofs (NIZKs) can be implemented using Fiat-Shamir type proofs of discrete logarithm equality,pairing-based proofs, or code-based proofs, but we omit these distinctions here as they are not relevant for this high-level overview.

A Short Recap of PVSS. To begin, we describe the common high-level idea behind many efficient PVSS schemes in the literature. Let again $g$  and $h$  be known generators of some cyclic group $G$ of prime order $d$ . In the sharing phase, the dealer $D$  picks a value $α\in \mathbb {Z}_{p}$ and computes a $(t,n)$ -sharing of a group element $S:=h^{α}\text {by}$ interpolating a random polynomial P over $\mathbb {Z}_{p}$ of degree t through points $α_{i}=:(i)$ and computing the shares $h^{α_{i}}$ for all $i=0,\cdots ,n.$ In addition, $D$  also computes the commitments $g^{α_{0}}\cdots g^{α_{}}$ .It then computes ciphertexts $E_{i}:=\text {Ec}\left(pk_{i}h^{α_{i}}\right)$ for all $i$  and shares the vector $\vec {E}$ of encrypted shares together with the proof $\pi$  consisting of the values $g^{α_{0}},\cdots ,g^{α_{n}}$ and NIZKs proving that $\vec {E}$ is an encryption of values $h^{α_{i}}$  . This can be achieved by using the values $^{α_{0}},\cdots ,^{α_{}}$ Using the NIZKs and these values, anyone is convinced that E provides a correct sharing of S. To reconstruct, party $i$  decrypts its share via $h^{α_{}}=\text {Dc}\left(k_{}\vec {E}_{}\right)$ and sends this value to all parties. UJpon receiving $t+1$ shares $h^{α_{k_{1}}},\cdots ,h^{α_{k_{t+1}}}$ ,the secret can be recovered via Lagrange interpolation in the exponent of $h$ .

A Common Proof Strategy. The main difficulty in the context of adaptive corruptions that our simulator Sim has to overcome is to balance two seemingly mutually exclusive tasks. First, Sim has to simulate the security experiment without knowing the values $sk_{i}$ and the secret shares of all of the honest parties. If,instead,it knew all these values, the adversary's final output would be useless to Sim with regards to breaking the hardness assumption underlying the security of the PVSS scheme. Also, it is clear that guessing the sub-set of eventually corrupted parties is out of the question, as it would lead to a security loss exponential in t and $n$ . On the other hand, Sim must be able to provide the values $sk_{i}$  along with the share of party i, upon i becoming adaptively corrupted during simulation. We stress that this issue does not occur when corruptions are static, as Sim knows all the corrupted parties upfront. This allows Sim to inter-polate a properly distributed polynomial through a secret S as well as the corrupted parties' shares, without actually knowing them. This simulation strategy is well-known from the the literature on distributed key generation protocols [11,19,20,23].Unfortunately, it is not applicable to a setting with adaptive corruptions, which, instead, requires different arguments. As such, schemes commonly resort to heavy machinery such as non-committing encryption [23] to attain adaptive security.

<!-- 1792 -->

<!-- Adaptively Secure (Aggregatable) PVSS and Randomness Beacons -->

<!-- CCS'23, November 26-30,2023,Copenhagen,Denmark -->

Our techniques for addressing this problem are inspired by the recent work of Bacho and Loss [4] who proved adaptive security of the (symmetric) threshold BLS signature scheme in the AGM under the OMDL assumption. Loosely speaking, the OMDL as-sumption of degree $k$  asserts that it is difficult to return the discrete logarithms $z_{1},\cdots ,z_{k}$ of $k$  discrete logarithm challenges $g^{z_{1}},\cdots ,g^{z_{k}}$ when given (k - 1)-time access to a (perfect) discrete logarithm oracle $\mathrm {DL}_{g}.$ In more detail, on input a group element $ξ\in \mathbb {G}$ $\mathrm {DL}_{g}$ returns its discrete logarithm $z\in \mathbb {Z}_{p}$ to base $g$  (where $p$ is the prime order of G). The key insight of their work is the construction of a simulator Sim which reduces from this assumption and hence can leverage the oracle $\mathrm {DL}_{g}$ to simulate adaptive corruptions. Followup works have leveraged similar techniques to obtain adaptively secure asynchronous DKG [1] and threshold Schnorr signatures [15].

Challenges in the Context of PVSS. As explained above, aggregat-able PVSS are typically composed of three main components: an encryption scheme, a commitment scheme, and a NIZK. This com-bination opens up many different vectors of attack that add unique challenges to our security proofs when compared to structurally simpler pprimitives such as signatures and VSS. Intuitively, there are three ways in which an attacker can learn the secret S,each corresponding to one of the three aforementioned components: (1) it can break security of the encryption scheme Enc to learn a $(+1$ st share $h^{α_{i}},$ (2) it can find the discrete logarithm $a$  of h to base $g$  and compute $h^{α_{0}}$ from the commitment $\left(g^{α_{0}}\right)$ via $\left(g^{\alpha_{0}}\right)^{a},$ (3) it can pick up to t transcripts $T_{1},\cdots ,T_{}$ dependent on a single honest transcript $T^{*}$  in such a way that their aggregate becomes entirely independent of $T^{*}$ . In particular, it could choose them in such a way that $T^{*\prime }\mathrm {s}$ contribution is cancelled out entirely, in which case the secret shared by the aggregate transcript AT is no longer unpredictable. Intuitively, this lane of attack should be prevented by the NIZK component of the scheme, as it forces the attacker to know the discrete logarithms of the secrets.

Following this high-level template, our proof broadly distin-guishes multiple cases by providing appropriate simulations of the unpredictability experiment to the adversary in each1 of which the OMDL instance is embedded into different components of the scheme. The main difficulty of our proof is to balance these sim-ulation strategies without the adversary being able to tell them apart.

Additional Issutes with Asymmetric Groups. While we could prove all of our claims for symmetric variants of the pairing-based PVSS schemes we consider directly under the OMDL assumption,we insist on proving these schemes directly in their original and more performant versions over asymmetric pairing groups. Because of this, the OMDL assumption unfortunately turns out to be insuffi-cient for our purposes. To see the issue, note that PVSS schemes over asymmetric pairing groups typically share the secret in both source groups $\mathbb {G}_{1}$ and $\mathbb {G}_{2}$ .As a consequence, our reduction would have to supply the dliscrete logarithm challenges in both groups as $g_{1}^{x_{1}},\cdots ,g_{1}^{x_{k}},g_{2}^{x_{1}},\cdots ,g_{2}^{x_{k}}$ ,where $g_{1}$  and $g_{2}$  are the groups' re-spetive generatrs. To remedy thnis issue, we introduce a natural extension of OMDL to asymmetric pairing groups, in which the adversary obtains all of these generators and can query the oracle $\mathrm {DL}_{g_{1}}$ for elements in $\mathbb {G}_{1}$ . We refer to this assumption as $Co-OMDL$ and provide a rigorous proof of its hardness in the generic group model (GGM). Our proof followsalong the lines of Bauer et al.[5], but requires a new mathematical lemma due to the higher degree of polynomials in the exponents of target group elements.

We believe that, similar to established asymmetric hardness as-sumptions such as SXDH [3] or Co-CDH [10], Co-OMDL has many applications to schemnes based on asymmetric pairing groups and, as such, is of independent interest. As an example, we refer again to the work of Bachoand Loss who prove adaptive security for the (symmetric) threshold BLS from OMDL. As we explain in more detail in the full version, their proof faces similar issues in the asymmetric setting that wouldI also require Co-OMDL.

### 1.3 Related Work and Discussion

We give an overview of the literature on PVSS and how our work fits in. We also briefly discuss some limitations of our work.

Publicly Verifiable Secret Sharing. The idea of publiclyverifiable secret sharing (PVSS) was first formally stated in the seminal work of Stadler [33], although Stadler notes that it already was implicitly conceived in the work of Chor et al.[14].Over the years,many improved schemes have been proposed. The common idea behind many of these schemes is the following. The dealer samples a poly-nomial $\in \mathbb {Z}_{p}[X]$ of degree t uniformly at random and commits to it via Feldman commitments [17] (i.e. it commits to the $t+1$ coefficients of $f$ ). The dealer also provides encryptions of shares to an $(t,n)$  -Shamir secret sharing of $f$ . The Feldman commitments are used by non-dealer parties to compute commitments to the shares $f(i)$  that are proven via zero-knowledge proofs to corre-spond to the encrypted shares. Stadler realized these proofs via the Fiat-Shamir heuristics in the random oracle model. Security of the scheme is reduced from the Decisional Diffie-Hellman (DDH) assumption. Schoenmakers [31] gives a more efficient variant of Stadler's construction, in which the security of the scheme is re-duced from the computational Diffie-Hellman (CDH) assumption. Ruiz and Villar [29] and Jhanwar et al. [25] gave standard model constructions which replace random oracle model proofs through checks based on Paillier encryption [28]. The security of both these schemes is reduced from the Decisional Composite Residuosity (DCR) assumption. Heidarvand and Villar [22] and Jhanwar [24] proposed alternative pairing-based PVSS constructions in the plain model with security under the Decisional Bilinear Square (DBS) assumption and the multi-sequence of exponents Diffie-Hellman (MSE-DDH) assumption. A significant drawback of these schemes is that parties must each compute $O(nt)$ ) exponentiations to verify the validity of the encrypted shares. Since one is mostly interested in the case $t\in O(n)$ , this results in high computation cost of $O(^{2})$ 

This barrier in quadratic computation cost was first overcome by SCRAPE, an elegant scheme proposed by Cascudo and David [12]. The idea of their scheme is the following. Instead of committing to the coefficients of $f$ , the dealer directly commits to the polynomial evaluations $f(i)$  by publishing $g^{f(i)}$ .With the help of linear error correcting codes (and their dual codes), parties can verify with high probability that the commitments published by the dealer actually correspond to a polynomial of degree t. In this manner, the total computation cost reduces to $O(n)$  exponentiations. The authors provide two construction based on the underlying model. In the random oracle model, the proofs are realized via NIZKs and security of the scheme is reduced from the DDH assumption. In the standard model, the authors use pairings to realize these proofs and security of the scheme is reduced from the Decisional Bilinear Square (DBS) assumption. This construction has inspired several followups, which we elaborate on below.

<!-- 1793 -->

<!-- CCS '23, November 26-30, 2023, Copenhagen, Denmark -->

<!-- Renas Bacho & Julian Loss -->

In the context of randomness beacons, Das et al. [16] propose SPURT, which gives a variant of SCRAPE that relies on the stan-dard Decisional Bilinear Diffie-Hellman (DBDH) assumption and achieves similar performance to SCRAPE. The work of Gurkan et al. [21] also gives a variant of the pairing-based SCRAPE and uses it as a building block to design a DKG protocol. To support efficient aggregation of PVSS transcripts,their construction relies on sig-natures of knowledge and is proven secure under the Symmetric External Diffie-Hellman (SXDH) assumption for Type 3 pairings.

Security of Publicly Verifiable Secret Sharing. The literature on PVSS has considered two main security notions, both of which capture the notion of indistinguishability of secrets.These notions were first formally defined in [22]. In the weaker notion of IND1-secrecy, the adversary cannot distinguish between the sharings of two secrets $S_{1},S_{2}$ chosen uniformly at random by the challenger.In the stronger notion of IND2-secrecy, the adversary has the additional power to choose the two secrets $S_{1},S_{2}$ by itself.As already pointed out by Heidarvand and Villar, there is a generic transformation from an IND1-secure PVSS scheme to an IND2-secure PVSS scheme. Omitting some details, the transform uses an IND1-secret PVSS to share a uniform key K which in turn is used to encrypt a secret S.

In the following, we compare these notions to our notion of unpredictability. Intuitively, IND-secrecy says that an adversary cannot learn any information about the secret S shared in the dis-tribution protocol. Therefore, proofs achieving this security notion have to provide simulator Sim that on input a uniformly random S simulates protocol execution in which the secret S is shared. As discussed above, it is unknown how to instantiate Sim efficiently for adaptive corruption without modifying the scheme. Our no-tion of (aggregated) unpredictability obviates the need for this type of simulation. This is because unpredictability allows the adver-sary to obtain partialinformation about the secret S, with the only condition thatit cannot fully recover the secret.

### 1.4 Organization of this Article

In Chapter 2, we define preliminaries and our model. In Chapter 3, we formalize the notion of an aggregatable PVSS scheme and in-troduce a new security notion for it. Following this, we show that the PVSS schemes used in OptRand and SPURT are secure under this notion. In Chapter 4, we infer the adaptive security of the randomness beacons OptRand and SPURT. In the full version of this paper, we provide a warm-up chapter, in which we introduce the syntax and a new security notion for standard PVSS schemes, prove that Schoenmakers' PVSS is secure under it, and infer the adaptive security of the randomness beacon GRandPiper [8]. There we also provide a detailed discussion on the literature of random-ness beacons. Finally, we provide in the full version a proof for the hardness of our newly introduced Co-OMDL assumption in the generic group model.

## 2 PRELIMINARIES AND MODEL

Throughout the paper, we consider a complete network $P$  of n par-ties connected by pairwise authenticated channels, i.e. the receiver of a message is aware of the sender's identity. We assume known party identifiers,w.l.o.g from $P_{1}$ to $P_{n}$ . An unknown subset of these parties is faulty and controlled by an adversary.

General Notation. We denote the set of integers by Z, the group of integers modulo $p$  by $\mathbb {Z}_{p}=\mathbb {Z}/p\mathbb {Z}$ and its multiplicative unit group by $\mathbb {Z}_{}^{*}$ We denote the set of integers from $a$  to $b$  by $[a,b]$ ];if $a=1,$ we write [b],and if $a=0$ we write $[b]$ .For an element $x$ in a set S, we write $x\leftarrow $ to indicate that $x$  was sampled from $S$ uniformly at random. We consider the standard notion of proba-bilistic polynomial time algorithms. As such,all of our algorithms are randomized (unless stated otherwise) and are written in upper-case serif-free letters.We write $x\leftarrow \mathrm {\;A}\left(x_{1},\cdots ,x_{}\right)$ to denote that algorithm A is run on inputs $\left(x_{1},\cdots ,x_{n}\right)$ and produces ooutput $x$ .We write $x\in \mathrm {\;}\left(x_{1},\cdots ,x_{}\right)$ to denote that $x$  is a possible output of a (randomized) algorithm A on input $\left(_{1},\cdots ,_{n}\right)$ .If A has oracle access to some algorithm B during its execution, wve write $A^{}$ .Fur-thermore,we write $\mathrm {G}^{\mathrm {A}}$ to denote the output of the experiment G involving algorithm A. We define $LC$  to be the Reed-Solomon code over $\mathbb {Z}_{p}$ of length $n$ and dimension $t+1$ of the following form

$$\mathcal {LC}:=\left\{(f(1),\cdots ,f(n))|f(X)\in \mathbb {Z}_{p}[X],\text {deg}(f)\leq t\right\},$$

where $f(X)$ ranges over all polynomials in $\mathbb {Z}_{p}[X]$ of degree at most t.Its dual code $\mathcal {LC}^{\bot }$ is defined as

$\mathcal {LC}^{\bot }:=\left\{\left(vartheta_{1}r(1),\cdots ,vartheta_{n}r(n)\right)|r(X)\in \mathbb {Z}_{p}[X],\right.$ $|,\text {deg}(r)\leq n-t\}$ 

with the coefficients $vartheta_{i}:=\prod _{j\in [n]\backslash \{i\}}1/(i-j)$ .Equivalently, $\mathcal {LC}^{\bot }$ is the vector space consisting of all $c^{\bot }\in \mathbb {Z}_{p}^{n}$ that are orthogonal to all of $LC$ ,i.e. $\left\langle c^{\bot },c\right\rangle =0$ for all $c\in \mathcal {LC}$ where $<·,·>$ is the standard inner product operation on $\mathbb {Z}_{p}^{n}$ 

Setup Assumptions and Adversary Model. We assume that par-ties have established a public key infrastructure (PKI) via a public bulletin board. This means that every party $P_{i}$ is associated with a public-secret key pair $\left(pk_{i},\right.$ ski) of a public key encryption scheme, where $pk_{i}$  is known to all parties $\{\}^{1}\mathrm {We}$  assume an adversary who can take full control of up to $t<n$ parties and may cause them to deviate from the protocol arbitrarily. We refer to the correct parties as honest and to the faulty parties as corrupt. The adversary is adaptive, i.e. it chooses the faulty parties at any time during the execution of the protocol. We do not assume that the keys are computed in a trusted manner. Instead,we assume only that each party generates its keys locally(faulty parties may choose their keys arbitrarily) and then makes its public keys known to all other

1In some specific cases, we will also require that parties share private and public keys for a digital signature scheme.

<!-- 1794 -->

<!-- Adaptively Secure (Aggregatable) PVSS and Randomness Beacons -->

<!-- CCS '23, November 26-30, 2023, Copenhagen, Denmark -->

parties by using the public bulletin board. However, the adversary is assumed to be rushing andI can corrupt some subset C [n] of parties so as to replace their keys with keys of its own choice, before they get posted to the bulletin board.

Random Oracle Model. We assume the random oracle model (ROM) [6]. In this model, a hash function H is treated as an ideal-ized random function. Concretely, H is modeled as an oracle with the following properties. The oracle internally keeps a list H for bookkeeping purposes. At the beginning, all entries of H are set to 1. On input $m$  from the domain of H, the oraclefirstchecks whether $H[m]\neq \bot$ . If so, it returns $H[m]$ . Otherwise, it sets $H[m]$ to a uniformly random value in the codomain of H and then returns $H[m]$ .We write $q_{h}$  to denote the maximum number of allowed hash queries, i.e. the number of times the adversary may query the oracle H.

Cryptographic Groups. Let $λ$  be the security parameter. Through-out, we assume that global system parameters $par$  are fixed and known to all parties. Depending on the setting, we either assume that $\text {pa}=(\mathbb {G}hp)$ defines a cyclic group $G$  of prime order $p$  with generators $g,$ h or that $\text {p}=\left(\mathbb {G}_{1},\mathbb {G}_{2},\mathbb {G}_{T},\right.$ p,g,g,h,e) defines a triple of groups $\mathbb {G}_{1},\mathbb {G}_{2},\mathbb {G}_{T}$ of prime order $p$  such that $g,\hat {g}\in \mathbb {G}_{1}$ $,\in \mathbb {G}_{2}$ and e: $\mathbb {G}_{1}x\mathbb {G}_{2}\rightarrow \mathbb {G}_{T}$ is a bilinear asymmetric pairing of Type 3. That is, there is no efficiently computable isomomorphism from $\mathbb {G}_{1}$ to $\mathbb {G}_{2}$  and vice versa. For concrete choices,we will assume $λ=128$ and that $\mathbb {G}_{1},$ $\mathbb {G}_{2}$ are instantiated with 256-bit elliptic curves.

Algebraic Group Model. In the algebraic group model (AGM) [18], all algorithms are treated as algebraic. Intuitively,whenever an algorithm outputs a group element, it must also output a represen-tation of that element relative to all of the inputs the alggorithm has received up to that point. This captures the intuition that any reasonable algorithm should know how it computes its outputs from its inputs. In terms of assumptions, the algebraic group model lies in between the generic group model [32] and the plain model.

Definition 2.1 (Algebraic Algorithm). An algorithm A is called algebraic (over group G) if for all group elements $ζ\in \mathbb {G}$ that A outputs, it additionally outputs a vector $\vec {z}=\left(z_{0},\cdots ,z_{m}\right)$ of inte-gers such that $ζ=\prod _{i}g_{i}^{z_{i}}$ where $\left(g_{0}\cdots g_{m}\right)$ is the list of group elements A has received so far.

## 3 ADAPTIVELY SECURE APVSS SCHEMES

In this section, we provide a formal definition for aggregatable PVSS $(APVSS$ ). Additionally, we propose our new security notion1 and prove several schemes from the literature secure with respect to it.

An APVSS scheme allows a dealer to share a secret S via ADist via a transcript $T=(\vec {E},\pi )$  $多$ contains a vector of encrypted shares of $S$ ,each to a different public key; $pk_{i}$ such that any $+1$ decryptions uniquely reconstruct S. T is publicly verifiable using algorithm Ver. The aggregation routine Agg allows to homomorphically combine the secrets corresponding to transcripts $T_{1},\cdots ,T_{k}$ into an aggre-gate transcript AT. To be useful as a building block,we endow an aggregatable PVSS scheme with an additional verification routine AVer for aggregated transcripts. Intuitively, AVer can be used to detect whether an aggretated transcript AT has at least one contri-bution from an honest party. In order for this to be well-defined, we also define the notion of ownership of a transcript T. This is captured via the auxiliary algorithm Ownld that can efficiently find the creator of T. In concrete schemes, this is usually implemented by parties holding signing keys in addition to their encryption keys and digitally signing their transcripts. Rather than unnecessarily convoluting our syntax, we simply require that the distribution algorithm ADist take in a party's secret key as part of its input. (This would, for example, allow a party holding a signing key as part of its overall secret key to sign its transcript upon distributing it.) We remark that in our definitions, we syntactically distinguish between transcripts and aggregated transcripts.

Definition 3.1 (Aggregatable PVSS Scheme). Let $\hat {\mathbb {G}}$  be a cyclic group of prime order p specified by par. A $(t,n)-threshold$ ag-gregatable PVSS (APVSS) scheme over $\hat {\mathbb {G}}$  is a tuple of algorithms $\text {APVSS}=(\text {Keys,Enc,Dec,ADist,Own}$ ld, Ver, AVer, Rec,Agg) with the followving properties:

·Keys: The randomized key generation algorithm takes as in-put system parameters par and an identity index $i\in [n]$ . It outputs a public key $pk_{i}$  and a secret key $sk_{i}$ .

·Enc: The randomized encryption algorithm takes as input a public key $pk_{i}$  and a message $m$ . It outputs a ciphertext c.

·Dec: The deterministic decryption algorithm takes as input a secret key $sk_{i}$  and a ciphertext c. It outputs a message $m$ (optionally with a proof of correct decryption). We require that for all messages $m$ ,

$$\text {Pr}\left[\text {Dec}_{sk_{i}}\left(\text {Enc}_{pk_{i}}(m)\right)=m\right]=1.$$

·ADist: The randomized aggregatable secret sharing algorithm takes as input a secret key $sk_{i}$  and public keys $pk_{1},\cdots ,pk_{n}$ It outputs a vector of encrypted shares $\vec {E}=\left(\text {En}_{pk_{1}}\left(S_{1}\right),\cdots ,\right.$ $\left.\text {Enc}_{pk_{n}}\left(S_{n}\right)\right)$ and a proof $\pi$ ,where $S_{1},\cdots ,S_{n}$ are shares of a secret $S\in \hat {\mathbb {G}}.$ We referto $T:=(\vec {E},\pi )$ as a $PVSS$ transcript.

Ver: The deterministic verification algorithm takes as input public keys $pk_{1},\cdots ,pk_{n},$ and a PVSS transcript $T=(\vec {E},\pi ).$ It outputs 1 (accept) or 0 (reject). In the first case we call the transcript T valid (relative to $\left.pk_{},\cdots ,pk_{}\right);$ otherwise we call it invalid.

·Ownld: The deterministic owner identifier algorithm takes as input a PVSS transcript $T=(\vec {E},\pi )$ and a public key $pk_{i}$ It outputs 1 (accept) or 0 (reject). In the first case,we refer to 1 $P_{i}$ as the owner o $\text {of}T{}^{2}$ 

· $Agg$ : The deterministic aggregation algorithm takes as input $t+1$  PVSS transcripts $\left(\vec {E}_{1},\pi _{1}\right),\cdots ,\left(\vec {E}_{t+1},\pi _{t+1}\right)$ with pairwise distinct owners. It outputs an aggregated PVSS transcript $AT:=(\vec {E},\pi )$ 

·AVer: The deterministic aggregation verification algorithm takes as input public keys $pk_{1},\cdots ,pk_{n},$ and an aggregated PVSS transcript $AT=(\vec {E},\pi )$ . It outputs 1 (accept) or 0 (reject). In the first case we call the aggregated transcript AT valid; otherwise we call it invalid.

·Rec:The deterministic reconstruction algorithm takes as input $t+1$ shares $S_{1},\cdots ,S_{t+1}$ . It outputs a reconstructed secret $S\in \hat {\mathbb {G}}.$ In case Rec gets more than $t+1$ shares as input, it takes the first lexicographical $+1.$ 

2We remark that Ownld could return 1 on an invalid transcript.

<!-- 1795 -->

<!-- CCS '23, November 26-30, 2023,Copenhagen,Denmark -->

<!-- Renas Bacho & Julian Loss -->

For an aggregatable PVSS scheme APVSS = (Keys, Enc, Dec, ADist, Ownld, Ver, AVer, Rec, Agg) as defined above, we define pub-lic verifiability of transcripts and aggregated transcripts as well as correctness as follows:

·Correctness (of Aggregatable PVSS). We say that APVSS is correct if for all $\left(pk_{1},k_{1}\right),\cdots ,\left(pk_{n},k_{n}\right)\in \text {K}(\text {par}$ and all $i\in [n]$ 

$$\text {Pr}\left[\text {Ver}\left(\left\{pk_{j}\right\}_{j\in [n]},T\right)=1\wedge \text {Ownld}\left(pk_{i},T\right)=1\right]=1,$$

where the probability is taken over all $T\leftarrow \text {ADit}$ $\left(sk_{i},\left\{pk_{j}\right\}_{j\in [n]}\right)$ ·Public Verifiability (of Transcripts). We say that APVSS is ub-licly verifiable if for all $\left(pk_{1},k_{1}\right),\cdots ,\left(pk_{n},k_{n}\right)\in \text {K}(\text {pa}$ and all $(\vec {E},\pi )\text {s.t.}\text {V}\left(\left\{pk_{j}\right\}_{j\in [n]},(\vec {E},\pi )\right)=1,$ ,there exists a unique $S\in \hat {\mathbb {G}}$ s.t.

$$\text {Rec}\left(\left\{\text {Dec}_{sk_{i}}\left(\vec {E}_{i}\right)\right\}_{i\in \mathcal {I}}\right)=S\quad \forall \mathcal {I}\subset [n],|\mathcal {I}|=t+1$$

·Public Verifiability (of Aggregated Transcripts). We say that APVSS is publicly verifiable if for all $\left(pk_{1},k_{1}\right),\cdots ,\left(pk_{n},k_{n}\right)$ $EKeys(par)$  and all aggregated transcripts $AT=(\vec {E},\pi )$ s.t. $\text {AVer}\left(\left\{pk_{j}\right\}_{j\in [n]},(\vec {E},\pi )\right)=1$ , there existsa unique $S\in \hat {\mathbb {G}}$ s.t.

$$\text {Rec}\left(\left\{\text {Dec}_{sk_{i}}\left(\vec {E}_{i}\right)\right\}_{i\in \mathcal {I}}\right)=S\quad \forall \mathcal {I}\subset [n],|\mathcal {I}|=t+1.$$

We say that an APVSS scheme is publicly verifiable if both its transcripts and aggregated transcripts are publicly verifiable.We would also like to guarantee that the secret reconstructed from an aggregated transcript $AT=\text {Agg}\left(T_{1},\cdots ,T_{+1}\right)$ corresponds to the sum of the secrets $S_{i}$  that can be reconstructed from $T_{i}$ . This is captured in the following definition.

Definition 3.2 (Correctness of Aggregation). We say that an ag-gregatable and publicly verifiable $(t,n)$  -threshold APVSS scheme $\text {APVSS}=(\text {Keys,Enc,Dec,ADist,O}$ wnld, Ver, AVer, Rec, Agg) over $\hat {\mathbb {G}}$  is correctly aggregatable if for all keys $\left(pk_{1},k_{1}\right),\cdots ,\left(pk_{n},k_{n}\right)\in$ $Keys(par)$  and all PVSS transcripts $T_{1}=\left(\vec {E}_{1},\pi _{1}\right),\cdots ,T_{t+1}=\left(\vec {E}_{t+1},\right.$ $\left.\pi _{t+1}\right)$ with pairwise distinct owners, the following is true. If for all $i\in [+1]\text {V}\left(\left\{pk_{j}\right\}_{j\in [n]}T_{i}\right)=1$ ,then for all $\mathcal {I}\subset [n]$ , $|\mathcal {I}|=+1$ the aggregated transcript $AT=\left(\vec {E}^{\prime },\pi ^{\prime }\right):=\text {Agg}\left(T_{1},\cdots ,T_{t+1}\right)$ satis-fies

$$\text {Rec}\left(\left\{\text {Dec}_{sk_{i}}\left(\vec {E}_{i}^{\prime }\right)\right\}_{i\in \mathcal {I}}\right)=\prod _{j\in [t+1]}\text {Rec}\left(\left\{\text {Dec}_{sk_{i}}\left(\vec {E}_{j,i}\right)\right\}_{i\in \mathcal {I}}\right),$$

where we write $\vec {E}_{j}=\left(\vec {E}_{j,1},\cdots ,\vec {E}_{j,n}\right).$ 

### 3.1 New Security Notions for APVSS

We introduce a new security notion for APVSS schemes called aggregated unpredictaability. This is a kind of non-malleability kind property specifically for aggregatable PVSS schemes. It prohibits an adversary controlling t parties from learning the secret of an aggregated transcript with at least one honest contribution, even if the adversary is allowed to contribute itself to the aggregate. This models an active adversary who can contribute to the final secret itself. In the following, we define this notion formally.

Definition 3.3 (Aggregated Unpredictability of Aggregatable PVSS Scheme). Let APVSS = (Keys, Enc, Dec, ADist, Ownld, Ver, AVer, Rec, $Agg)$  be a publicly verifiable aggregatable (t,n)-PVSS scheme over G.For an algorithm A, define the aggregated unpredictability exper-iment $\text {AggP}_{\mathrm {APVSS}t}^{\mathrm {A}}$ as follows:

·Offline Phase. For all $i\in [$ n], run Keys on input $(par,i)$ to generate keys $\left(pk_{i},sk_{i}\right)$ $\leftarrow$ Keys(par,i). On input par and $\left\{pk_{i}\right\}_{i\in [n]}$ Areturns an index set $C\subset$ [n] of initially corrupted parties along with updated public keys $\left\{\hat {pk}_{j}\right\}_{j\in \mathcal {C}}.$ Set $pk_{j}:=\hat {pk}_{j}$ for $all$ $j\in C$ 

·Corruption Queries. At any point of the experiment,A may submit an index $i\in [n]\backslash C$ . In this case, return the secret key $sk_{i}$ i and update $C:=C\cup \{\}$ . $IfA$  is static, it submits an index set $C^{\prime }$ $C$ $[n]$ $C$ at the beginning of the experiment. Return the secret keys $\left\{sk_{i}\right\}_{i\in C^{\prime }}$  and update $C:=C^{\prime }\cup C$ 

·Random Oracle Queries. At any point of the experiment,A gets access to an oracle that answers queries of the following type:When A submits a query $m$ , check if $H[m]=\bot$ .If so, set H[m] $\leftarrow \mathbb {Z}_{p}^{*}$  and return $H[m]$ . Otherwise, return $H[m]$  .

·Transcript Queries. At any point of the experiment,A gets access to an oracle that answers queries of the following type: When A submits a request $(givePVSS,i)$ ) for an $i\in [n]\backslash C$ ,do the following.On behalf of dealer $P_{i},$ ,run ADist on input $sk_{i}$ and $pk_{1},\cdots ,pk_{n}$ Return the output transcript $T=(\vec {E},\pi )$ 

·Output Determination. When A outputs an aggregated tran-script $T^{\prime }=\left(\vec {E}^{\prime },\pi ^{\prime }\right)$ and an element $S^{*}\in \hat {\mathbb {G}},$ do:

- Return 1 $\text {if}|C|\leq t,\text {AVer}\left(\left\{pk_{i}\right\}_{i\in []},\left(\vec {E}^{\prime },\pi ^{\prime }\right)\right)=1,$ ,and $S^{*}=\text {Rec}\left(\left\{\text {Dec}_{sk_{i}}\left(\vec {E}_{i}^{\prime }\right)\right\}_{i\in [t+1]}\right)$ 

- Return 0 otherwise.

We say that APVSS is $\left(\varepsilon ,T,t,q_{k},q_{h}\right)$ -aggregated unpredictable if for all algorithms A that run in time at most $T$ , make at most $q_{k}$ transcript queries, and make at most $q_{h}$ random oracle queries, $\text {Pr}\left[\text {AggPred}_{\mathrm {APVSS},t}^{\mathrm {A}}=1\right]\leq \varepsilon$ .Conversely,we say thatA $\left(\varepsilon ,T,t,q_{k}\right.$ , $q_{h}$ )-breaks aggregated unpredictability of APVSS if it runs in time at most $T$ , makes at most $q_{k}$  transcript queries, makes at most $q_{h}$ random oracle queries, and $\text {Pr}\left[\text {AggPrd}_{\mathrm {APVSS}}^{\mathrm {A}}=1\right]>\varepsilon .$ 

### 3.2 Security Analysis of APVSS in the AGM, OptRand's & SPURT's Scheme

We analyze the (adaptive) security of two recent APVSS schemes from the literature that are designed upon Type 3 asymmetric pair-ings, OptRand's and SPURT's APVSS. As already explained in the introduction, the standard OMDL assumption is not sufficient any-more for this setting. The reason is that the secret is shared in both source groups, which makes it impossible for the simulation to work when relying on OMDL. We elaborate on this in more detail in the full version. We observe that this issue can be resolved by relying on an extended version of OMDL, which we call the $CO$ one-more discrete logarithm (COMDL) assumption. In the following, let $\mathbb {G}_{1}$ and $\mathbb {G}_{2}$  e two cyclic groups of prime order $p$  with respective generators $g\in \mathbb {G}_{1}$ and $\in \mathbb {G}_{2}.$ We denote by $\mathrm {DL}_{g}$ an oracle that on input $ξ:=g^{z}\in \mathbb {G}_{1}$ returns the discrete logarithm $Z$  of $ξ$  to base $g$ .

Definition 3.4 $Co$  One-More Discrete Logarithm Problem). For an algorithm A and $\in \mathbb {N},$  define the co one-more discrete logarithm experiment $n-\mathrm {COMDL}^{\mathrm {A}}$  for $\mathbb {G}_{1}$ and $\mathbb {G}_{2}$ as follows:

·Offline Phase. Sample $\left(z_{1},\cdots ,z_{n}\right)\leftarrow \mathbb {Z}_{p}^{n}$ uniformly at ran-dom and set $ξ_{i}:=\left(g^{z_{i}},h^{z_{i}}\right)\in \mathbb {G}_{1}x\mathbb {G}_{2}$ for all $i\in [n].$ 

<!-- 1796 -->

<!-- Adaptively Secure (Aggregatable) PVSS and Randomness Beacons -->

<!-- CCS'23, November 26-30, 2023, Copenhhagen,Denmark -->

<table border="1" ><tr>
<td>Let $e:$ $\mathbb {G}_{1}x\mathbb {G}_{2}\rightarrow \mathbb {G}_{T}$be an asymmetric pairing and independent generators g $,\hat {}\in \mathbb {G}_{1}$ and $h\in \mathbb {G}_{2}$.Let $\left(pk_{i},sk_{i}\right)$be the key pair of $pk_{i}=h^{k_{i}}$.The dealer $P_{L}$with key pair $\left(pk_{L},sk_{L}\right)$wants to share secret e(g,ha)for an $α\leftarrow \mathbb {Z}_{p}^{*}.$The ADist algorithm party $P_{i}$with<br>$pk_{1},\cdots ,pk_{n}$It outputs the transcript $T_{L}:=\left\{C_{i},Y_{i},\pi \right\}_{i\in [n]}$defined as follows.In the following, takes as input $sk_{L}$ and public keys<br>$\langle m\rangle _{i}:=(m,σ)$denotes the pair consisting of message $m$ and a signature $σ$ on $m$ from party $P_{i}$(1) Choose a polynomial $f(X=α+α_{1}X+\cdots +α_{t}X^{t}\in \mathbb {Z}_{p}[X]$of degree t uniformly at random.<br>(2) Publish commitments $C_{i}=g^{f(i}\in \mathbb {G}_{1}$for $i\in [n]$. Also publish encrypted shares $Y_{i}=pk_{i}^{f(i)}\in \mathbb {G}_{2}\text {for}i\in [n].$(3) Compute $ζ=g^{α}$and a NIZK proof $\theta =(c,r)$of knowledge of $a$ where the challenge is $c=\mathrm {H}\left(g^{r}ζ^{-c},ζ\right).$Publish $\pi :=\langle ζ,\theta \rangle _{L}$The transcript verification algorithm Ver takes as input the public keys $pk_{1},\cdots ,pk_{}$(including $\left.pk_{L}\right)$and transcript $T_{L}$. It outputs 1 (accept) or 0 (reject). Let $LC$ be the linear code as defined in General Notation 2 and let $\mathcal {LC}^{\bot }$e its dual code.<br>(4)Check that $\left(g,Y_{i}\right)=\left(C_{i},p_{i}\right)$for a $all$ $i\in [n].$. Sample a random codeword $\left(v_{1},\cdots ,v_{n}\right)\in \mathcal {LC}^{\bot }\text {andcheckthat}$ $C_{1}^{v_{1}}·\cdots ·C_{n}^{v_{n}}=1$(5)Check that $ζ=g^{f(0)}$via Lagrange interpolation in the exponent from the $C_{i}$(6) Check that the NIZK proof $\theta =(c,r$verifies using $ζ$and H. Check thatthe signature on $\langle ζ,\theta \rangle _{L}$verifies using $pk_{L}$(7) If one of the above checks fails, output 0 (invalid transcript). Otherwise, output 1 (valid transcript).</td>
</tr></table>

**Figure 1: Aggregatable distribution protocol ADist and transcript verification algorithm** Ver of **OptRand's** APVSS.

<table border="1" ><tr>
<td>On input the encrypted shares $Y_{1},\cdots ,Y_{},$the decryption Dec and reconstruction Rec algorithms work as follows.<br>(1) Using $sk_{i}$, compute the secret share $S_{i}=h^{f(i}$from $Y_{i}$via extracting the root $S_{i}=Y_{i}^{1/sk_{i}}$.Publish the decryption $S_{i}$.<br>(2) Upon receiving a secret share $S_{\ell }$ from party $P_{\ell },$check that $\left(C_{\ell },h\right)=\left(,S_{\ell }\right)$.Otherwise, the secret share is invalid.<br>(3)Upon receiving $t+1$valid secret shares $S_{j}=h^{f(j}$from different parties,compute $S=h^{f(0)}$via Lagrange interpolation in the exponent.Finally, the secret is computed as $(\hat {g}S)\in \mathbb {G}_{T}$and output.</td>
</tr></table>

**Figure 2: Decryption Dec and reconstruction Rec algorithms of OptRand's APVSS.**

<table border="1" ><tr>
<td>We demonstrate aggregation for the first $t+1$parties $P_{1},\cdots ,P_{t+1}$ The algorithm $Agg$ takes as input the individual parties' transcripts $\left\{C_{i,j},Y_{i,j},\pi _{j}\right\}_{i\in [n]}$for all party indices $j\in [t+1]$and outputs an aggregated transcript $AT:=\left\{C_{i},Y_{i},\pi \right\}_{i\in []}$.In the following,let $μ_{1},\cdots ,μ_{t+1}$denote the Lagrange coefficients for the set $[t+1]$at the point $x=0,$i.e. $μ_{i}:=\prod _{j\in [t+1]\backslash \{i\}}$ $j/(j-i)$for $i\in [t+1]$(1) For i E [n],compute$C_{}:=C_{,1}·\cdots ·C_{,t+1}$and $Y_{i}:=Y_{i,1}·\cdots ·Y_{i,t+1}.$Let $\pi :=\left(\pi _{1},\cdots ,\pi _{t+1}\right)$where as above $\pi _{j}=\left\langle ζ_{j},\theta _{j}\right\rangle _{j}$for $\text {all}j\in [t+1$.Publish the aggregated transcript $AT:=\left\{C_{i},Y_{i},\pi \right\}_{i\in [n]}$The aggregation transcript verification algorithm AVer takes as input public keys $pk_{1},\cdots ,pk_{}$and an aggregated transcript $AT:=$ $\left\{C_{i},Y_{i},\pi \right\}_{i\in []}$as above. It outputs 1 (valid aggregated transcript) or 0 (invalid aggregated transcript).<br>(2) Check as usual that $\left\{C_{i},Y_{i}\right\}_{i\in [n]}$and that $\left\langle ζ_{i},\theta _{i}\right\rangle _{i}$for $i\in [t+1]$verify.Also check that $ζ_{1}·\cdots ·ζ_{t+1}=C_{1}^{μ_{1}}·\cdots ·C_{t+1}^{μ_{t+1}}$.If one of these checks fails, output 0 (invalid aggregated transcript). Otherwise, output 1 (valid aggregated trancript).</td>
</tr></table>

**Figure** 3: Aggregation algorithm $Agg$  and aggregation transcript **verification** **algorithm** AVer **of OptRand's** **APVSS.**

·Online Phase. Run A on input (par, $\left.ξ_{1},\cdots ,ξ_{}\right)$ In this phase, A gets access to the oracle $\mathrm {DL}_{g}\text {in}\mathbb {G}_{1}.$ 

·Output Determination. When A outputs $\left(z_{1}^{\prime },\cdots ,z_{}^{\prime }\right)$ ,return 1 $\text {if(i)}z_{i}^{\prime }=z_{i}$ for all $i\in [n]$ ,and1(ii) $\mathrm {DL}_{g}$ was queried at most $n-1$ times during the online phase. Otherwise, return 0.

We say that the co one-more discrete logarithm problem of degree n is(ε,T)-hard if for all algorithms A that run in time at most $T$ , $\text {P}\left[-\text {COMDL}^{\mathrm {}}=1\right]\leq \varepsilon .$ Conversely, we say that an algorithm A $(ε,T)$ )-solves the co one-more discrete logarithm problem of degree $n$  if it runs in time at most $T$ , and $\text {Pr}\left[n-\mathbf {COMDL}^{\mathrm {A}}=1\right]>\varepsilon .$ .linear (multivariate) polynomials. Their proof relies on techniques from linear algebra, especially the theory of linear vector spaces. In our case, however, this lemma does not suffice anymore, since we obtain polynomials of degree 2 from the pairing operation. Nevertheless, using techniques from algebraic geometry and the theory (of rational points) on projective varieties, we are able to extend their lemma to our setting and thus get a proof of hardness of COMDL in the generic group model. We note that the proof

In the full version, we provide a proof of hardness of COMDL in the generic group model (GGM) when the groups are equipped with a bilinear pairing ee: $\mathbb {G}_{1}x\mathbb {G}_{2}\rightarrow \mathbb {G}_{T}$ . This structure gives the adversary additional power and makes our proof even more valuable. Our proof follows along the lines of Bauer et al.'s [5] proof of hardness of OMDL in the GGM. At the heart of their proof is a technical lemma on vector spaces generated by the vanishing set of

Some notes on OptRand's APVSS.. In their scheme, the authors use an unspecified digital signature scheme to sign the commit-ment $ζ=g^{α}$ along with the NIZK proof of knowledge $\theta$ .In our description of their scheme, we assume for convenience that the generated pairs $\left(pk_{i}sk_{i}\right)$ also (implicitly) include the verification-signing key pair (vki,dlki)of the underlying signature scheme for party $P_{i}$ so that we do not have to keep track of these pairs in our description of the scheme. We will use a signature scheme $\mathrm {DS}=(\mathrm {SKey},\text {Sign},\mathrm {Ver})$  as defined in Definition ?? to implement

<!-- 1797 -->

<!-- CCS '23, November 26-30, 2023, Copenhagen, Denmark -->

<!-- Renas Bacho & Julian Loss -->

their (and SPURT's) underlying APVSS scheme. For this, we will write $\text {APVSS}_{\mathrm {DS}}$  to denote that APVSS is implemented with DS.In particular $\left(vk_{i},dk_{i}\right)\leftarrow \text {SKey}(\text {par},i)$  is used for the owner identi-fier algorithm. In Definition ??, we define the security of a signature scheme by means of the unforgeability under chosen message game.

Subsequently, we give a tight securityreduction from the hard-ness of $n-COMDL$  to the aggregated unpredictability of OptRand's APVSS scheme. In the following, we provide an intuition for our proof. Our analysis starts with the observation that the adversary controlling t parties essentially has four options to successfully predict the secret S of the aggregate. Firstly, it learns an additional $(+1)$ -th decryption key controlled by an honest party, in which case it can derive S from enough decryptions of secret shares. Sec-ondly, it breaks the underlying encryption scheme directly and thus obtains an additional secret share. Thirdly, it finds the discrete log-arithm $e$  of the second generator $\hat {g}\in \mathbb {G}_{1}$ to base $g$ ,in which case it can compute the secret $S=\left(\hat {g},h^{α}\right)$ from the element $g^{α}$ (which is derived via Lagrange interpolation in the exponent from the public commitments) by the identity $\left(\hat {g},h^{α}\right)=\left(g^{α},h\right)^{\ell }$ .Lastly,it forms its contributions to the aggregate such that honest parties' contri-butions erase (malleability attack). The key idea of our reduction therefore is to embed the $n-COMDL$  challenge $ξ$  in the public keys $pk_{1},\cdots ,pk_{}$ f parties, the polynomial $\in \mathbb {Z}_{p}[X]$ chosen by the challenger to answer a transcript query, or the second generator $\hat {g}\in \mathbb {G}_{1}$ , a choice that remains hidden from the adversary. In the first case,we simulate by using the discrete logarithm oracle [ $\mathrm {DL}_{}$ o answer corruption queries. In the second case, we simulate by using an honest-verifier zero knowledge simulation in the random oracle to generate the NIZK proofs for the transcripts of honest parties.In the third case, we execute the protocol honestly. Additionally,our reduction is able to leverage the algebraic equations that result from the random oracle queries by the adversary to generate its NIZK proofs of knowledge to handle the malleability attack. Overall,our reduction is tight and loses only a factor of $1/6$ . The running time of the reduction has only a quadratic overhead.

THEOREM 3.5. If $n-COMDL$  is $(ε,T)$  -hard in the AGM and DS is $\left(\varepsilon _{s},T_{s},q_{s}\right)$ -secure, then OptRand's $\text {APVSS}_{\mathrm {DS}}$  is $\left(\varepsilon ^{\prime }T^{\prime }tq_{k}q_{h}\right)$ aggregated unpredictable in the AGM & ROM,where

$\varepsilon \geq \frac {\varepsilon ^{\prime }-\varepsilon _{s}}{6}-\frac {q_{h}}{6p},$ $T\leq T^{\prime }+T_{s}+O\left(n^{2}\right)$ 

PROOF. Let A be an algebraic adversary that ( $\left(\varepsilon ^{\prime },T^{\prime },,q_{k},q_{h}\right)$ breaks aggregated unpredictability of APVSS. In our proof, we assume that all parties are honest prior to the execution of APVSS. It is easy to adjust the proof to the case where the adversary has already corrupted some parties before the execution of the protocol. Additionally, we assume that the aggregated transcript output by the adversary at the end of the game has contribution from ex-actly one corrupt party. At the end of the proof we explain how to adjust the proof (at one place) to obtain the general case. In the following,let $C\subset \mathcal {P}=\left\{P_{1},\cdots ,P_{}\right\}$ be the dynamically changing set of corrupt parties and $\mathcal {H}=\mathcal {P}\backslash C$ the set of honest parties. In particular, we assume that $C=\{\}$ prior to the execution of the protocol. We consider the following game between a challenger and the adversary.

GAME G: This is the real game. The challenger generates the system parameters $\left(\mathbb {G}_{1},\mathbb {G}_{2},\right.$ p,g,g,h),,where e: $\mathbb {G}_{1}x\mathbb {G}_{2}\rightarrow \mathbb {G}_{T}$ is an asym-metric pairing of cyclic groups of prime order $p$  with independent generators $g,\hat {g}\in \mathbb {G}_{1}$ and $h\in \mathbb {G}_{2}.$  Furthermore, the challenger gen-erates the public-secret key pairs $\left(pk_{i}k_{i}\right)=\left(h^{x_{i}}x_{i}\right)$ of the honest parties. Whenever A decides to corrupt a party $P_{i}$  the challenger returns the internal state of that party, which consists of $P_{i}$ 's secret key $x_{i}=sk_{i},$ ,and sets $C=C\cup \left\{P_{i}\right\},\mathcal {H}=\mathcal {H}\backslash \left\{P_{i}\right\}$ .In addition, $A$  gets full control over party $P_{i}$ . Random oracle queries $m_{i}$  are answered by sampling $r_{i}\leftarrow \mathbb {Z}_{p}^{*}$ uniformly at random and returning $H\left[m_{i}\right]=r_{i}.$ Transcript oracle queries are answered by sampling a polynomial fk $\leftarrow \mathbb {Z}_{p}[X]$ of degree t uniformly at random, running the ADist algorithm and returning the transcript $T_{k}$ with recon-structed secret e(g,i $\left.h^{α_{0,k}}\right)$ where $α_{0,k}=f_{k}(0)$ . The transcript also includes $ζ_{k}=g^{α_{0,k}}$ and a Chaum-Pedersen non-interactive zero-knowledge (NIZK) proof of knowledge $\pi _{k}=\left(c_{k},r_{k}\right)$ of $α_{0,k}$ The challenge $c_{k}$  for the proof is computed as the hash $\mathrm {H}(-)\text {o}g^{_{k}}\|ζ_{k},$ where $_{k}=_{k}-c_{k}α_{0,k}$ and || denotes the concatenation of elements in $\mathbb {G}_{1}$ .From now on, we write $P:=_{1}\in \mathbb {Z}_{p}[X]$  for $f_{1}$ .At the end of the game, A outputs an aggregated transcript AT with contribution from $t+1$  different parties along with a secret $σ^{*}\in \mathbb {G}_{}.$ 

GAME $\mathrm {G}_{1}$ : This game is identical to the game before, except that the game aborts and the adversary loses when it forges a signature of an honest party. Clearly, the statistical distance between game G and $\mathrm {G}_{1}$  is bounded by the advantage $\varepsilon _{S}$  of $A$  in the UF-CMA game of the underlying signature scheme DS. This observation is necessary, otherwise A could forge signatures on the NIZK and aggregate $t+1$ transcripts it sampled itself. Note that in the APVSS scheme the signature is used as proof of ownership of a transcript.

The strategy of our reduction will be to embed the COMDL instance into the generator $\hat {g}$ , the public keys $pk_{1}\cdots pk_{n}$ f parties, or the polynomials $f_{k}\in \mathbb {Z}_{p}[X]$ of transcripts $T_{k}$ .In the following, we make the simplification by embedding the instance in only one particular polynomial, w.l.o.g. the first one $f_{1}$ 1, and that the adversary picks the corresponding transcript $T_{1}$  for his aggregated transcript. At the end of the proof, we will eliminate these simplifications. Having said that, our reduction now samples all buit the first queried transcript honestly. As A is an algebraic adversary, it returns the secret $σ^{*}$  together with a representation

$$\left(a,b,\left\{c_{i}\right\}_{i=1}^{n},\left\{d_{i}\right\}_{i=1}^{n},\left\{e_{i}\right\}_{i=1}^{n},\left\{f_{i}\right\}_{i=1}^{n},\left\{u_{i}\right\}_{i=1}^{n},\left\{v_{i,j}\right\}_{i,j=1}^{n},\left\{w_{i,j}\right\}_{i,j=1}^{n}\right)$$

of elements in $\mathbb {Z}_{p}$ such that

$$σ^{*}=e(g,h)^{a}·e(\hat {g},h)^{b}·\prod _{i=1}^{n}e\left(C_{i},h\right)^{c_{i}}·\prod _{i=1}^{n}e\left(g,pk_{i}\right)^{d_{i}}·\prod _{i=1}^{n}e\left(g,Y_{i}\right)^{e_{i}}$$

$$\prod _{i=1}^{n}e\left(\hat {g},pk_{i}\right)^{f_{i}}·\prod _{i=1}^{n}e\left(\hat {g},Y_{i}\right)^{u_{i}}·\prod _{i,j=1}^{n}e\left(C_{i},pk_{j}\right)^{v_{i,j}}·\prod _{i,j=1}^{n}e\left(C_{i},Y_{j}\right)^{w_{i,j}}$$

(1)

Here, the representation is split (from left to right) into powers of pairing evaluations on combinations of the generators g $\hat {}\in \mathbb {G}_{1}$ and h $\in \mathbb {G}_{2}$ ,the public keys $pk_{1},\cdots ,pk_{}\in \mathbb {G}_{2}$ ,the polynomial commitments $C_{1},\cdots ,C_{n}\in \mathbb {G}_{1}$  of $f_{1}$ , and the encrypted shares $Y_{1},\cdots ,Y_{n}\in \mathbb {G}_{2}.$  As already clarified, we do not explicitly present the elements from the outputs $\left\{T_{k}\right\}_{k\geq 2}$ in the equation because these can directly be put into the other terms in on the right-hand side of the equation (since the $T_{k}$ for $k>1$  are honestly gener-ated). We also do not include $ζ$  into the equation because it can be computed via Lagrange interpolation in the exponent from the commitments $C_{1},\cdots ,C_{n}.$ In the following, let $R_{i}$  fori e [qh]denote the random oracle queries made by the adversary. Let $R_{\dagger }$ and $ζ^{\prime }$ be the elements corresponding to the contribution of the corrupt party. Since A is an algebraic adversary, it returns the elements $R_{\dagger }\stackrel {!}{=}g^{r^{\prime }}ζ^{\prime -^{\prime }}\in \mathbb {G}_{1}\text {ad}$ $ζ^{\prime }\in \mathbb {G}_{1}$ together with an algebraic repre-sentation. Note that we assume w.l.o.g.that the adversary queries the random oracle on $R_{\dagger }\|ζ$ to obtain a challenge for the NIZK $\pi ^{\prime }$ corresponding to its contribution. For $R_{\dagger },$ let $\left(^{\prime },b^{\prime },c_{1}^{\prime },\cdots ,c_{}^{\prime }\right)$ be elements in $\mathbb {Z}_{p}$ such that

<!-- 1798 -->

<!-- Adaptively Secure (Aggregatable) PVSS and Randomness Beacons -->

<!-- CCS'23, November 26-30, 2023, Copenhagen,Denmark -->

$R_{\dagger }=g^{a^{\prime }}·\hat {g}^{b^{\prime }}·C_{1}^{c_{1}^{\prime }}·\cdots ·C_{n}^{c_{n}^{\prime }}$  (1')

And for $ζ^{\prime }$ ,let $\left(a^{\dagger },b^{\dagger },c_{1}^{\dagger },\cdots ,c_{n}^{\dagger }\right)$ be elements in $\mathbb {Z}_{p}$ such that

$ζ=g^{a^{\dagger }}·\hat {g}^{b^{\dagger }}·C_{1}^{c_{1}^{\dagger }}·\cdots ·C_{n}^{c_{n}^{\dagger }}$  (1”)

In the following,let $\ell \in \mathbb {Z}_{p}$ denote the discrete logarithm of $\hat {g}$ to base $g$ $\left(\text {i..}g^{\ell }=\hat {g}\right)$ And let $α_{0,i}=f_{i}(0)$ for $i\in [2,$ qk]denote the secret field elements chosen by the reduction to answer the i-th transcript oracle query $T_{i}$ . Assuming the adversary wins the game $G$  by outputting the secret of the aggregated transcript AT (w.l.o.g. it has contributions(α',o $\left.α,α_{0,2},\cdots ,α_{0,t}\right)$ ,where $α^{\prime }$  comnes from the adversary), the above equation (1) to base $e(g,h)$  yields

$$\ell \left(α+α^{\prime }+\sum _{i=2}^{t}α_{0,i}\right)=a+\ell b+\sum _{i=1}^{n}P(i)c_{i}+\sum _{i=1}^{n}x_{i}d_{i}+\sum _{i=1}^{n}x_{i}P(i)e_{i}\quad +\ell \sum _{i=1}^{n}x_{i}f_{i}+\ell \sum _{i=1}^{n}x_{i}P(i)u_{i}+\sum _{i,j=1}^{n}P(i)x_{j}v_{i,j}+\sum _{i,j=1}^{n}P(i)P(j)x_{j}w_{i,j}$$

Since the $α_{0,i}$ for $i>1$ are known and the sum with coefficients $e_{i}$ also appears in the sum with coefficients $v_{i,i}$ ,this equation reduces to (using the same symbols for the coefficients)

$$\ell \left(α+α^{\prime }\right)=\ell \left(b+\sum _{i=1}^{n}x_{i}f_{i}+\sum _{i=1}^{n}x_{i}P(i)u_{i}\right)+a+\sum _{i=1}^{n}P(i)c_{i}+\sum _{i=1}^{n}x_{i}d_{i}\quad +\sum _{i,j=1}^{n}P(i)x_{j}v_{i,j}+\sum _{i,j=1}^{n}P(i)P(j)x_{j}w_{i,j},\tag{2}$$

which we write as $\ell \left(α+α^{\prime }\right)=αA+B$ for appropriate variables $A$ and B. On the other hand, equation (1') together with the condition that $R_{\dagger }\stackrel {!}{=}g^{r^{\prime }}ζ^{-c^{\prime }}$ yields

$α^{\prime }c^{\prime }=r^{\prime }-a^{\prime }-\ell b^{\prime }-\sum _{i=1}^{n}P(i)c_{i}^{\prime }$  (2')one (2) with the same notation for $A$  and B yields

We make the crucial observation that the adversary necessarily queries the random oracle on input $R_{\dagger }\|ζ$ before obtaining the challenge $c^{\prime },$ thus fixing the value $α^{\prime }$ ' before $c^{\prime }$  was chosen by the reduction. Therefore, all appearing variables includling $α^{\prime }$  are in-dependent from $c^{\prime }$  and the above equation $(2')$  is equivalent to $α^{\prime }=\tilde {a}+\ell \tilde {b}+\sum _{i\leq }P(i\tilde {c}_{i}/c^{\prime }\left(2^{\prime \prime }\right),$ ,where the elements $\tilde {a},\tilde {b},\tilde {c}_{i}\in \mathbb {Z}_{p}$ are appropriately defined. Plugging this equation into the above

$$\ell ^{2}\tilde {b}+\ell \left(α+\tilde {a}+\sum _{i=1}^{n}P(i)\tilde {c}_{i}/c^{\prime }-A\right)-B=0.$$

Not to forget, equation $(1")$  yields

$$α^{\prime }=a^{\dagger }+\ell b^{\dagger }+\sum _{i=1}^{n}P(i)c_{i}^{\dagger }\tag{1}$$

where the coefficients on the right-hand side are again independent from $c^{\prime }$ '. In the following, we denote by $V$  the Vandermonde matrix corresponding to the polynomial $ω(X)=1+X+\cdots +X^{t}\in \mathbb {Z}_{p}[X]$ of degree t at the points $\{1,2,\cdots ,n\}$ .Since V is Vandermonde, its rank is $t+1$  and thus its kernel $ker(V)$ is of dimension $n-(t+1)=t.$ 

We define the following four events:

$E_{1}$  defined by $\tilde {b}=0\wedge$ $α+\tilde {a}+\sum _{i=1}^{n}P(i)\tilde {c}_{i}/c^{\prime }-A=0.$ 

$E_{2}$ defined by: $\left(\tilde {c}_{1},\cdots ,\tilde {c}_{n}\right)\in \mathbb {Z}_{p}^{n}$ is in the kernel of V.

$E_{3}$ defined by $1=x_{1}u_{1}+\cdots +x_{n}u_{n}$ 

· $E_{4}$ defined by:There is no index $i\in \mathcal {H}\text {s.t.}u_{i}\neq 0.^{3}$ 

We have the following technical lemma.

LEMMA 3.6. Let $\mathrm {G}_{1}$ and $E_{i}$  for $i\in [4]$ be defined as above.Then there exist (algebraic) algorithms $\mathrm {A}_{j}$ $forjE$ [5] playing in game **n-COMDL** that run in time at most T such that:

$$\text {Pr}\left[n-\text {COMDL}^{\mathrm {A}_{1}}=1\right]=\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge \neg E_{1}\right],$$

$$\text {Pr}\left[n-\text {COMDL}^{\mathrm {A}_{2}}=1\right]=\left(1-\frac {1}{p}\right)·\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge E_{1}\wedge \neg E_{2}\right],$$

$$\text {Pr}\left[n-\text {COMDL}^{\mathrm {A}_{3}}=1\right]=\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge E_{1}\wedge E_{2}\wedge \neg E_{3}\right],$$

$$\text {Pr}\left[n-\text {COMDL}^{\mathrm {A}_{4}}=1\right]=\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge E_{1}\wedge E_{2}\wedge E_{3}\wedge \neg E_{4}\right],$$

$$\text {Pr}\left[n-\mathrm {COMDL}^{\mathrm {A}_{5}}=1\right]=\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge E_{1}\wedge E_{2}\wedge E_{3}\wedge E_{4}\right]$$

Moreover, $T\leq T^{\prime }+O\left(n^{2}\right)$ 

PROOF.Let $ξ=\left(ξ_{1},\cdots ,ξ_{n}\right)\in \left(\mathbb {G}_{1}x\mathbb {G}_{2}\right)^{n}$ with $ξ_{i}=\left(g^{z_{i}},h^{z_{i}}\right)$ for $i\in [n]$ be the COMDL instance of degree $n$ . Algorithms $\mathrm {A}_{i}$  for $i\in [5]$ have access to a (perfect) discrete logarithm oracle $\mathrm {D}_{g}$ in $\mathbb {G}_{1}$  (to base $g$ ) which they can query at most $n-1$ times.When we say algorithm $\mathrm {A}_{i}$  queries the discrete logarithm oracle on $ξ_{j}$ ,we mean that it queries $3$  on the first component of $ξ_{j}$ which is a group element in $\mathbb {G}_{1}$  . The algorithms $\mathrm {A}_{i},i\in [5]$ ,simulate game $\mathrm {G}_{1}$ as described in the following.

**Algorithm** $A_{1}(ξ,par)$  :Algorithm $\mathrm {A}_{1}$ works as follows. On input $ξ$ , $\mathrm {A}_{1}$ queries the discrete logarithm oracle $\mathrm {DL}_{g}$ on $ξ_{2},\cdots ,ξ_{}$ and gets $\left(z_{2},\cdots ,z_{n}\right)$ . It publishes the generator $\hat {g}$  by setting $\hat {}=ξ_{1,1}$ In particular, it is $\ell =\mathrm {DL}_{}(\hat {})=z_{1}$ .Furthermore, $\mathrm {A}_{1}$ generates the public-secret key pairs of parties and the polynomial $P(X)\in \mathbb {Z}_{p}[X]$ honestly (by sampling $sk_{i}$ i, $α_{j}\leftarrow \mathbb {Z}_{p}$ uniformly at random). Random oracle queries $m_{i}$  are answered honestly by sampling $r_{}\leftarrow \mathbb {Z}_{p}$ and returning $H\left[m_{i}\right]=r_{i}$ .. Transcript oracle queries are answered hon-estly by sampling a polynomial $f_{k}\leftarrow \mathbb {Z}_{p}[X]$ of degree t uniformly at random and running the distribution phase on it. Corruption queries are answered by returning the secret key of the correspond-ing party. It is not hard to see that $\mathrm {A}_{1}$ 's simulation of $\mathrm {G}_{1}$  is perfect.

$3Att$ his stage, $\mathcal {H}\subset \mathcal {P}$ is the set of parties that remain honest at the end of the game.

<!-- 1799 -->

<!-- CCS '23, November 26-30, 2023, Copenhagen,Denmark -->

<!-- Renas Bacho & Julian Loss -->

Suppose that $\mathrm {A}_{1}$  wins $\mathrm {G}_{1}$ and that event $\neg E_{1}$  happens. Equation $()$ is then a non-trivial equation of degree one or two in l over the field $\mathbb {Z}_{p}$ (either the coefficient of $\ell ^{2}$ or the one from $l$  is non-zero). By standard techniques, $\mathrm {A}_{1}$ can efficiently compute $\ell =z_{1}$ and thus solve the COMDL instance. Overall, we obtain

$$\text {Pr}\left[n-\mathrm {COMDL}^{\mathrm {A}_{2}}=1\right]=\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge \neg E_{1}\right].$$

The bound on the running time of $\mathrm {A}_{1}$ is obvious.

**Algorithm** $\mathrm {A}_{2}(ξ,$ par):Algorithm $\mathrm {A}_{2}$ works on input $ξ_{i}=\left(g^{z_{i}},h^{z_{i}}\right),$ $i\in [n],$ ,as follows. It samples $\ell \leftarrow \mathbb {Z}_{p}$ uniformly at random and publishes $\hat {g}=g^{\ell }$ . It generates the public-secret key pairs of parties honestly. It chooses the polynomial $P(X)=α_{0}+α_{1}X+\cdots +α_{}X^{}$ s.t. $g^{α_{i}}=ξ_{i+1,1}$ for all $i\in [[]]$ . In particular, it is $α_{i}=z_{i+1}$ for $i\in [[t]]$ Commitments $C_{i}=g^{P(i)}$ and encryptions $Y_{i}=pk_{i}^{P(i)}=\left(h^{P(i)}\right)^{x_{i}}$ are computed via Lagrange interpolation in the exponent from the elements $ξ_{1},\cdots ,ξ_{t+1}$ and returned to the adversary. The NIZK proof $\pi$  is generated via an HVZK simulation and returned. Random oracle queries $m_{i}$  are answered by sampling $r_{}\leftarrow \mathbb {Z}_{p}$ and returning $H\left[m_{}\right]=r_{}.$ .Transcript oracle queries for $k>1$ are answered by sampling a polynomial $f_{k}\leftarrow \mathbb {Z}_{p}[X]$ of degree t uniformly at random and running the distribution phase on it. Corruption queries are answered by returning the secret key of the corresponding party. It is not hard to see that $\mathrm {A}_{2}$ 's simulation of $\mathrm {G}_{1}$  is perfect.

Suppose that $\mathrm {A}_{2}$  wins $\mathrm {G}_{1}$  and that event E1 $V$ $\neg E_{2}$ happens.In particular,the vector $\left(\tilde {c}_{1},\cdots ,\tilde {c}_{n}\right)\in \mathbb {Z}_{p}^{n}$  is not in the kernel of $V$ .Comparison of the equations $(2")$  and (t) coming from the random oracle query on $R_{\dagger }\|ζ^{\prime }$ gives

$$\tilde {a}+\ell \tilde {b}+\sum _{i=1}^{n}P(i)\tilde {c}_{i}/c^{\prime }=a^{\dagger }+\ell b^{\dagger }+\sum _{i=1}^{n}P(i)c_{i}^{\dagger }$$

$$Longleftrightarrow\quad \sum _{i=1}^{n}P(i)δ_{i}=a^{\dagger }-\tilde {a}+\ell \left(b^{\dagger }-\tilde {b}\right),$$

where $δ_{i}:=\left(\tilde {c}_{i}/c^{\prime }-c_{i}^{\dagger }\right)$ for all $i\in [n]$ .With the previously defined notation $P(X)=α_{0}+α_{1}X+\cdots +α_{t}X^{t},$ the last equation is equivalent

$\sum _{i=0}^{t}α_{i}\left(δ_{1}+2^{i}δ_{2}+3^{i}δ_{3}+\cdots +n^{i}δ_{n}\right)=a^{\dagger }-\tilde {a}+\ell \left(b^{\dagger }-\tilde {b}\right)$ $Longleftrightarrow\quad \sum _{i=0}^{t}α_{i}F(i)=a^{\dagger }-\tilde {a}+\ell \left(b^{\dagger }-\tilde {b}\right),$  ()

where $F(X):=δ_{1}+2^{X}δ_{2}+3^{X}δ_{3}+\cdots +n^{X}δ_{n}.$ Assuming $F(i)=0$ for all $i\in [[t]]$ , we get the following system of linear equations in the variables $δ_{1}\cdots δ_{n}$ written in matrix form:

$$\begin{pmatrix}1&1&\cdots &1\\ 1&2&\cdots &n\\ :&:&&:\\ :&2^{t}&\cdots &n^{t}\end{pmatrix}\cdot \begin{pmatrix}\delta _{1}\\ \delta _{2}\\ :\\ \delta _{n}\end{pmatrix}=\begin{pmatrix}0\\ 0\\ :\\ 0\end{pmatrix}\quad \Leftrightarrow \quad V\cdot \begin{pmatrix}\tilde {c}_{1}\\ \tilde {c}_{2}\\ :\\ \tilde {c}_{n}\end{pmatrix}/c^{\prime }\quad =V\cdot \begin{pmatrix}c_{1}^{\dagger }\\ c_{2}^{\dagger }\\ :\\ c_{n}^{\dagger }\end{pmatrix}$$

By assumption that event- $\neg E_{2}$ happens, the left-hand side is an n-dimensional non-zero vector with scaling factor $1/c^{\prime },$ whereas the right-hand side is an n-dimensional vector independent from $c^{\prime }$  (since the coefficients $c_{i}^{\dagger }$ and $\tilde {c}_{i}$ were fixed by the adversary before seeing $c^{\prime }$ ). As a result, both sides are equal with probability at most $1/p$ . Therefore, there is an $\tilde {i}\in [[t]]$ such that $F(i)\neq 0$ with probability $1-1/p$ and algorithm $\mathrm {A}_{2}$ proceeds as follows. It queries the discrete logarithm oracle $\mathrm {DL}_{g}$ on $ξ_{i+1}$ for all $i\in [[n-1]\backslash \{\tilde {i}\}$ and obtains $z_{i}$  for all $\in [n]\backslash \{\tilde {}+1\}$ .In particular, $\mathrm {A}_{3}$ has knowledge of the polynomial coefficients $α_{i}$  for all $\neq \tilde {}$ and computes the remaining value $a$ from the above equation()using $F(\tilde {i})\neq 0.$ As a result, it solves the COMDL instance with $n-1$  oracle queries. Overall,we obtain

$$\text {Pr}\left[n-\text {COMDL}^{\mathrm {A}_{2}}=1\right]=\left(1-\frac {1}{p}\right)·\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge E_{1}\wedge \neg E_{2}\right].$$

The boundon the running time of $\mathrm {A}_{2}$ is clear.

**Algorithm** $A_{3}(\xi ,par)$ :Algorithm $\mathrm {A}_{3}$  works on input $ξ_{i}=\left(g^{z_{i}},h^{z_{i}}\right)$ $i\in [n],$  as follows. It queries the discrete logarithm oracle $\mathrm {DL}_{g}$ on $ξ_{2},\cdots ,ξ_{n}$ and gets $\left(z_{2},\cdots ,z_{n}\right)$ .It samples $\ell \leftarrow \mathbb {Z}_{p}$ uniformly at random and publishes $\hat {g}=g^{\ell }$ It generates the public-secret key pairs of parties honestly. It chooses the polynomial $q(X)=$ $α_{1}X+\cdots +α_{}X^{}\in \mathbb {Z}_{p}[X]$ uniformly at random and lets $P(X)=$ $α+q(X)$ such that $g^{α}=ξ_{1,1}$ . In particular, it is $α=z_{1}$  and $\mathrm {A}_{3}$ knows the coefficients $α_{i}$ for $i\in$ $[t]$ (since it chose them uniformly at random). Commitments $C_{i}=g^{P(i)}$ are computed as $C_{i}=ξ_{1,1}g^{q(i)}$ and returned. Encrypted shares $Y_{i}=pk_{i}^{P(i)}$ are computed as $Y_{i}=$ $\left(h^{P(i)}\right)^{x_{i}}$ where $h^{P(i)}=ξ_{1,2}h^{q(i)}$ and returned. The NIZK proof $\pi$  is generated via an HVZK simulation and returned. Random oracle queries $m_{i}$  are answered honestly by sampling $r_{i}\leftarrow \mathbb {Z}_{p}$ and returning $H\left[m_{i}\right]=r_{i}$ .. Transcript oracle queries for $k>1$ are answered honestly by sampling a polynomial $fx$ $\leftarrow \mathbb {Z}_{p}[X]$ of degree t uniformly at random and running the distribution phase on it. Corruption queries are answered by returning the secret key of the corresponding party. It is not hard to see that $\mathrm {A}_{3}$ 's simulation of $\mathrm {G}_{1}$ is perfect.

Suppose that $\mathrm {A}_{3}$  wins $\mathrm {G}_{1}$ and that event $E_{1}\wedge$ $E_{2}\wedge \neg E_{3}$ happens. The equation defining event $E_{1}$  is given by

$$α+\tilde {a}+\sum _{i=1}^{n}P(i)\tilde {c}_{i}/c^{\prime }=b+\sum _{i=1}^{n}x_{i}f_{i}+\sum _{i=1}^{n}x_{i}P(i)u_{i}.$$

The knowledge that $\left(\tilde {c}_{1},\cdots ,\tilde {c}_{n}\right)\in \text {kr}(V)$ given by event $E_{2}$ reduces this equation to

$$α+\tilde {a}=b+\sum _{i=1}^{n}x_{i}f_{i}+\sum _{i=1}^{n}x_{i}P(i)u_{i}$$

With the same notation $P(X)=α+q(X)$ as above,this yields

$α+\tilde {a}=b+\sum _{i=1}^{n}x_{i}f_{i}+\sum _{i=1}^{n}x_{i}q(i)u_{i}+α\sum _{i=1}^{n}x_{i}u_{i}$  (+)

With the condition that event $\neg E_{3}$ happens, equation (◆) is a non-trivial linear equation in $a$ and thus yields

$$α=\left(b-\tilde {a}+\sum _{i=1}^{n}x_{i}f_{i}+\sum _{i=1}^{n}x_{i}q(i)u_{i}\right)\left(1-\sum _{i=1}^{n}x_{i}u_{i}\right)^{-1}$$

since the second factor is non-zero. As a result, $\mathrm {A}_{3}$ can efficiently comppute $α=z_{1}$ and thus solve the COMDL instance with $n-1$ oracle queries. Overall, we obtain

$$\text {Pr}\left[n-\text {COMDL}^{\mathrm {A}_{3}}=1\right]=\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge E_{1}\wedge E_{2}\wedge \neg E_{3}\right].$$

The bound on the running time of algorithm $\mathrm {A}_{3}$  is obvious.

**Algorithm** $\mathrm {A}_{4}(ξ,par)$ : Algorithm $\mathrm {A}_{4}$  works on input $ξ_{i}=\left(^{z_{i}},h^{z_{i}}\right)$ 

<!-- 1800 -->

<!-- Adaptively Secure (Aggregatable) PVSS and Randomness Beacons -->

<!-- CCS'23, November 26-30, 2023, Copenhagen, Denmark -->

$i\in [n],$ ,as follows. It samples $\ell \leftarrow \mathbb {Z}_{p}$ uniformly at random and publishes $\hat {g}=g^{\ell }.$ Itgenerates the polynomial $P(X)\in \mathbb {Z}_{p}[X]$ hon-estly by sampling $α_{i}\leftarrow \mathbb {Z}_{p}$ for all $i\in$ [t] uniformly at random. It chooses party $P_{j}\text {'s}$ public key $pk_{j}$ as $pk_{j}=ξ_{j,2}$ for all $j\in [n$ In particular, it is $x_{j}=sk_{j}=z_{j}$ for all j e [n].Commitments $C_{i}$ encrypted shares $Y_{i}$ , and NIZK proof $\pi$  are computed honestly and returned (which is possible, since the polynomial $P(X)$  is completely known to $\left.\mathrm {A}_{4}\right)$ . Random oracle queries $m_{i}$  are answvered honestly by sampling $r_{i}\leftarrow \mathbb {Z}_{p}$ and returning $H\left[_{}\right]=r_{}$ Transcript oracle queries for $k>1$ are answered honestly by sampling a polynomial fk $\leftarrow \mathbb {Z}_{p}[X]$ of degree t uiniformly at random and running the distribution phase on it. Corruption queries are answered with the help of the discrete logarithm oracle $\mathrm {DL}_{g}.$ A corruption query on party $P_{j}$ is answered by computing $\mathrm {DL}_{g}\left(k_{j}\right)$ and returning the secret key $sk_{j}$  . It is easy to see that $\mathrm {A}_{4}$ 's simulation of $\mathrm {G}_{1}$  is perfect. Suppose that $\mathrm {A}_{4}$ wins $\mathrm {G}_{1}$  and that event E1 $r^{v}$ $E_{3}$ $\wedge \neg E_{4}$ hap-pens. In particular, event $\neg E_{4}$  implies that there is an index $\tilde {i}\in \mathcal {H}$ such that $u_{\tilde {i}}\neq 0$ . Given the equation $1=_{1}u_{1}+\cdots +_{}u_{}$ (2)defined by $E_{3}$ ,algorithm $\mathrm {A}_{4}$ proceeds as follows. It queries the dis-crete logarithm oracle $\mathrm {DL}_{g}$ on $ξ_{i}$  for all $i\in \mathcal {H}\backslash$ i} and obtains $x_{i}$  for all $i\in \mathcal {H}\backslash$ i}.Therefore, $\mathrm {A}_{4}$  has knowledge of $x_{i}$  for all $i\in \mathcal {H}\backslash \{\tilde {i}\}\cup C=\mathcal {P}\backslash \{\tilde {i}\}$ and computes the remaining value $x_{\tilde {i}}$  by the above equation (). As a result, it solves the COMDL instance with $n-1$  oracle queries. Overall, we obtain

$$\text {Pr}\left[n-\text {COMDL}^{\mathrm {A}_{4}}=1\right]=\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge E_{1}\wedge E_{2}\wedge E_{3}\wedge \neg E_{4}\right].$$

The bound on the running time of algorithm $\mathrm {A}_{4}$ is clear.

**Algorithm** $A_{5}(ξ,par)$ : Algorithm $\mathrm {A}_{5}$  works on input $ξ_{i}=\left(g^{z_{i}},h^{z_{i}}\right)$ $i\in [n]$ ,as follows. The simulation of the game $\mathrm {G}_{1}$ is identical to that of $\mathrm {A}_{2};$ in particular $\mathrm {A}_{5}$ chooses the polynomial $P(X)=$ $α_{0}+α_{1}X+\cdots +α_{t}X^{t}$ such that $g^{α_{i}}=ξ_{i+1,1}$ for all $i\in [[t]]$ ,and thus it is $α_{i}=z_{i+1}$ for all $i\in [[t]]$ Again, $\mathrm {A}_{5}\text {'s}$ simulation of $\mathrm {G}_{1}$  is perfect. Suppose that $\mathrm {A}_{5}$ wins G and that event $E_{1}$ $V$ $E_{2}\wedge E_{3}\wedge E_{4}$ happens. With the same notation $P(X)=α+q(X)$ as before,events $E_{1}$ to $E$ yield the identities (note that $u_{i}=0$ for all $i\in$  H by $E_{4}$ 4)

$\tilde {a}=b+\sum _{i=1}^{n}x_{i}f_{i}+\sum _{i\in \mathcal {C}}x_{i}q(i)u_{i},\quad 1=\sum _{i\in \mathcal {C}}x_{i}u_{i}$  (★)

The latter implies that there is an index $\tilde {j}\in C$ such that $x_{\tilde {j}}u_{\tilde {j}}\neq 0.$ The first equation in the above identity $(*)$  is then equivalent to

$$q(\tilde {j})=-\frac {1}{x_{\tilde {j}}u_{\tilde {j}}}·\left(b-\tilde {a}+\sum _{i=1}^{n}x_{i}f_{i}+\sum _{i\in \mathcal {C}\backslash \{\tilde {j}\}}x_{i}q(i)u_{i}\right)$$

Algorithm $\mathrm {A}_{5}$  proceeds as follows. It queries the discrete logarithm $\mathrm {DL}_{g}$ on $ξ_{1}$ , $ξ_{+2},\cdots ,ξ_{n}$ and $g^{q(i)}$ for all $i\in C\backslash \{\tilde {j}\}$ .Note that since $g^{P(X)}=g^{α_{0}}·g^{q(X)}=ξ_{1}·g^{q(X)}$ ,algorithm $\mathrm {A}_{5}$ can compute (and hence query) $g^{q(i)}$  for any $\in \mathbb {Z}_{p}$  W.l.o.g. we may assume that $|C|=t$ (otherwise $\mathrm {A}_{5}$ simply simulates,for itself, $t-|C|$ corruption queries for random parties from $H$ ).As a result,/ $\mathrm {A}_{5}$ can compute $q(\tilde {j})$  from the above identity and has finally knowledge of $t+1$  points in the range of $[n]$  on the polynomial $b$ of degree t.In particular, $\mathrm {A}_{5}$ knows the coefficients of q,i.e. $α_{1}=z_{2},\cdots ,α_{t}=z_{t+1}$ .From previous oracle queries it knows $z_{1},z_{+2},\cdots ,z_{n}$ and thus solves the COMDL instance with $1+(n--1)+(-1)=n-1$ queries to $\mathrm {DL}_{g}.$ Overall,we obtain

$$\text {Pr}\left[n-\text {COMDL}^{\mathrm {A}_{5}}=1\right]=\text {Pr}\left[\mathrm {G}_{1}^{\mathrm {A}}=1\wedge E_{1}\wedge E_{2}\wedge E_{3}\wedge E_{4}\right].$$

The bound on the running time of algorithm $\mathrm {A}_{5}$  is obvious.

☐

To end the proof, consider algorithm B playing in $n-COMDL$ as follows: B samples $i^{*}$ ← [5] and then internally emulates $\mathrm {A}_{i^{*}}$ Clearly, B is an algebraic algorithm running in time at most $T$  (the running time of $\left.\mathrm {A}_{i},1\leq i\leq 5\right)$ . An application of the law of total probability yields

$$\text {Pr}\left[n-\text {COMDL}^{\mathrm {B}}=1\right]=\frac {1}{5}\sum _{i=1}^{5}\text {Pr}\left[n-\text {COMDL}^{\mathrm {A}_{i}}=1\right]$$

$$\geq \frac {1}{5}\left(1-\frac {1}{p}\right)·\text {Pr}\left[\mathbf {G}_{1}^{\mathrm {A}}=1\right]$$

$$\geq \frac {1}{6}·\text {Pr}\left[\mathbf {G}_{1}^{\mathrm {A}}=1\right]\geq \frac {1}{6}\left(\varepsilon ^{\prime }-\varepsilon _{s}-\frac {q_{h}}{p}\right)$$

where the last equality comes from the soundness error of the NIZK proof of knowledge of discrete logarithm output by the adversary, one try for each random oracle query. Finally, in the full version we elaborate on the simplifications made at the beginning of the proof, which completes our analysis. ☐

We conclude with a theorem on the aggregated unpredictability of SPURT's APVSS scheme. The proof mostly follows the lines of the above one with some modifications. For this, we observe that there are only two differences between SPURT's and OptRand's APVSS. (1) The former assumes an additional generator $\hat {h}\in \mathbb {G}_{2}$ (resulting in a total of four generators g $g,\hat {g}\in \mathbb {G}_{1}$ $\left.,h,\hat {h}\in \mathbb {G}_{2}\right)$ whose purpose being solely to help their security analysis, which is a reduction from the decisional bilinear Diffie-Hellman (DBDH) problem.(2) The NIZK proof $\pi =(c,r)$ of knowledge of $α=(0)$ is replaced by n independently generated knowledge-sound NIZK proofs $\pi _{i}=$ $\left\{\left(c_{i},r_{i}\right)\right\}$ for $i\in [n]$  of discrete logarithm equality of commitment $C_{i}$  and encrypted share $Y_{i}$  (thus obviating the need to compute n pairings for this task). Here,a challenge $c_{i},i\in$ $[n]$ ,is computed as the cryptographic hash $\mathrm {H}\left(C_{i},g^{_{i}}C_{i}^{_{i}},Y_{i},h^{_{i}}Y_{i}^{_{i}}\right)$ defined by the non-interactive Chaum-Pedersen Σ-protocol. For a proof and a formal description of their scheme, we refer to the full version.

THEOREM 3.7. If $n-COMDL$  is $(ε,T)-hard$  in the AGM and DS is $\left(\varepsilon _{s},T_{s},q_{s}\right)$ -secure, then SPURT's AAPVSSDs $\text {i}\left(\varepsilon ^{\prime },T^{\prime },t,q_{k},q_{h}\right)\text {-aggr-}$ gated unpredictable in the AGM & ROM,where

$\varepsilon \geq \frac {\varepsilon ^{\prime }-\varepsilon _{s}}{6}-\frac {q_{h}}{6p}$ $T\leq T^{\prime }+T_{s}+O\left(n^{2}\right)$ 

## 4 APPLICATION TO STATE-OF-THE-ART RANDOMNESS BEACONS

In this chapter, we discuss the adaptive security of the state-of-the-art randomness beacon protocols in their respective network mod-els: OptRand [7] in the synchronous network model, and SPURT [16] in the partially synchronous network model. In the full version, we provide a detailed discussion (including a comparison table) on existing work of randomness beacons. We begin by formally defining a randomness beacon protocol.

<!-- 1801 -->

<!-- CCS '23, November 26-30, 2023, Copenhagen,Denmark -->

<!-- Renas Bacho & Julian Loss -->

Randomness Beacon. A randomness beacon is a distributed pro-tocol that allows a system of $n$  parties to generate a sequence of unpredictable and unbiased random values, one for each epoch. Each party $P_{i}$ has a local log that is defined as a write-once ar-ray $Σ_{i}=\left(Σ_{i}[1],Σ_{i}[2],\cdots \right)\text {wi}$ $Σ_{i}[\ell ]$ being its beacon output at epoch $\ell \geq 1$ . Initially, each value is set to $T$ . We say that party $P_{i}$ outputs a beacon value in epoch $e$  if it writes a value on $Σ_{i}[\ell ]$ . A secure randomness beacon has to satisfy the following properties: consistency, availability, bias-resistance, and d-unpredictability.

Definition 4.1 (d-Secure Randomness Beacon). Let RB be an epoch-based protocol executed by parties $P_{},\cdots ,P_{}$ We define the follow-ing security properties for RB:

·Consistency. RB is $(t,L)$ -consistent if the following holds whenever at most t parties are corrupted: if an honest party outputs a value $σ_{\ell }\in \{0,1\}^{λ}$ in epoch $\ell \in [L]$ 1,then all honest parties output $σ_{\ell }$  in epoch l.

·Availability. RB is $(t,L)$  -available if the following holds whenever at most t parties are corrupted: for each $\ell \in [L],$ every honest party outputs a value $σ_{\ell }\in \{0,1\}^{λ}$ in epoch $e.$ .

· $Bias-Resistance$ . $RB$  is (ε,T,t,L)-bias-resistant if it is $(t,L)$ available, $(t,L)$ -consistent, and the following holds for all algorithms $A$  D s.t. A corrupts at most t parties and both A and D run in time at most $T$ . Denote by $Σ_{\mathrm {}L}$ the probability distribution induced by the outputs of an honest party in an execution of $RB$  until epoch L with A as adIversary.Then

$$\left|\text {Pr}_{σ\leftarrow Σ_{\mathrm {A},L}}[\mathrm {D}(σ)=1]-\text {Pr}_{u\leftarrow U_{L}}[\mathrm {D}(u)=1]\right|\leq \varepsilon ,$$

where $U_{L}$ denotes the uniform distribution over the L-times Cartesian product of $\{0,1\}^{λ}$ with itself.

· $d-Unpredictability.RB$  is $\left(\varepsilon ,T,t,L,q_{h},d\right)$  -unpredictable if it is $(t,L)$ -available,(t,L)-consistent,and for all $\ell \in [L]$ and algorithms A that run in time at most T and make at most $q_{h}$  random oracle queries, the following experiment outputs 1 with probabillity at most $3$ :

- Offline Phase. For all $i\in [n]$ ,run Keys on input $(par,i)$ ) to generate keys( $\left(pk_{i},sk_{i}\right)$ ←Keys(par, i). On input $par$  and $\left\{pk_{i}\right\}_{i\in [n]},\mathrm {A}$ returns an index set $C\subset []$ of initially cor-rupted parties along with updated public keys $\left\{\hat {pk}_{j}\right\}_{j\in C}.$ Set $pk_{j}:=\hat {pk}_{j}$ for all $j\in C$ . Initiate an execution of $RB$ with A controlling parties in $C$ .

- Random Oracle Queries. At any point of the experiment, A gets access to an oracle that answers queries of the follow-ing type:When A submits a query $m$  check if $H[m]=\bot$ .If so,set $H[m]\leftarrow \{01\}^{λ}$ . Return $H[m]$ ].

- Online Phase. Run $RB$  with A. When A outputs a value $\left(σ_{}^{\prime },\right)$ for an $e>\ell$ , the experiment ends with output 0 in case there is an honest party that has output a value $σ_{\ell +1}$ for epoch $\ell +1.$ Continue the execution of $RB$  for another $e-e$ epochs.

- Corruption Queries. During the online phase, A may cor-rupt a party $P_{i}$  by submitting an indexi e [n]\C.In this case, return the internal state of $P_{i}$ and set $C:=C\cup \{\}$ Henceforth, A controls $P_{i}$ 

- Output Determination. Return 1 4 $|C|\leq t,e\geq \ell +d,L\geq e,$ and $σ_{e}^{\prime }=σ_{e}$ . Otherwise, return 0.

We say that RB is a $\left(\varepsilon ,T,t,L,q_{h},d\right)$ -secure randomness beacon pro-tocol if it is $(ε,T,t,L)$ -bias-resistant, $(ε,T,t,L,$ qh,d)-unpredictable, $(t,L)$ -available, and $(t,L)$ -consistent.

Discussion. We briefly elaborate on the security notions defined above. Consistency and availability guarantee that each honest party outputs the same value $σ_{}\in \{0,1\}^{λ}$ in each epoch $\geq 1$ Bias-resistance guarantees that the beacon outputs are indistinguishable from uniformly random numbers. This property ensures that the adversary has no power in biasing the beacon output,even when controlling up to t parties in the system. On the other hand, this notion does not prohibit the adversary from learning the beacon output some epochs ahead of the honest parties. That is ensured by the notion of $d$ $d-unpredictability$  , which states that the adversary does not learn the beacon output d epochs before the honest parties. Conversely,an adversary could predict the beacon output some epochs ahead of the honest parties, e.g.by corrupting the next t leaders whose previously committed values determine the next t beacon outputs as in GRandPiper [8] or HydRand [30],without having the power to bias it. In our notions, we introduce an epoch bound L upon which the randomness beacon protocol can run.

In the full version, we introduce the notion of a weakly secure randomness beacon to capture the properties of SPURT. Since the construction of SPURT allows parties to output a bot symbol $\bot _{\mathcal {RB}}$ whenever the leader of an epoch does not behave correctly,the protocol does not achieve full availability. Still, every n epochs the randomness beacon outputs at least $n-t$  proper non- $\bot \mathcal {RB}$  values and thus has a form of weak availability.We adapt the other security notions of a randomness beacon accordingly.

### 4.1 OptRand's and SPURT's Beacon Design

We give a high-level description of the randomness beacons of interest, OptRand and SPURT. For more detailed descriptions, we refer the reader to the full version or their papers [7,16]. Both protocols are built upon (respective) leader-based state machine replication (SMR) protocols. In leader-based SMR, parties run a protocol to agree on a public ledger. The protocol proceeds through epochs,where each epoch e has a designated leader $L_{e}$  responsible for choosing the value to agree on for that epoch. In our setting, $L_{e}$  will be instructed to gather and aggregate PVSS transcripts that other parties send to it at the beginning of epoch e.

The protocol rotates through leaders in round-robin fashion (or using a randomized scheduling) so that even a malicious leader cannot stall progress for more than one round. Whenever $L_{e}$  is honest, parties are guaranteed to agree on a correct value for epoch $e$ (where correctness here refers to that of the aggregate transcript $L_{e}$ proposes). We stress that the details of these consensus protocols are immaterial for the ensuing discussion. However, it is impor-tant to note that while both OptRand and SPURT achieve only static security for their beacon constructions, their underlying SMR protocols are adaptively secure. We elaborate more on this below.

OptRand. The protocol employs their APVSS scheme and an op-timistically responsive extension of RandPiper's adaptively secure leader-based SMR [8]. This gives a communication complexity of $O\left(\ell +λ^{2}\right)$  bits per consensus decision on a block of size $e$  bits. In each epoch $\geq 1$ , the leader $L_{e}$  first collects $t+1$  valid PVSS transcripts from other parties, aggregates them, and then puts the aggregate on the ledger.If $L_{}$ does not put anything on the ledger or the aggregate is invalid, parties blacklist $L_{e}$  from future leader elections. Apart from this policy, parties adhere to a round-robin leader election. When the same party is elected as a leader $L_{e^{\prime }}$  in epoch $e^{\prime }>e+t$ the next time, parties take its previously published (valid) aggregate and reconstruct the secret $S_{e}$ . The beacon output $O_{e^{\prime }}$  for epoch $e^{\prime }$  is computed as hash $O_{^{\prime }}=\mathrm {H}\left(S_{}\right)$ . Finally, to en-sure availability the first time a party is elected as the leader, the protocol relies on a setup where parties start with agreed-upon buffers $\mathcal {B}\left(P_{i}\right)$  for $i\in []$  that contain random PVSS transcripts each. Ignoring the pre-processing phase for buffers, OptRand outputs a randomness beacon value with a communication cost of $O\left(λ^{2}\right)$ bits and optimal resilience $t<n/$ 2 in the synchronous setting.

<!-- 1802 -->

<!-- Adaptively Secure (Aggregatable) PVSS and Randomness Beacons CCS '23, November 26-30,2023, Copenhagen, Denmark -->

SPURT. The protocol employs their APVSS scheme and a leader-based SMAR protocol based on HotStuff [34]. Adaptive security of this SMR protocol follows directly from the adaptive security of HotStuff [26,27,34]. Furthermore, their SMRhas a communication complexity of $O\left(\ell n^{2}\right)$ bits per consensus decision on a block of size $e$  bits.In each epoch $e\geq 1,$ the leader $L_{e}$  collects $t+1$ valid PVSS transcripts from other parties, aggregates them and multicasts the aggregate. Additionally, $L_{e}$  distributes other parts of the collection of $t+1$ transcripts among the parties via the private channels such that each non-leader party checks a disjoint part of the aggregation such that any subset of $+1$ honest parties collectively checks the entire aggregation. For efficiency reasons, the SMR is only used for the hash of the aggregate. Again, parties adhere to a round-robin leader election. However, SPURT does not use a blacklisting strategy and a pre-processing phase for buffers and thus does not guarantee availability. When the same party is elected as a leader $L_{e^{\prime }}$ in epoch $e^{\prime }=e+n$ the next time, parties take its previously agreed-upon aggregate and reconstruct the secret $S_{e}$  (in case the leader did not behave correctly, parties do not output a beacon value for that epoch). The randomness beacon value $O_{e^{\prime }}$ is computed as e(Se,h). Spurt outputs a beacon with a communication cost of $O\left(λ^{2}\right)$ bits and optimal resilience $</$  in the partially synchronous setting.

### 4.2 Security Analysis of OptRand and SPURT

We prove that the state-of-the-art randomness beacons OptRand and SPURT are indeed adaptively secure. In their respective papers, the authors only provide a security analysis against a much weaker static adversary. For this, we employ our results from the previous chapter. For our analysis, we consider the derived protocol SPURT+ which results from SPURT by hashing its final output (OptRand does hash the reconstructed secret at the end anyway). This is necessary, since our aggregated unpredictability notion allows the adversary to obtain partial information about the secret.Thus,by hashing the result, we obtain a truly random beacon output (in the random oracle model, which both protocols assume anyway).We provide a proof of the following theorem in the full version.

THEOREM 4.2. If the underlying $\mathrm {APVSS}_{\mathrm {DS}}$ $\text {is}\left(\varepsilon ,T,t,q_{k},q_{h}\right)\text {-ar-}$ gated unpredictable in the AGM & ROM, then OptRand (SPURT+) is an $\left(\varepsilon ^{\prime }T^{\prime }tLq_{h}^{\prime }\right.$ $1-(wakly$ secure randomness beacon protocol in the AGM & ROM,where

$$\varepsilon \geq \frac {\varepsilon ^{\prime }}{L}-\frac {q_{h}^{\prime }}{p},\quad T\leq T^{\prime }+O\left(Ln^{2}\right)$$

## ACKNOWLEDGMENTS

This work is funded by the Deutsche Forschungsgemeinschaft (DFG, German Research Foundation) - 507237585, and by the European Union, ERC-2023-STG, Project ID: 101116713.Views and opinions expressed are however those of the author(s) only and do not nec-essarily reflect those of the European Union. Neither the European Union nor the granting authority can be held responsible for them.

## REFERENCES

[1] Ittai Abraham, Philipp Jovanovic, Mary Maller, Sarah Meiklejohn, and Gilad Stern. 2022. Bingo: Adaptively Secure Packed Asynchronous Verifiable Secret Sharing and Asynchronous Distributed Key Generation. Cryptology ePrint Archive, Report 2022/1759.(2022). https://eprint.iacr.org/2022/1759.

[2] Ittai Abraham, Philipp Jovanovic, Mary Maller, Sarah Meiklejohn, Gilad Stern, and Alin Tomescu. 2021. Reaching Consensus for Asynchronous Distributed Key Generation. CoRR abs/2102.09041 (2021). arXiv:2102.09041 https://arxiv.org/abs/ 2102.09041

[3] Giuseppe Ateniese, Jan Camenisch, and Breno de Medeiros. 2005. Untraceable RFID Tags Via Insubvertible Encryption. In ACM CCS 2005: 12th Conference on Computer and Communications Security, Vijayalakshmi Atluri, Catherine Meadows, and Ari Juels (Eds.). ACM Press, Alexandria, Virginia, USA, 92-101. https://doi.org/10.1145/1102120.1102134

[4] Renas Bacho and Julian Loss. 2022. On the Adaptive Security of the Threshold BLS Signature Scheme. In ACM CCS 2022: 29th Conference on Computer and Communications Security, Heng Yin, Angelos Stavrou, Cas Cremers,and Elaine Shi (Eds.). ACM Press, Los Angeles, CA, USA, 193-207. https://doi.org/10.1145/ 3548606.3560656

[5] Balthazar Bauer, Georg Fuchsbauer, and Antoine Plouviez. 2021. The One-More Discrete Logarithm Assumption in the Generic Group Model. In Advances in Cryptology-ASIACRYPT 2021, Part IV (Lecture Notes in Computer Science), Mehdi Tibouchi and Huaxiong Wang (Eds.), Vol. 13093. Springer, Heidelberg, GGermany, Singapore,587-617.https://doi.org/10.1007/978-3-030-92068-520

[6] Mihir Bellare and Phillip Rogaway. 1993. Random Oracles are Practical: A Para-digm for Designing Efficient Protocols.In ACM CCS 93: 1st Conference on Com-puter and Communications Security, Dorothy E. Denning, Raymond Pyle,Ravi Ganesan, Ravi S. Sandhu, and Victoria Ashby (Eds.). ACM Press, Fairfax, Virginia, USA,62-73.https://doi.org/10.1145/168588.168596

[7] Adithya Bhat, Nibesh Shrestha, Aniket Kate, and Kartik Nayak. 2022. Op-tRand: Optimistically responsive distributed random beacons. Cryptology ePrint Archive, Paper 2022/193.(2022).https://doi.org/10.14722/ndss.2023.24832https://eprint.iacr.org/2022/193.

[8] Adithya Bhat, Nibesh Shrestha, Zhongtang Luo, AAniket Kate,and Kartik Nayak. 2021. RandPiper-Reconfiguration-Friendly Random Beacons with Quadratic Communication. In ACM CCS 2021: 28th Conference on Computer and Communi-cations Security, Giovanni Vigna and Elaine Shi (Eds.). ACM Press, Virtual Event, Republic of Korea, 3502-3524.https://doi.org/10.1145/3460120.3484574

[9] Alexandra Boldyreva. 2003. Threshold Signatures, Multisignatures and Blind Sig-natures Based on the Gap-Diffie-Hellman-Group Signature Scheme. In PKC 2003: 6th International Workshop on Theory and Practice in Public Key Cryptography (Lecture Notes in Computer Science), Yvo Desmedt (Ed.), Vol. 2567.Springer, Heidel-berg, Germany, Miami, FL, USA, 31-46. https://doi.org/10.1007/3-540-36288-63

[10] Dan Boneh,Ben Lynn, and Hovav Shacham. 2001. Short Signatures from the Weil Pairing. In Advances in Cryptology-ASIACRYPT 2001 (Lecture Notes in Computer Science), Colin Boyd (Ed.), Vol. 2248. Springer, Heidelberg, Germany, Gold Coast, Australia, 514-532. https://doi.org/10.1007/3-540-45682-130

[11] Ran Canetti, Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin. 1999. Adaptive Security for Threshold Cryptosystems. In Advances in Cryptology-CRYPTO'99 (Lecture Notes in Computer Science), Michael J.Wiener (Ed.), Vol.1666. Springer, Heidelberg, Germany, Santa Barbara, CA, USA, 98-115. https://doi.org/ 10.1007/3-540-48405-17

[12] Ignacio Cascudo and Bernardo David. 2017. SCRAPE: Scalable Randomness Attested by Public Entities. In ACNS 17: 15th International Conference on Applied Cryptography and Network Security (Lecture Notes in Computer Science), Dieter Gollmann, Atsuko Miyaji, and Hiroaki Kikuchi (Eds.), Vol. 10355. Springer, Hei-delberg, Germany, Kanazawa, Japan, 537-556. https://doi.org/10.1007/978-3-319-61204-127

[13] Benny Chor, Shafi Goldwasser, Silvio Micali, and Baruch Awerbuch. 1985. Veri-fiable secret sharing and achieving simultaneity in the presence of faults. 26th Annual Symposium on Foundations of Computer Science (sfcs 1985)(1985),383-395.

[14] Benny Chor, Shafi Goldwasser, Silvio Micali, and Baruch Awerbuch. 1985. Ver-ifiable Secret Sharing and Achieving Simultaneity in the Presence of Faults (Extended Abstract). In 26th Annual Symposium on Foundations of Computer Science.IEEE Computer Society Press, Portland, Oregon, 383-395. https://doi. org/10.1109/SFCS.1985.64

<!-- 1803 -->

<!-- CCS '23, November 26-30, 2023, Copenhagen,Denmark -->

<!-- Renas Bacho & Julian Loss -->

[15] Elizabeth Crites, Chelsea Komlo, and Mary Maller. 2023. Fully Adaptive Schnorr Threshold Signatures. Cryptology ePrint Archive, Paper 2023/445. (2023). https: //eprint.iacr.org/2023/445 https://eprint.iacr.org/2023/445.

[16] Sourav Das, Vinith Krishnan, Irene Miriam Isaac, and Ling Ren. 2022. Spurt: Scalable Distributed Randomness Beacon with Transparent Setup. In 2022 IEEE Symposium on Security and Privacy. IEEE Computer Society Press, San Francisco, CA,USA,2502-2517.https://doi.org/10.1109/SP46214.2022.9833580

[17] Paul Feldman. 1987. A Practical Scheme for Non-interactive Verifiable Secret Sharing. In 28th Annual Symposium on Foundations of Computer Science. IEEE Computer Society Press, Los Angeles, CA,USA,427-437.https://doi.org/10.1109/ SFCS.1987.4

[18] Georg Fuchsbauer, Eike Kiltz, and Julian Loss. 2018. The Algebraic Group Model and its Applications. In Advances in Cryptology-CRYPTO 2018,Part II(Lecture Notes in Computer Science), Hovav Shacham and Alexandra Boldyreva (Eds.), Vol. 10992. Springer, Heidelberg, Germany, Santa Barbara, CA, USA, 33-62. https: //doi.org/10.1007/978-3-319-96881-02

[19] Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin. 1999. Secure Distributed Key Generation for Discrete-Log Based Cryptosystems. In Advances in Cryptology-EUROCRYPT'99 (Lecture Notes in Computer Science), Jacques Stern (Ed.), Vol. 1592. Springer, Heidelberg, Germany, Prague, Czech Republic,295-310. https://doi.org/10.1007/3-540-48910-X21

[20] Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk,and Tal Rabin. 2007.Secure Distributed Key Generation for Discrete-Log Based Cryptosystems.Journal of Cryptology 20,1(Jan.2007),51-83.https://doi.org/10.1007/s00145-006-0347-3

[21] Kobi Gurkan, Philipp Jovanovic, Mary Maller, Sarah Meiklejohn, Gilad Stern, and Alin Tomescu. 2021. Aggregatable Distributed Key Generation. In Advances in Cryptology-EUROCRYPT 2021, Part I (Lecture Notes in Computer Science), Anne Canteaut and François-Xavier Standaert (Eds.), Vol. 12696. Springer,Heidelberg, Germany, Zagreb, Croatia, 147-176. https://doi.org/10.1007/978-3-030-77870-56

[22] Somayeh Heidarvand and Jorge L. Villar. 2009. Public Verifiability from Pairings in Secret Sharing Schemes. In SAC 2008: 15th Annual International Workshop on Selected Areas in Cryptography (Lecture Notes in Computer Science), Roberto Maria Avanzi, Liam Keliher, and Francesco Sica (Eds.), Vol. 5381. Springer,Heidelberg, Germany, Sackville, New Brunswick, Canada, 294-308. https://doi.org/10.1007/ 978-3-642-04159-419

[23] Stanislaw Jarecki and Anna Lysyanskaya. 2000. Adaptively Secure Threshold Cryptography: Introducing Concurrency, Removing Erasures. In Advances in Cryptology-EUROCRYPT 2000 (Lecture Notes in Computer Science), Bart Preneel (Ed.), Vol. 1807. Springer, Heidelberg, Germany, Bruges, Belgium, 221-242. https: //doi.org/10.1007/3-540-45539-616

[24] Mahabir Prasad Jhanwar. 2011. A PracticaI (Non-interactive) Publicly Verifiable Secret Sharing Scheme. In Information Security Practice and Experience (ISPEC), Vol. 6672. Springer, 273-287.

[25] Mahabir Prasad Jhanwar,Ayineedi Venkateswarlu, and Reihaneh Safavi-Naini. 2014.Paillier-based publicly verifiable (non-interactive) secret sharing. Designs, Codes and Cryptography,Volume 73,2(2014),529-546.

[26] Kartik Nayak. 2023. https://decentralizedthoughts.github.io/2023-01-05-player-replaceability-II/.(2023). https://decentralizedthoughts.github.io/2023-01-05-player-replaceability-II/

[27] Kartik Nayak. 2023. Player Replaceability - Towards Adaptive Security and Sub-quadratic Communication Simultaneously (Part I). (2023). https: //decentralizedthoughts.github.io/2023-01-05-player-replaceability-I/

[28] Pascal Paillier. 1999. Public-Key Cryptosystems Based on Composite Degree Residuosity Classes. In Advances in Cryptology-EUROCRYPT'99(Lecture Notes in Computer Science), Jacques Stern (Ed.), Vol. 1592. Springer, Heidelberg, Germany, Prague, Czech Republic, 223-238. https://doi.org/10.1007/3-540-48910-X16

[29] Alexandre Ruiz and Jorge L. Villar. 2005. Publicly verifiable secret sharing from paillier's cryptosystem. In WEWoRC 2005 - Western European Workshop on Research in Cryptology, Christopher Wulf, Stefan Lucks, and Po-Wah Yau(Eds.). Gesellschaft für Informatik e.V., Bonn,98-108.

[30] Philipp Schindler, Aljosha Judmayer, Nicholas Stifter, and Edgar R. Weippl. 2020. HydRand:Efficient Continuous Distributed Randomness. In 2020 IEEE Symposium on Security and Privacy. IEEE Computer Society Press, San Francisco, CA, USA, 73-89.https://doi.org/10.1109/SP40000.2020.00003

[31] Berry Schoenmakers. 1999. A Simple Publicly Verifiable Secret Sharing Scheme and Its Application to Electronic.In Advances in Cryptology-CRYPTO'99(Lecture Notes in Computer Science), Michael J. Wiener (Ed.), Vol. 1666. Springer, Heidel-berg, Germany, Santa Barbara,CA, USA, 148-164. https://doi.org/10.1007/3-540-48405-110

[32] Victor Shoup. 1997. Lower Bounds for Discrete Logarithms and Related Problems. In Advances in Cryptology-EUROCRYPT'97 (Lecture Notes in Computer Science), Walter Fumy (Ed.), Vol. 1233. Springer, Heidelberg, Germany,Konstanz,Germany, 256-266.https://doi.org/10.1007/3-540-69053-018

[33] Markus Stadler. 1996. Publicly Verifiable Secret Sharing. In Advances in Cryp-tology-EUROCRYPT'96 (Lecture Notes in Computer Science), Ueli M. Mau-rer (Ed.), Vol. 1070. Springer, Heidelberg, Germany, Saragossa,Spain,190-199. https://doi.org/10.1007/3-540-68339-917

[34] MMaofan Yin, Dahlia Malkhi, Michael K. Reiter, Guy Golan-Gueta, and Ittai Abra-ham. 2019. HotStuff: BFT Consensus with Linearity and Responsiveness. In 38th ACM Symposium Annual on Principles of Distributed Computing, Peter Robin-son and Faith Ellen (Eds.). Association for Computing Machinery, Toronto,ON, Canada, 347-356. https://doi.org/10.1145/3293611.3331591

<!-- 1804 -->

