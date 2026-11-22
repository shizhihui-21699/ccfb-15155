# keyhunt — 内存镜像密钥取证工具

从被勒索软件加密过的服务器的内存镜像中寻找密钥：识别常见对称加密算法的
**展开密钥结构**（key schedule）与非对称私钥结构，在内存有损坏/换页时尽量
还原完整密钥，并用找到的候选密钥**实际解密样本文件**来证明结果。

几十 GB 的镜像中随机数据会产生海量假阳性，因此本工具遵循一条原则：

> **宁可少报，不可错报。** 每个报告出来的密钥都必须能真实解密样本；结构性
> 命中（如完整的 AES key schedule）视为强证据，但没有样本验证时不当作"证明"。

## 快速开始

```bash
cmake -B build -DOPENSSL_ROOT_DIR=$(brew --prefix)   # 需要 OpenSSL 3/4
cmake --build build -j

# 对镜像取证，样本文件用于验证
./build/keyhunt scan memory.raw \
    --sample locked.docx --sample locked.pdf \
    --jsonl findings.jsonl --outdir recovered/

# 只扫某个物理内存区间（先做少量样本，快速确认）
./build/keyhunt scan memory.raw --range 0x1a000000-0x2a000000 --sample locked.pdf

# 单独的候选密钥验证（无需重扫镜像）
./build/keyhunt verify --key aes-256:<hex> --sample locked.pdf
```

`--outdir` 下会以 `0600` 权限导出可用的 `*.key` / `*.pem` 与元数据。

## 设计要点

### 1. AES key schedule 的代数结构

内存里几乎不会留着原始 AES 密钥，而是实现写入的**轮密钥数组**（OpenSSL
`AES_KEY.rd_key[]`、mbedTLS `aes_encrypt_ctx.rk[]`、Go 的堆上 `enc []uint32`、
RustCrypto 的 round-key 数组都是同一形状）。本工具对 OpenSSL 4.x 逐位验证了
这些恒等式：

设 P = nk（4/6/8），加密 schedule 满足

| 条件 | 关系 | 用途 |
|------|------|------|
| `i%P ∈ {1,2,3}`（256 位还含 `{5,6,7}`） | `w[i] == w[i-P] ^ w[i-1]` | 96 位线性预过滤，3 次 XOR |
| `i%P == 0` | `w[i] == w[i-P] ^ SubWord(RotL8(w[i-1])) ^ (rc[i/P]<<24)` | 4 次 S 盒查表，把命中变成**证明** |
| `i%P == 4`（仅 256 位） | `w[i] == w[i-P] ^ SubWord(w[i-1])` | 同上 |

解密 schedule（OpenSSL `AES_set_decrypt_key` 产出）同样满足内部块的
`d[i] == d[i+4] ^ d[i-1]`（`i%4 != 0`）。

**关键**：这些关系全部可逆。只要有一段（甚至带空洞的）连续轮密钥，就能反推
回 `w[0..P-1]` —— 也就是原始密钥。这就是"内存损坏仍能还原"的基础：
`aes_reconstruct_enc()` 在正反两个方向反复传播已知量，再用完整展开回验。

检测采用**稀疏种子**策略而不是逐窗口尝试：线性关系在随机数据下每字命中概率
是 2⁻³²，所以候选起点（schedule 开头只可能出现在命中点前 1..P 个位置）几乎
为空。对每个候选做完整展开比对；对受损 schedule 则用掩码重建 + 独立回验
（只用 `i>=nk` 的存活字比对，避免自证）。

### 2. 裸密钥与样本驱动扫描

原始密钥没有任何结构可识别。唯一的诚实检测器是密文本身。给定样本和已知明文
前缀（文件魔数），候选密钥 K 的正确性是**一次 AES 块运算**：

```
CBC, IV 前置 : D_K(C[16..32]) == P0 ^ IV
CBC, 零 IV   : D_K(C[0..16])  == P0
CTR, IV 前置 : E_K(IV)        == P0 ^ C0
ECB          : D_K(C[0..16])  == P0
```

比较 ≥8 字节时假阳性概率 ~2⁻⁶⁴。因此 `sweep_raw_keys()` 可以**扫遍整幅镜像
每个 4 字节对齐窗口**而不产生噪声；每个窗口只做一次密钥扩展，然后批量跑
4 个探针块。这就是"几十 GB 也可行"的关键：哈希表式的结构预过滤对裸密钥无效，
但一次块运算就足够了。

### 3. 非对称私钥

- **DER/BER 解析器**（`der.cpp`）识别 PKCS#1 RSAPrivateKey、PKCS#8（RSA/EC/
  Ed25519/X25519/DSA）、SEC1 ECPrivateKey、EncryptedPrivateKeyInfo（PBES1/
  PBES2/scrypt）、PKCS#12 PFX、X.509、OpenSSH `openssh-key-v1`、PEM。
- **容错解析**：长度字段损坏时按剩余缓冲区继续；整数按长度/位置重锚定。
- **RSA 恢复**：`(n,e,d)` 齐全但缺 p/q 时，用 `e·d-1 = 2^t·r` 的经典算法分解
  n；只有 `(p,q)` 时重算 d 和 CRT 参数；每个字段做算术验证（n==p·q、
  e·d≡1、素性检验）。
- **加密容器**：`--dict` 提供口令表，用 OpenSSL 实际尝试解密 PKCS#8/PKCS#12，
  成功即报告口令。

### 4. 流式、多线程、超大镜像

- `mmap` 全文件，按 `--chunk`（默认 64 MiB）分块，块间 `--overlap` 重叠，
  结构跨块不会被漏；用分块归属 + 去重集合消除重复报告。
- 线程池按核数并行，进度写 stderr。
- 内存占用与镜像大小无关（只有 mmap 的只读页）。

## 测试镜像生成器

`keyhunt-genimg` 构造一个可信的内存镜像，包含：

| 类别 | 内容 |
|------|------|
| AES | 128/192/256 加密 schedule、OpenSSL 解密 schedule、被清零若干字的受损 schedule |
| 裸密钥 | 32 字节原始 AES 密钥、ChaCha20 块状态 |
| 非对称 | RSA-2048 PKCS#1/PKCS#8/PEM、RSA-1024 仅 n/e/d、EC P-256/secp256k1 SEC1+PEM、Ed25519/X25519 PKCS#8+PEM、DSA、加密 PKCS#8、PKCS#12 |
| 干扰 | 高熵随机块、外形像 DER 但无效的序列、零页、0xAA 填充、ASCII 日志页 |

并生成一个用其中一个密钥 CBC 加密的样本文件，供验证链使用。清单 JSON 记录
每个植入结构的偏移与类型，评估脚本据此计算召回率与精确率。

```bash
./build/keyhunt-genimg -o image.raw -m image.json --mib 512 --sample locked.pdf
python3 scripts/evaluate.py --mib 512 --threads 13
```

`evaluate.py` 输出各类结构的召回率、非对称容器识别情况、以及"被样本证明"的
密钥；`keyhunt-e2e` 作为 CTest 用例在 24 MiB 镜像上做端到端断言。

## 结果（512 MiB 合成镜像，13 线程）

- AES schedule（含受损）：**12/12** 找回（受损者从存活段重建）
- ChaCha20 状态：**1/1**
- 非对称容器：13 个中 **12** 个识别（3 个加密容器需口令；`--dict` 可解）
- 误报：结构性检测 **0**；裸密钥扫描靠密文证明，同样 **0**
- 吞吐（512 MiB / 13 线程）：纯结构扫描 4.1 s（约 130 MB/s）；带样本的裸
  密钥扫描 11.6 s（约 46 MB/s，即 ~160 GB/小时）。单线程遍历裸密钥约
  8.9 MB/s，多核线性扩展。

## 已知限制

- 裸密钥扫描需要样本 + 可猜测明文前缀（文件魔数）。没有样本时，只有结构
  化的 schedule 可被找回——这也是诚实的边界。
- 受损 schedule 的恢复需要至少 `nk+2` 个存活轮密钥字。
- 加密私钥需要口令在字典中；不做暴力破解。
- 仅建模了 OpenSSL 的内存布局（big-endian 字序在加载时等价，已验证）；其他
  实现的 schedule 若顺序/字节序不同，线性关系仍成立（XOR 与字节置换可交换），
  非线性步骤的两字节序变体由验证器覆盖。

## 命令行参考

```
keyhunt scan <image> [options]
  --range <start-end>  只扫指定区间（hex 或十进制，可重复）
  --sample <file>      用于验证的密文样本（可重复）
  --key <cipher:hex>   额外测试给定密钥
  --dict <file>        加密私钥口令字典
  --outdir <dir>       导出可用密钥到 <dir>/keys（0600）
  --jsonl <file>       机器可读逐行 JSON
  --report <file>      人类可读报告（默认 stdout）
  -t, --threads <n>    线程数（默认 核数-1）
  --chunk <size>       分块大小，支持 K/M/G 后缀（默认 64M）
  --all                输出未验证候选
  --raw                启用高熵裸密钥启发式（噪声大，默认关闭）
  --no-asym            跳为非对称检测
```
