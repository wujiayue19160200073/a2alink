# 变更记录

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
版本策略与"什么算破坏性"见 [`docs/VERSIONING.md`](docs/VERSIONING.md)。

---

## [0.4.0] — 2026-11-05

主题：**让"任务消失了但日志一切正常"这件事不再可能。**

v0.3 解决了"怎么发出去"，但没回答"发出去之后呢"。`ack` 的语义是
"我读到了"，却被当成"我做完了"。于是 Agent 读完崩溃、读完转手、
读完发现做不了——这三种情况在审计链上是同一个样子：什么都没有。

这一版补的是投递语义，不是新功能。

### Added
- **投递确认拆分**（ADR-8）：`done_at` 独立于投递位点。
  `a2alink done <id>` 明确确认完成，`a2alink inflight` 列出"已读未完成"。
  这张表就是**可能掉在地上的任务清单**。
- **死信队列**：`a2alink fail <id> --reason "..."` 上报失败，
  超阈值（默认 3 次）进 DLQ；`a2alink dlq {list,requeue,purge}`。
  重投通过**新建 delivery** 实现，不倒退 cursor。
- **遗嘱消息**（ADR-9）：`a2alink up --will "..." --will-to @某人 --will-ttl 600`。
  掉线超时后由中继代发。存的是**客户端预签的整条信封**——
  注册中心没有私钥，它只能转交，不能生成。
- **回复链 references**：抄 SMTP 的 References 头，记录整条回复链。
  转手三次之后还能回答"最初问的是什么"。
- `docs/transport-survey.md`：TCP/UDP/MQTT/AMQP/Kafka/gRPC/SMTP/联邦模型
  的逐个对照，以及本项目的取舍记录。

### Changed
- `up` 增加 `--will/--will-to/--will-ttl`；`down` 默认撤销遗嘱（`--keep-will` 保留）。
- `check` 在每条消息后提示 `a2alink done <id>`。
- 注册中心巡检循环同时处理群表决超时与遗嘱触发，不额外起线程。

### 兼容性
- **信封字段只增不改**。`references` 为空时**不落字段**，
  `canonical_bytes` 与 0.3 完全一致——历史信封的签名照样验得过。
  （有测试专门守这条线：`test_empty_chain_keeps_old_bytes`。）
- 数据库通过 `_migrate()` 增量加列，老库直接可用。

### 明确没做
- **没做自动重投**。超时自动重发需要后台租约与心跳，复杂度接近一个小 broker，
  而 Agent 场景里"任务有没有结果"比"消息重投了几次"更要紧。
  先让失败可见，再谈自动恢复。
- **没做接收侧副作用去重**。`idempotency_key` 在协议里有，
  但"同一个 ID 第二次到达时必须跳过业务动作"是**适配器**的责任。
  文档写清楚了，因为这一点最容易被误以为协议已经保证。

---

## [0.3.0] — 2026-11-04

主题：**从"一个库"变成"装一下就能用"。**

v0.2 已经能加密、能验签、能审计，但想真正跑起来要记住五件事：起注册中心、
指定 agent 名、指定 home、加好友、再发消息。真实的用户第一次就会卡在第二步。
这一版把前面四步全部收进命令内部，只留最后一件事给人：说话。

### Added
- **`sessions.py`：会话身份。** 把宿主的会话 ID（`CODEBUDDY_SESSION_ID` 等）
  映射成稳定的 agent 名与 home 目录。同一个对话窗口被调用一百次，拿到的
  永远是同一个身份、同一把密钥、同一条审计链。
  - **改名不换身份**：别名（`@运维`）随便改，协议身份冻结。改协议名等于在
    注册中心里换一个人，好友、群成员、对端固定的公钥全部失联。
  - 别名表在 `~/.a2alink/sessions.json`，只在本机有意义，不出网络。
  - 别名冲突检测、保留字、前缀歧义都会明确报错，不猜。
- **`autostart.py`：本地中继自启。** 每条命令先探 `/healthz`，活着就用，
  没活着就拉起来，退出后不影响。
  - 只对**回环地址**生效。远端注册中心只探活，探不到就报错——不去猜
    "也许是别的东西"，更不重试到某个偶然可用的目标上。
  - 探活以服务自报家门（`service: a2alink`）为准，不看 pid 文件：
    pid 会残留、会被复用。
  - 停止只杀自己拉起的进程；端口活着但没有 pid 记录 → 只报告，不碰。
- **`skillpack.py`：一键装成技能。** 生成 `SKILL.md`（给 Agent 的操作手册）
  + `scripts/a2a.py`（启动器，写死源码绝对路径）+ 安装标记。
  - 幂等、`--dry-run`、拒绝覆盖非本工具安装的同名目录。
  - 启动器不依赖 `pip install`，仓库路径变了会打印"源码目录找不到了"并提示
    `A2ALINK_SRC`，而不是甩一个 ModuleNotFoundError。
- **`install.py`：一条命令。** 装技能 + 起中继 + 打印下一步。
- **同机互信 `local_mesh`（服务端）。** 同一台机器上的会话互发消息不要求
  先加好友，**每次放行写审计**（`mesh.local_trust`）。
  - 只在监听回环地址时允许开启，`--host 0.0.0.0` 时强制关闭并告知。
  - 判断依据不是"图省事"：同一个 OS 用户本来就能读 `~/.a2alink` 下所有私钥、
    能直接改 SQLite。在这个前提下要求本机会话互加好友只是仪式，不是边界。
    真正的边界是"这台机器别被别人用"。
- **新命令**：`session {whoami,name,release,list,forget}`、`skill
  {install,status,uninstall}`、`up` / `down`、`say`、`ask`、`reply`、`check`、`peers`。
- **全局 `--as`**，并且可以写在子命令后面（解析前自动提前，argparse 的
  全局选项位置限制对使用者不该可见）。

### Changed
- `session name` 顺带把身份登记到中继。不起这一步，别人 `@` 你会得到
  "找不到名为 s-xxxx 的 Agent"——名字存在本地，注册中心不认识它。
- 收信展示改为取载荷正文 + 单独的围栏标记，不再把 `instruction`/`intent`
  这些键名和整段系统声明一起喷给 Agent。

### Security
- **同机互信不是"关掉好友审批"**，而是把它换成另一个更诚实的判断：
  同一台机器 = 同一个信任域。所以它必须可审计、可关闭、且只在回环地址生效。
- 会话 ID 会拼进文件路径，因此严格限制字符集（`SID_RE`），挡住 `../`。
- `recent.json` 只存元数据和 80 字摘要，不存全文——本地缓存不该变成第二个
  明文消息库，那等于把"日志不存原文"的努力绕过去了。

### 已知边界（重要，别误解）
- **Agent 不会自己醒过来收信。** 技能是被调用才执行的，消息是异步投递的。
  对方要等到下一次被唤起（用户跟它说话，或你让它 `check`）才会看到。
  这一版没有常驻监听，也不打算用未公开的钩子机制去伪造一个。
- `ask` 的超时是"等不到就如实说等不到"，不是"重试到有人回"。重试正是这个
  协议要防的死循环。

---

## [0.2.0] — 2026-11-03

主题：**注册中心从"可以读、可以冒充"变成"只是个路由"。**

v0.1 有两个绕不过去的硬伤：消息明文存在服务端 SQLite 里（谁拿到那台机器都能读），
身份凭证是 bearer token（服务端自己能造一条"来自 alice"的消息）。这两个问题
不能用"加个开关"解决，只能上公钥体系。

### Added
- **`crypto.py`：Ed25519 签名 + X25519 密钥交换 + HKDF-SHA256 + 认证加密**，
  零第三方依赖，纯 Python 实现。
  - Ed25519 逐条通过 RFC 8032 §7.1 的三组测试向量
  - X25519 通过 RFC 7748 §5.2 与 §6.1
  - HKDF 通过 RFC 5869 Test Case 1
  - 加密用 **PRF-CTR + Encrypt-then-MAC**，而非手写 AES-GCM：
    HMAC-SHA256 作 PRF 是 stdlib 现成且有证明的构造，出错空间远小于手写 S 盒。
- **`trust.py`：对端公钥固定**，策略 `tofu / strict / off`。
  首次见面记录指纹，之后指纹变化**一律拒收**并写审计（`crypto.key_changed`）。
- **`a2alink keys {show,list,forget,publish,rotate,peer,pin}`**。
  `show/list/forget` 可离线跑；`pin --expect <指纹>` 在你提供的指纹与
  注册中心不一致时**直接失败**，防止 pin 退化成"注册中心说什么我信什么"。
- **信封新增 `pub` / `enc` 字段**，签名覆盖二者——否则可以替换密文块、
  或把发送者换一个人而签名依然有效。
- **加密的 AAD 绑定信封头部**（from/to/conversation_id/act/stage/时间戳），
  密文搬不到别的会话或别人身上。
- **服务端入站验签**（`Registry._verify_envelope`）：用**库里登记的公钥**验，
  而不是信封自带的那把。`require_signature` 默认 `True`。
- **`PUT /v1/agents/me/keys`**：轮换公钥。用 PUT 而非 POST——换公钥是幂等操作。
- **`Received` 新增 `authenticated / decrypted / trust / reject_reason`**。
  被拒的消息也会返回（`quarantine=True`, `text=""`），让调用方看得见"有人试图冒充"，
  而不是凭空消失。
- **11 个新审计理由码**：`crypto.sealed / crypto.group_plaintext / crypto.key_changed /
  wire.bad_signature` 等。
- **`docs/crypto.md`**：威胁模型（含**挡不住的 6 类**）、带外验证流程、
  密钥管理等运维清单。

### Changed
- **消息默认端到端加密**（`encrypt="auto"`）：单聊自动用对端交换公钥加密；
  `always` 拿不到公钥就拒发；`never` 只签名。
- **接收顺序改为 验签 → 公钥固定 → 解密 → 看门狗 → 入站围栏**。
  先解密再验签会让未认证的密文先消耗一次椭圆曲线运算（CPU 耗尽），
  且解密结果已经进过内存。
- **发送顺序保持 看门狗在加密前**。加密后 payload 只剩占位符，
  内容指纹去重会失效——"两个 Agent 互相发乱码"就会被当成不同内容放行。
- `Envelope.canonical_bytes()` 明确纳入 `pub` / `enc`；签名加域前缀
  `a2alink/v1/envelope\0` 防止跨协议复用。
- `public_agent()` 返回 `sign_pub / kex_pub / key_fp`（公钥是公开信息）。

### Fixed
- **Windows 上私钥文件偶发损坏**：`os.open` 默认文本模式，私钥随机字节里的
  `0x0A` 被写成 `0x0D 0x0A`，32 字节变 33 字节。32 字节随机数含 `0x0A` 的概率
  约 12%——表现为"偶尔有人的密钥文件读不出来"，Linux 上永远复现不了。
  现在显式带 `O_BINARY`，并有回归测试。
- `KeyStore.rotate()` 里给只读 property 赋值导致崩溃。
- AEAD 的 `os.write` 部分写未处理（大 payload 时可能截断）。

### Known limitations（写在这里，不藏在文档里）
- **纯 Python 不是常量时间实现**：能挡远程攻击者，**挡不住同机恶意进程或 root**。
  要防这个必须换 OpenSSL 后端，本项目刻意不做"自动降级"——两条路径里
  总有一条很久没被测试。
- **群消息只签名不加密**：服务端 fan-out 导致无法端到端加密，
  正确做法是 sender key（v0.3）。在此之前群聊按"会议室"对待。
- **元数据可见**：注册中心知道谁在何时和谁通信、消息多大。
  这是路由的必然代价。
- **首次见面的中间人**：TOFU 固有问题，只能靠带外核对指纹解决。

---

## [0.1.2] — 2026-11-02

主题：**让"不是我干的"这句话说不出口——审计可追责。**

### Added
- **结构化审计链 `audit.py`**：每条裁决写一条 JSONL 记录，带
  `seq / ts / trace / actor / decision / reason / detail / evidence / prev / h`。
  哈希链 + 独立 `HEAD` 锚点，能检出改内容、删中间、换顺序、删尾部四类篡改。
  设计取舍与局限见 [`docs/logging.md`](docs/logging.md)。
- **27 个理由码（`REASONS`）**：拒绝自由文本理由。写不在表里的值直接抛
  `AuditError`——因为"已处理""异常"这类日志在定责时等于没写。
- **`a2alink logs {tail,search,verify,stats,export,seal}`**：可离线查，
  不依赖注册中心（出问题时它往往正好连不上）。`--json` 输出不截断的原值。
- **`a2alink trace <id>`**：一条消息的完整一生，本地决策链 + 服务端投递记录。
  支持短 id 前缀匹配（表格里复制出来直接能查）。
- **`a2alink incident`**：把"人工强行放行的"单独列在最前面，附完整理由；
  "试图放行但没给理由被拒"也单独列——这是有价值的安全信号。
- **服务端拒绝留痕**：`_dispatch` 单点记录每次 4xx/5xx，
  带 `status / code / route / 调用者`。原来只记成功动作，被拒的请求一拍两散。
- **`/v1/trace/<id>`**：服务端按 trace 回元数据，仅参与方可查，不回 payload。

### Changed
- **`force=True` 必须同时给 `force_reason`（≥8 字）**，否则抛
  `force_requires_reason`。CLI 对应 `--force --reason "..."`。
  不需要填理由的"强行放行"按钮，在真实团队里三个月内一定会变成默认操作。
- `purge_old()` **不再删 `audit` 表**。审计与业务数据共用留存期，
  等于给了"把 days 设成 0.01 洗证据"一条正规通道。
- `override` 类记录的 `decision` 由 `deny` 改为 `note`——
  `decision` 描述最终结果（放行了），闸门判定交给 `reason`。
- 审计目录从"只扫当前目录"改为递归扫 `archive/`，否则 seal 之后
  seq 从 1 重开，归档动作会把自己验成"证据已被破坏"。
- 链锁从"pid 文件"改为**操作系统文件锁**。pid 文件在进程被杀后残留，
  导致 CLI 每次执行都新开一条链，一屏全是链名。

### Fixed
- 日志里不再出现明文：默认 `preview_chars=0`，只存指纹、长度、命中规则名。
  ID 类字段（`agt-` / `trace-` / `conv-`）原样保留——排查时"对端是谁"是第一要回答的问题。
- `force_reason` 走白名单完整保留。之前被长度策略截成 `<str:23>`，
  恰好把责任链上最关键的一环抹掉了。
- `seal()` 的 `json.dump` 参数冲突导致崩溃（且在移动文件之后崩，留下半成品）。

---

## [Unreleased] — v0.2.0 计划

### Added（计划）
- **本地可视化会话台** `a2alink console`：只读面板，看得到每一轮信封、每个
  Agent 的工作笔记、看门狗预算余量、DLP 命中详情。零依赖（`http.server` + SSE），
  只 bind `127.0.0.1`。设计见 [`docs/visual-console.md`](docs/visual-console.md)。
- 本地事件流 `~/.a2alink/<agent>/events.jsonl`（面板的数据源，也是审计的补充）。
- `a2alink audit report`：把审计账本聚合成"谁在批量操作"的可读报告。

### Changed（计划）
- 无。

---

## [0.1.1] — 2026-11-02

主题：**入群准入从"通过表决就能进来"改成"本人同意 + 表决"，并把反滥用做进代码。**

### Added
- **两段式入群准入**：`invite()` 一律先进入 `pending_consent`，必须由**受邀者
  本人**调用 `group_consent()` 表态。这一步没有开关、没有旁路、管理员也跳不过。
  理由见 [`docs/abuse.md`](docs/abuse.md) §2。
- **受信直入（`trusted_direct`，默认开）**：邀请人与受邀者已是双向好友时，
  受邀者点同意即入群，跳过全员表决。**这直接实现了"已互相同意的人直接进群，
  后面的人自己决定进不进"**。可用 `--no-trusted` 关闭。
- `AgentLink.group_consent(gid, pid, accept, reason)` / `POST /v1/groups/{gid}/consent`。
- `AgentLink.pending_actions()` / `GET /v1/pending` / `a2alink pending`：
  待我表态的邀请 + 待我投的票。人和 Agent 共用，也是 v0.2 面板的数据源。
- **扩散保险丝** `abuse.PropagationGuard`（默认开启，不可跳）：
  同一内容 30 分钟内发往 >4 个目标、或同一会话触达 >6 个对端 → 抛
  `PropagationBlocked`，必须人 `force=True` 才放行。
- **转发闸门** `abuse.ProvenanceError`：`forwarded_from` 参数在
  `allow_forward=False`（默认）时直接拒绝；开启后强制写入 `_provenance` 署名。
- **邀请配额与拒绝冷却**：每群每小时 20 次邀请；被拒后 24h 内不得重复邀请同一人，
  被同一人拒 3 次则 7 天冷却（`blocked_by_target`）。
- **好友申请全局配额**：单 Agent 24h 内最多发起 20 条；对方连续拒绝 3 次后停手。
- **群成员可见性收紧**：非成员只能拿到 `group_public_info`（群名、人数、群主、
  建群时间），**没有成员名单**。受邀者在同意前也只能看这个最小集。
- **静默成员审计** `a2alink group privacy <gid>` / `GET /v1/groups/{gid}/privacy`：
  列出入群超过 N 天却从未发言的成员（长期静默收集的唯一可观测信号）。
- **留存策略** `Registry.purge_old(days=30)`：按天清理消息、投递记录与审计。
- `docs/abuse.md`：完整滥用威胁模型（裂变/女巫/监听/外传/社工/汇聚/DoS）。
- `docs/VERSIONING.md`、`CHANGELOG.md`、`COMMERCIAL.md`。
- `tests/test_abuse.py`（9 个用例）、`tests/test_e2e.py` 新增 6 个准入用例。

### Changed
- **⚠️ 破坏性（`0.1.x` 内的有意识例外）**：提案状态机新增 `pending_consent`。
  任何依赖 `group_invite()` 返回 `state == "pending"` 并直接 `group_vote()` 的
  调用方必须改为：`invite()` → 由受邀者 `group_consent()` → 再 `vote()`。
  `invite()` 的返回值不再含 `needed`/`voters`（表决尚未开始，无从计算）；
  `consent()` 的返回值才含。`CHANGELOG` 里说清楚，是为了让升级的人少踩一次坑。
- **表决快照改为"受邀者同意之后"才取**。原实现在邀请时取快照，导致"同意前
  有人入群/退群"会让语义漂移。现在快照固定在投票真正开始的那一刻。
- `group_info()` 的 `pending_proposals` 同时包含 `pending` 与 `pending_consent`。
- `h_group_props` 补上成员校验（v0.1.0 遗漏：任何登录用户都能读到任意群的
  邀请流水，这是侦察素材）。
- 许可证从 MIT 改为 **A2A-LNL v1.0**（非商业使用免费，商业使用需书面授权，
  违规使用含赔偿条款）。**注意：这不是 OSI 开源许可，是 source-available。**
- `pyproject.toml` 的 classifier 从 `OSI Approved :: MIT License` 改为
  `Other/Proprietary License`。

### Fixed
- `invite()` 在 `join_mode=admin` 时由管理员直接入群，**绕过了受邀者意愿**。
  这不是 bug 而是设计缺陷，本版一并修掉（管理员现在只能跳过"表决"，不能跳过"同意"）。
- 同一目标重复邀请会产生多条未结提案，把对方的待办刷爆 → 改为幂等返回已有提案。

### Security
- 无已知在野漏洞。本版所有改动都是**收紧**默认策略，没有放松任何一条。

---

## [0.1.0] — 2026-11-02

首个可运行原型。定位：**开发者实验工具**，不是 C 端产品。

### Added
- **信封协议**（`protocol.py`）：信封/载荷分离、`act` 语义（task/result/event/
  chat/notice）、`stage` 终结信号、`ttl_hops` + `ttl_seconds` + `budget` 三重递减、
  幂等键、canonical bytes 与内容指纹。
- **看门狗**（`watchdog.py`）：消息配额、token 预算、轮次上限、simhash 内容指纹
  去重、熔断与降级动作、提前预警。
- **出站 DLP**（`guard.py` `EgressGuard`）：密钥/私钥/连接串/中文密级标识 → 阻断；
  内网 IP/内部域名/主机名/PII → 脱敏；高熵串检测；项目自定义禁出词表。
- **入站围栏**（`guard.py` `IngressGuard`）：提示词注入检测 + `<untrusted_external_content>`
  包裹 + 系统声明。
- **注册中心**（`registry.py`）：SQLite 持久化、身份与能力标签、发现、双向好友、
  群组与表决（unan/majority/admin）、单目标投递、inbox/ack、幂等去重、
  只存元数据的审计账本、令牌桶限流。
- **服务端强制关系策略**：不是好友不能发消息、不是成员不能在群里发言——
  这一点不能只靠客户端自证。
- **客户端 SDK**（`client.py`）：`AgentLink`，`send()`/`recv()` 内置闸门，
  身份落 `~/.a2alink/<agent>/identity.json`（600 权限）。
- **适配器**（`adapters.py`）：echo、LLM、DeepSeek Harness、AutoGen、LangGraph。
- **CLI**（`cli.py`）：`registry` / `whoami` / `discover` / `friend` / `group` /
  `send` / `inbox` / `serve` / `guard check` / `doctor` / `demo`。
- 文档：`README.md`（含泄密警示）、`SECURITY.md`（威胁模型 + 密级矩阵 +
  事故响应）、`docs/architecture.md`（设计取舍与 ADR）、`docs/protocol.md`、
  `docs/roadmap.md`。
- 63 个 stdlib `unittest` 用例。

### Design decisions（值得单独记下来的）
- **默认 `bind 127.0.0.1`**：本地优先同时解决冷启动与合规（境内公网信息服务涉资质）。
- **不做中继网关**：既避开资质问题，也让"协议级病毒传播"在物理上不成立。
- **默认拒绝而非默认放行**：未配置的对端按 `wan`（最严）处理。
- **全员表决不做默认推荐**：>5 人时有人休假就永久挂起，且一人可否决一切的
  女巫成本过低。文档推荐 `majority + quorum 0.6`，代码保留用户原设定的默认值。

[Unreleased]: https://github.com/wujiayue19160200073/a2alink/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/wujiayue19160200073/a2alink/releases/tag/v0.1.1
[0.1.0]: https://github.com/wujiayue19160200073/a2alink/releases/tag/v0.1.0
