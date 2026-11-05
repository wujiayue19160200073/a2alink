# 多平台分发：代码放到哪里，谁是权威

**结论先给：只放三个地方。GitHub 是唯一的权威仓库，其余是只读镜像。**

不是为了摆得好看，是因为**每多一个镜像，就多一个会漂移、会分裂讨论、
会变成"另一个真相"的地方**。三个已经是上限。

| 平台 | 定位 | 为什么 | 状态 |
|---|---|---|---|
| **GitHub** | **权威源** | 唯一接受 Issue / PR / Release / 安全报告的地方 | ✅ 已上线 |
| **Gitee** | 只读镜像 | 国内直连可达。这是唯一的实质增量 | ⏳ 待本人实名后建仓 |
| **GitLab.com** | 只读镜像 | 不少公司内网只允许从 GitLab 拉依赖 / 做 fork 基线 | ⏳ 可选 |
| ~~Codeberg~~ | **排除** | 见下一节，**规则上不允许** | ❌ 不可行 |
| ~~Bitbucket~~ | 排除 | 国内访问差，功能无增量，多一个维护点 | ❌ 不划算 |
| ~~GitCode / AtomGit~~ | 暂不纳入 | 同样要实名 + 内容审核，生态与镜像工具未稳定 | ⏸ 观望 |

---

## 一、Codeberg 走不通，原因不是偏好

Codeberg 的服务条款写得很直白（§ 1(2)、§ 2(1)）：

> Our service is open for all projects covered by a free software or open source
> licence, as defined by either the Free Software Foundation (FSF) or the
> Open Source Initiative (OSI).
>
> Repository content shall be licensed under an open-source license approved by
> the Free Software Foundation or the Open Source Initiative.

本项目的许可是 **A2A-LNL v1.0**，非商业许可，**不是 OSI 认可的开源许可**
（README 的"许可"一节已经写明，限制使用领域即不符合 OSD 第 6 条）。
它属于 **source-available**，不是 open source。

所以这不是"要不要投递"的问题，是**投过去就违反对方条款**。同一个页面还写着
Codeberg 不欢迎自动镜像（会把资源无限占用），只接受手动 `git push --mirror`。

**不要为了上架去改许可证。** 改许可换来的曝光，代价是"你说过的话以后不算数"——
一个安全工具的作者如果许可都能为渠道让步，那它的审计承诺也不值得信。

---

## 二、权威仓库条约（放上去之前先认这五条）

镜像一旦存在，就一定有人把它当成主仓库。这五条是防止分裂的最低成本：

1. **GitHub 是唯一权威。** 提交、合并、发版、Release 说明，只在 GitHub 发生。
2. **镜像一律只读**，且**关闭 Issue 功能**。不是"写了不接受但还在收"——
   那叫收了不看。Gitee / GitLab 都支持在仓库设置里关掉 Issue。
3. **镜像仓库描述第一句必须是**「只读镜像，请到 GitHub 提交」
   并放权威地址。别指望人点开 README 才知道。
4. **安全漏洞只认一个入口**：GitHub Security Advisory + `1980427975@qq.com`
   （见 [SECURITY.md](../SECURITY.md)）。镜像平台的 Security 面板不用、
   也不承诺看。**两个入口 = 两个都可能漏**。
5. **许可证不因分发平台改变。** 在任何平台 clone 到的都是 A2A-LNL，
   商用仍需授权。镜像页也要放 `LICENSE`（它本来就在仓库里，随镜像同步过去）。

> 第 4 条最容易做错。GitHub 有 Private vulnerability reporting，
> GitLab 有 Security Dashboard，Gitee 有安全扫描——三个都"能收"，
> 但你只有一双眼睛。写下"只认一个"比"我尽量都看"诚实得多。

---

## 三、凭据怎么给：别用一个 token 换一次省事

### 3.1 不推荐：Gitee 的「从 GitHub 自动镜像」功能

Gitee 支持 Pull 方向镜像（GitHub → Gitee），自动同步，最短间隔 5 分钟。
它需要你填一个 **GitHub Personal Access Token**，权限要求是
`repo`（**能读写你名下全部仓库，含私有仓库**）+ `admin:repo_hook`。

也就是说：**为了省掉一次 `git push`，你要把一把能打开你所有 GitHub
私有仓库的钥匙，存到另一个平台上。** 这个交换在任何安全评估里都不成立。

### 3.2 推荐：本地 `git push` + 每平台一把**单仓库部署公钥**

| 做法 | 泄露后的损失 |
|---|---|
| 账号级 SSH key 复用一把 | 攻击者可动你**所有**仓库，且在多个平台同时有效 |
| GitHub PAT 存到 Gitee | 可读**所有**私有仓库；token 通常还长期有效 |
| **单仓库部署公钥（deploy key）** | **只能写 `a2alink` 这一个仓库**，别的一概碰不到 |

所以：**Gitee 用「部署公钥」、GitLab 用「Deploy Key」，勾选写权限。**
不要加到账号级 SSH keys 里。

本机已经生成两把独立的密钥（不复用 GitHub 那把 `id_ed25519`）：

```
~/.ssh/id_a2alink_gitee      公钥 → Gitee 仓库 → 管理 → 部署公钥 → 勾"启用推送"
~/.ssh/id_a2alink_gitlab     公钥 → GitLab 仓库 → Settings → Repository → Deploy keys → 勾"Grant write permissions"
```

`~/.ssh/config` 已按 Host 分流，并加了 `IdentitiesOnly yes`
（不加这句，ssh 会把本机所有默认名密钥依次递给对方服务器试，
等于顺手把 GitHub 那把的身份也告诉了 Gitee）。

> Windows 上 `ls -l` 显示私钥是 644 是 MSYS 的显示假象，
> NTFS 靠 ACL 控制，OpenSSH 会自己校验。别为此反复折腾 `chmod`。

---

## 四、Gitee 的具体操作（需要本人做，Agent 碰不了账号）

### 4.1 先建**私有**仓库，不要一上来就公开

原因很实际：本项目主题是 **端到端加密 + 审计 + 泄密防护 + 反滥用**。
国内平台的公开仓库有内容审核，这类关键词的审核结果**不确定**——
不是"肯定过"也不是"肯定不过"。所以顺序是：

```
私有仓库 → 推上去 → 在网页上逐页看过一遍（README 渲染、文件树、许可页）
→ 确认没有渲染异常/误判 → 再改公开
```

一次到位去撞审核，被拦下时你连"是内容问题还是建仓问题"都分不清。

### 4.2 步骤

1. 注册并**完成实名认证**（Gitee 未实名时很多仓库功能不可用）
2. 右上角 `+` → 新建仓库
   - 仓库名 `a2alink`
   - **不要**勾「使用 Readme 初始化」「.gitignore 模板」「许可证模板」
     （理由同 [RELEASING.md](RELEASING.md) 第一节：远端会多出一个孤立提交）
   - 可见性先选**私有**
3. 仓库 → 管理 → **部署公钥** → 添加 `id_a2alink_gitee.pub` 内容 → 勾选「启用推送」
4. 本地加 remote 并推：

```bash
cd a2alink
git remote add gitee git@gitee.com:<你的Gitee用户名>/a2alink.git
git push gitee main
git push gitee --tags
```

5. 网页逐页检查 → 改公开 → 在仓库描述里写：
   `只读镜像｜请到 github.com/wujiayue19160200073/a2alink 提交 Issue 与 PR`
6. 设置里**关闭 Issue**（若不允许关闭，就在 README 顶部加显著提示，并真的不看）

### 4.3 Gitee 特有注意

- **HTTPS 与 SSH 的账号名可能不同**：Gitee 的 SSH 地址是
  `git@gitee.com:<个人空间地址>/a2alink.git`，那个"个人空间地址"是
  你注册时设的 URL 段，不一定等于登录手机号。
- **镜像最短同步间隔 5 分钟**（如果你后来改用官方镜像功能）；
  本项目用手动 push，没有这个延迟。
- Gitee 会显示"贡献者/提交统计"，从 GitHub 推过去的历史不会有归属问题，
  但如果你在意，可以接受它是镜像这一事实。

### 4.4 报 `Could not read from remote repository`

这是建镜像第一次推送最常见的失败，而且报错信息具有误导性——它让你去查
"仓库是否存在""权限对不对"，但真正的原因通常更简单。

**判据：读得到、写不了。**

```bash
git ls-remote gitee; echo "exit=$?"     # exit=0 且无输出 = 空仓库，但读取成功
git push gitee main                     # 报 Could not read from remote repository
```

两条一对比就能定性：

| 现象 | 原因 |
|---|---|
| ls-remote 失败 + push 失败 | 仓库地址错 / key 没加 / 账号不对 |
| **ls-remote 成功 + push 失败** | **部署公钥是只读的——添加时没勾「启用推送」** |

Gitee 的部署公钥默认只读。添加后权限一般不能改，**删掉重新添加，勾上「启用推送」**。
GitLab 的 Deploy Key 对应的是「Grant write permissions」复选框，同样默认不勾。

再确认 key 到底有没有被接受：

```bash
GIT_SSH_COMMAND="ssh -v" git ls-remote gitee 2>&1 | grep -iE "server accepts|denied"
# Server accepts key ← 认证没问题，问题在授权（权限），不在身份
```

---

## 五、GitLab.com（可选）

只有一种情况值得做：**你的目标使用者所在公司只允许从 GitLab 拉依赖**。

```bash
git remote add gitlab git@gitlab.com:<用户名>/a2alink.git
git push gitlab main && git push gitlab --tags
```

GitLab 免费版对仓库镜像的支持随套餐变动，**本项目不依赖它的镜像功能**，
一律按手动 `git push` 处理。少一个自动机制，就少一个无声失败的地方。

---

## 六、怎么知道镜像有没有落后

镜像最典型的失败不是"推不上去"，而是**推上去了但忘了这个平台**。
三个月后 Gitee 上还是 v0.5.0，而 GitHub 已经 v0.8.0——访问者拿到的
是一份既旧又"看起来一样"的代码。对安全工具，这比没有镜像更坏。

```bash
python tools/mirror.py status     # 每个平台落后多少提交、tag 是否齐、敏感文件自检
python tools/mirror.py push       # 自检通过才逐个推；不会自动 force
```

`status` 报漂移时，**第一件事是搞清楚为什么落后**，而不是直接 force 覆盖。
`--force` 需要你自己加：本项目不替你决定"抹掉远端那几个提交"。

---

## 七、明确不做的事

| 不做 | 原因 |
|---|---|
| 双向镜像 | Gitee 官方文档自己标注"双向镜像目前存在代码丢失的风险"。丢的是历史，不可恢复 |
| 在镜像上收 PR/Issue | 收在那里的东西等于放进一个你不看的抽屉 |
| 自动 `--force` 同步 | 会无声抹掉别人在你镜像上的提交。要 force 必须由人显式打 |
| 为过审改许可证 | 见第一节末 |
| 把镜像地址写进 `pyproject.toml` 的元数据 URL | 元数据会被下游打包器抓取；权威地址只能有一个，否则下游永远不知道哪个最新 |
| 承诺镜像与主仓库实时一致 | 手动 push 就有窗口期。诚实写"可能落后"，比承诺"实时"且做不到好 |

> 最后一条不是免责话术。**安全类工具的用户需要知道"我拿到的是不是最新的"**，
> 所以 README 里必须写明权威地址，并且镜像描述里必须写"可能落后"。

---

## 八、和企业内部署的边界

多平台分发解决的是"拿得到"，不解决"合不合规"。
如果使用方要把本工具放进受监管环境（金融、政务、等保、商用密码相关），
**合规评估是使用方的义务**，不是分发平台的义务，也不是作者的义务。
本项目只提供代码与它自己的威胁模型（[SECURITY.md](../SECURITY.md)）。
