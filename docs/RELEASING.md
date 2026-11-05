# 发布到 GitHub

这份文档只讲一件事：**怎么把仓库推上去，以及以后每次发版怎么做。**
不含"怎么用 Git"——那属于基础知识。

---

## 一、首次发布（只做一次）

### 第 1 步：在网页上建一个**空**仓库

打开 <https://github.com/new>，填：

- Repository name：`a2alink`
- 可见性：按许可证来（本项目是 source-available，建议 **Public**；
  `LICENSE` 里已经写明"可用、禁商用、商用需授权"，公开不冲突）
- **README / .gitignore / license 三个勾全部不要勾**
- 点 Create repository

> **为什么必须空着建**：勾了任何一个，GitHub 会替你在远端生成一个提交。
> 那个提交和你本地的历史没有共同祖先，`git push` 会被拒
> （`non-fast-forward` / `unrelated histories`），得先 `pull --allow-unrelated-histories`
> 再生造一个合并提交。第一次发布就制造一个无意义的 merge，不值得。
>
> 本地已经有 `README.md` / `.gitignore` / `LICENSE`，远端不需要再生成一份。

### 第 2 步：确认认证可用

```bash
ssh -T git@github.com
# 期望：Hi <用户名>! You've successfully authenticated...
```

不通就先把 SSH key 加到 GitHub（Settings → SSH and GPG keys）。
本项目用 SSH 而不是 HTTPS，是为了不必把 token 存在磁盘上。

### 第 3 步：推

```bash
git remote -v                     # 应指向 git@github.com:<用户名>/a2alink.git
git push -u origin main
git push origin --tags            # 把 v0.1.1 ~ v0.4.0 一起推上去
```

推完仓库就有了，但**不会自动出现 Release 页面**。见第四节。

---

## 二、推送前自检（每次都要）

### 2.1 敏感文件不能进仓库

```bash
git ls-files | grep -Ei "identity\.json|\.sqlite3$|/keys/|\.env$|trust/" \
  && echo "⛔ 上面这些不该被跟踪" || echo "✅ 干净"
```

必须覆盖的东西（`.gitignore` 已配置，但**已提交的文件不会被 .gitignore 追溯**——
如果曾经 `git add` 过，得 `git rm --cached`）：

| 文件 | 为什么不能提交 |
|---|---|
| `identity.json` | 含向注册中心证明"我是我"的 token |
| `keys/*.key` | 私钥。提交即视为泄露，必须 `keys rotate` |
| `*.sqlite3` | 含全部消息元数据、审计、成员关系 |
| `policy.json` / `.env` | 可能含禁出词表、邀请码 |
| `trust/` | 对端公钥固定表：暴露你和谁通过信 |

### 2.2 测试必须全绿

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

绿了才推。"下次再修"的红色提交会一直留在历史里。

### 2.3 版本号与 CHANGELOG 对得上

```bash
grep version pyproject.toml
grep __version__ src/a2alink/__init__.py
head -20 CHANGELOG.md
```

三处必须是同一个版本号。对不上就说明漏改了某处。

---

## 三、以后每次发版

```bash
# 1. 改版本号（pyproject.toml + __init__.py）
# 2. 在 CHANGELOG.md 顶部加一节（Added / Changed / 兼容性 / 明确没做）
# 3. 跑全量测试
PYTHONPATH=src python -m unittest discover -s tests

# 4. 提交 + 打标签（注释标签，不要轻量标签）
git add -A && git commit -m "feat(v0.5.0): ..."
git tag -a v0.5.0 -m "v0.5.0 — 一句话主题"

# 5. 推代码和标签
git push origin main
git push origin v0.5.0
```

**标签一定要单独推**。`git push` 默认不带标签，
忘了这一步的表现是"代码推上去了，但 Releases 里没有这个版本"。

---

## 四、写 Release 说明

标签推上去不等于有 Release 页面。到
`https://github.com/<用户名>/a2alink/releases/new`：

1. 选刚推的标签
2. 标题写版本主题（一行）
3. 正文直接粘 `CHANGELOG.md` 里对应那一节

CHANGELOG 的写法就是为这一步准备的：
**"明确没做"那一节比 "Added" 更重要**——它告诉使用者哪里还有坑，
省掉他们踩一遍再回来问。

---

## 五、常见报错

| 报错 | 原因 | 怎么办 |
|---|---|---|
| `Repository not found` | 仓库还没建，或者不在这个账号下 | 回到第 1 步。**注意：GitHub 不支持用 SSH 建仓库**，必须先网页建 |
| `Permission denied (publickey)` | SSH key 没加到 GitHub，或加到了别的账号 | `ssh -T git@github.com` 看返回的是谁 |
| `non-fast-forward` | 远端已经有提交（通常是建仓库时勾了 README） | 见下方"远端已有提交" |
| `src refspec main does not match any` | 本地分支叫 `master` | `git branch -M main` |
| 推上去体积异常大 | 历史里混进了 sqlite / 私钥 | `git rm --cached` 后再 `git commit --amend`；**历史里已有的要用 filter-repo 清**，否则等于公开过 |

### 远端已有提交

如果建仓时勾了 README，远端会有一个孤立提交。两条路：

```bash
# A. 远端那个提交不要了（最简单，且远端还没有别人 clone）
git push -f origin main

# B. 想保留它
git pull --allow-unrelated-histories origin main
# 解决冲突后提交，再 push
```

推荐 A：仓库刚建、没有协作者时，一个干净的线性历史比"保留了那个 README"值钱。

---

## 六、为什么不自动化

可以用 GitHub Actions 做自动发布，也可以装 `gh` CLI 一条命令建仓。
本项目的选择是**手动**，理由：

- 发布是低频动作（几个月一次），自动化的收益抵不上多一个依赖；
- **推送前自检那一步必须有人看**——`git ls-files | grep` 的输出是"这次有没有
  把私钥推上去"的唯一防线，把它塞进脚本里自动通过，等于没有；
- 建仓这一步无论如何都要人去点（GitHub 不支持 API 之外的建仓方式，
  而 API 要 PAT，PAT 又要存在某个地方）。

一句话：**能自动的部分只有 `git push`，而 `git push` 本来就只有一行。**
