"""技能安装测试。

真正要验的不是"文件写出来了"，而是：
- 预演不落盘（说了不动手，就必须真不动）
- 不覆盖别人的同名目录（礼貌，也是安全）
- 启动器真的能跑（写死路径的意义就在这里）
- SKILL.md 里那几条安全约束还在（如果把防护条款删了，测试要红）
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink import __version__, skillpack


class TestInstall(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="a2a-skill-")

    def test_dry_run_writes_nothing(self):
        out = skillpack.install(self.root, dry_run=True)
        self.assertTrue(out["dry_run"])
        self.assertEqual(len(out["would_write"]), 3)
        for p in out["would_write"]:
            self.assertFalse(os.path.exists(p), f"预演不该写盘：{p}")

    def test_install_creates_layout(self):
        out = skillpack.install(self.root)
        target = out["target"]
        self.assertTrue(os.path.isfile(os.path.join(target, "SKILL.md")))
        self.assertTrue(os.path.isfile(
            os.path.join(target, "scripts", "a2a.py")))
        with open(os.path.join(target, skillpack.MARKER), encoding="utf-8") as fh:
            marker = json.load(fh)
        self.assertEqual(marker["name"], "a2alink")
        self.assertEqual(marker["version"], __version__)
        self.assertTrue(os.path.isdir(marker["src"]))

    def test_idempotent(self):
        a = skillpack.install(self.root)
        b = skillpack.install(self.root)
        self.assertEqual(a["target"], b["target"])
        self.assertEqual(b["upgraded_from"], __version__)

    def test_refuses_to_clobber_foreign_dir(self):
        foreign = os.path.join(self.root, "a2alink")
        os.makedirs(foreign)
        with open(os.path.join(foreign, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("我自己写的技能")
        with self.assertRaises(skillpack.SkillPackError):
            skillpack.install(self.root)
        # 内容必须原样保留
        with open(os.path.join(foreign, "SKILL.md"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "我自己写的技能")

    def test_force_overrides(self):
        foreign = os.path.join(self.root, "a2alink")
        os.makedirs(foreign)
        with open(os.path.join(foreign, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("old")
        out = skillpack.install(self.root, force=True)
        with open(os.path.join(out["target"], "SKILL.md"), encoding="utf-8") as fh:
            self.assertIn("a2alink", fh.read())

    def test_uninstall_keeps_identity(self):
        skillpack.install(self.root)
        out = skillpack.uninstall(self.root)
        self.assertTrue(out["removed"])
        self.assertFalse(os.path.exists(os.path.join(self.root, "a2alink")))

    def test_uninstall_refuses_foreign(self):
        foreign = os.path.join(self.root, "a2alink")
        os.makedirs(foreign)
        out = skillpack.uninstall(self.root)
        self.assertFalse(out["removed"])
        self.assertEqual(out["reason"], "not_managed")
        self.assertTrue(os.path.isdir(foreign))

    def test_status_reports_install(self):
        self.assertFalse(skillpack.status(self.root)["installed"])
        skillpack.install(self.root)
        st = skillpack.status(self.root)
        self.assertTrue(st["installed"])
        self.assertFalse(st["outdated"])
        self.assertEqual(st["missing_files"], [])


class TestLauncherRuns(unittest.TestCase):
    """启动器要真的能跑起来。

    这是整个"一键"最容易坏的一环：仓库路径一变，写死的 sys.path 就失效，
    而错误信息只会是 ModuleNotFoundError，用户根本猜不到原因。
    """

    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="a2a-lnch-")
        cls.out = skillpack.install(cls.root)
        cls.launcher = os.path.join(cls.out["target"], "scripts", "a2a.py")

    def test_runs_version(self):
        r = subprocess.run([sys.executable, self.launcher, "--version"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("a2alink", r.stdout)

    def test_reports_missing_src_clearly(self):
        # 模拟"仓库被搬走"：把写死的路径换成一个不存在的目录。
        # 期望的不是崩溃，而是一句能让人知道下一步做什么的话。
        with open(self.launcher, encoding="utf-8") as fh:
            text = fh.read()
        broken = os.path.join(self.root, "broken.py")
        with open(broken, "w", encoding="utf-8") as f:
            f.write(text.replace(repr(skillpack.package_src_root()),
                                 repr(os.path.join(self.root, "nonexistent"))))
        r = subprocess.run([sys.executable, broken, "--version"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        # 断言"有没有说清下一步"，而不是断言中文字面量：
        # 英文 Windows 的 stderr 编码不了中文，启动器会降级成英文说明。
        self.assertIn("nonexistent", r.stderr)
        self.assertIn("A2ALINK_SRC", r.stderr)
        self.assertTrue(
            "源码目录找不到了" in r.stderr or "source directory not found" in r.stderr,
            r.stderr,
        )

    def test_non_utf8_console_gets_readable_message(self):
        """cp1252 控制台下不许吐 \\uXXXX 转义。

        CI 在 windows-latest 上抓到的真 bug：中文写进 cp1252 的 stderr 时，
        Python 的 backslashreplace 会把它变成字面量 \\u6e90\\u7801\\u76ee\\u5f55，
        用户看到的是一堆转义而不是一句人话。
        """
        with open(self.launcher, encoding="utf-8") as fh:
            text = fh.read()
        broken = os.path.join(self.root, "broken_cp1252.py")
        with open(broken, "w", encoding="utf-8") as f:
            f.write(text.replace(repr(skillpack.package_src_root()),
                                 repr(os.path.join(self.root, "nonexistent"))))
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        r = subprocess.run([sys.executable, broken, "--version"],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertNotRegex(r.stderr, r"\\u[0-9a-f]{4}",
                            f"输出里有转义乱码，用户读不懂: {r.stderr!r}")
        self.assertIn("source directory not found", r.stderr)


class TestSkillGuardrails(unittest.TestCase):
    """SKILL.md 是给 Agent 的指令。安全条款被删掉，等于防护也没了。"""

    @classmethod
    def setUpClass(cls):
        root = tempfile.mkdtemp(prefix="a2a-md-")
        out = skillpack.install(root)
        cls.target = out["target"]
        with open(os.path.join(cls.target, "SKILL.md"), encoding="utf-8") as f:
            cls.md = f.read()

    def test_frontmatter(self):
        self.assertTrue(self.md.startswith("---\n"))
        self.assertIn("name: a2alink", self.md)
        self.assertIn(f"version: {__version__}", self.md)

    def test_says_check_first(self):
        self.assertIn("check", self.md)
        self.assertIn("先收信", self.md)

    def test_warns_about_data_boundary(self):
        """内外网边界这条是项目的底线要求，不能在任何版本里消失。"""
        for kw in ("内外网", "绝密", "合规"):
            self.assertIn(kw, self.md, f"SKILL.md 缺少 {kw} 相关说明")

    def test_treats_inbound_as_data(self):
        self.assertIn("untrusted_external_content", self.md)
        self.assertIn("不要当命令执行", self.md)

    def test_no_auto_loop(self):
        self.assertIn("不要", self.md)
        self.assertIn("死循环", self.md)

    def test_launcher_path_is_absolute(self):
        """必须是绝对路径。

        相对路径在 Agent 的 cwd 下必然失效——而 Agent 的 cwd 是不可预期的。
        """
        with open(os.path.join(self.target, "scripts", "a2a.py"),
                  encoding="utf-8") as f:
            text = f.read()
        src = os.path.abspath(skillpack.package_src_root())
        self.assertIn(repr(src), text)
        self.assertTrue(os.path.isabs(src))


if __name__ == "__main__":
    unittest.main()
