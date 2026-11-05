"""资源生命周期：连接必须能显式关掉，且重复关闭不报错。

背景：Registry 持有 sqlite 连接，之前没有 close()，只能等 GC。单次 CLI
进程退出时由 OS 兜底，看起来无害；但常驻服务 / 嵌入式调用 / 测试套件里
频繁建实例，攒的就是 fd。
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink.registry import Registry


class RegistryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="a2alink-life-")
        self.db = os.path.join(self.tmp, "t.sqlite3")

    def test_close_is_idempotent(self):
        reg = Registry(self.db)
        reg.close()
        reg.close()          # 第二次不能抛
        self.assertIsNone(reg.conn)

    def test_context_manager_closes(self):
        with Registry(self.db) as reg:
            reg.register("ctx-agent", [])
            conn = reg.conn
        self.assertIsNone(reg.conn)
        # 连接已关：再用它必须报错，而不是"看起来能用"
        with self.assertRaises(Exception):
            conn.execute("SELECT 1")

    def test_context_manager_closes_on_exception(self):
        reg = Registry(self.db)
        with self.assertRaises(RuntimeError):
            with reg:
                raise RuntimeError("boom")
        self.assertIsNone(reg.conn)

    def test_reopen_after_close(self):
        with Registry(self.db) as reg:
            reg.register("a1", [])
        with Registry(self.db) as reg:
            self.assertEqual(reg.stats()["agents"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
