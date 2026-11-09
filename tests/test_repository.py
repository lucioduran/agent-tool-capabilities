import re
import subprocess
import sys
import unittest
from pathlib import Path


class RepositoryTests(unittest.TestCase):
    def test_readme_sections(self):
        text = Path("README.md").read_text(encoding="utf-8")
        self.assertEqual(
            [
                "Problem",
                "Scope",
                "Quick start",
                "Usage",
                "Architecture",
                "Reproduction",
                "Results",
                "Testing",
                "Limitations",
                "Contributing",
                "License",
            ],
            re.findall(r"^## (.+)$", text, re.MULTILINE),
        )

    def test_no_em_dashes(self):
        roots = [
            Path(p)
            for p in ["agent_capabilities", "experiments", "tests", "docs", "examples"]
        ]
        paths = list(Path(".").glob("*.md"))
        for root in roots:
            paths.extend(p for p in root.rglob("*") if p.suffix in {".py", ".md"})
        for path in paths:
            with self.subTest(path=path):
                self.assertNotIn(chr(0x2014), path.read_text(encoding="utf-8"))

    def test_demo(self):
        import json

        result = subprocess.run(
            [sys.executable, "-m", "examples.demo"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        demo = json.loads(result.stdout)
        self.assertEqual({"/owned/note": "Hello"}, demo["notes"])
        self.assertEqual(
            ["allowed", "revoked"], [d["reason"] for d in demo["decisions"]]
        )
