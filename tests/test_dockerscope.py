import unittest
import dockerscope

class DockerScopeTests(unittest.TestCase):
    def rules(self, dockerfile):
        return {finding.rule for finding in dockerscope.lint(dockerfile, "Dockerfile")}

    def test_latest_image_tag(self):
        self.assertIn("DS001", self.rules("FROM python:latest\nUSER app\nHEALTHCHECK CMD true"))

    def test_secret_arg(self):
        self.assertIn("DS013", self.rules("FROM python:3.12-slim\nARG API_KEY\nUSER app\nHEALTHCHECK CMD true"))

    def test_relative_workdir(self):
        self.assertIn("DS009", self.rules("FROM python:3.12-slim\nWORKDIR app\nUSER app\nHEALTHCHECK CMD true"))

    def test_root_final_user(self):
        self.assertIn("DS002", self.rules("FROM python:3.12-slim\nUSER root\nHEALTHCHECK CMD true"))

    def test_ignore_comment(self):
        result = dockerscope.lint(
            "# dockerscope-ignore: DS001\nFROM python:latest\nUSER app\nHEALTHCHECK CMD true"
        )
        self.assertNotIn("DS001", {x.rule for x in result})

    def test_empty_file_is_syntax_finding(self):
        self.assertIn("DS000", self.rules(""))

if __name__ == "__main__":
    unittest.main()
