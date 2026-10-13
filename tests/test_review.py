import unittest

from ai_code_review import review_source


class ReviewTests(unittest.TestCase):
    def test_reports_ast_findings_with_exact_lines(self):
        findings = review_source("x = eval(input())\ndef f(value=[]):\n    return value\n")
        by_rule = {item.rule: item for item in findings}
        self.assertEqual(by_rule["PY001"].line, 1)
        self.assertEqual(by_rule["PY007"].line, 2)

    def test_reports_text_heuristics(self):
        findings = review_source('api_key = "abcdefghijk"\n# TODO: rotate it\n')
        self.assertEqual({f.rule for f in findings}, {"TXT001", "TXT002"})
        self.assertEqual([f.line for f in findings], [1, 2])

    def test_syntax_error_is_reported_not_raised(self):
        findings = review_source("if True print('no')")
        self.assertEqual(findings[0].rule, "PY000")
        self.assertEqual(findings[0].line, 1)

    def test_clean_input_has_no_findings_and_placeholders_are_ignored(self):
        self.assertEqual(review_source('password = "your-password-here"\nprint("ok")'), [])

    def test_shell_and_broad_exception_findings(self):
        source = "import subprocess\nsubprocess.run('echo hi', shell=True)\ntry:\n    pass\nexcept:\n    pass\n"
        by_rule = {f.rule: f for f in review_source(source)}
        self.assertEqual(by_rule["PY003"].line, 2)
        self.assertEqual(by_rule["PY005"].line, 5)


if __name__ == "__main__":
    unittest.main()
