#!/usr/bin/env python3
"""Independent metadata-diff oracle helper regressions; no PE execution."""
import unittest

from check_windows_diff_pairs import ascii_lower_dll, case_only


class DllCaseOracleTests(unittest.TestCase):
    def test_only_ascii_letters_are_normalized(self):
        self.assertEqual(ascii_lower_dll("KERNEL32.DLL"), "kernel32.dll")
        self.assertEqual(ascii_lower_dll("Ä.DLL"), "Ä.dll")
        self.assertEqual(ascii_lower_dll("İ.DLL"), "İ.dll")

    def test_ascii_case_only_diff_is_identified(self):
        self.assertTrue(case_only(["KERNEL32.DLL!ReadFile"], ["kernel32.dll!ReadFile"]))
        self.assertFalse(case_only(["KERNEL32.dll!ReadFile"], ["KERNEL32.dll!ReadFile"]))

    def test_unicode_case_change_is_not_equated(self):
        self.assertFalse(case_only(["Ä.DLL!F"], ["ä.dll!F"]))
        self.assertFalse(case_only(["İ.DLL!F"], ["i̇.dll!F"]))

    def test_collisions_or_changed_symbol_names_abstain(self):
        self.assertFalse(
            case_only(
                ["KERNEL32.DLL!ReadFile", "kernel32.dll!ReadFile"],
                ["kernel32.dll!ReadFile"],
            )
        )
        self.assertFalse(case_only(["KERNEL32.DLL!ReadFile"], ["kernel32.dll!WriteFile"]))


if __name__ == "__main__":
    unittest.main()
