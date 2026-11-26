import os
import unittest

class TestForensicStudioStructure(unittest.TestCase):
    def test_main_entry_exists(self):
        self.assertTrue(os.path.exists("forensic_studio.py"), "Main entry file forensic_studio.py is missing")

    def test_gui_directory_exists(self):
        self.assertTrue(os.path.isdir("forensic_gui"), "forensic_gui package directory is missing")

    def test_documentation_exists(self):
        self.assertTrue(os.path.exists("README.md"), "README.md is missing")
        self.assertTrue(os.path.exists("LICENSE"), "LICENSE file is missing")

if name == "main":
    unittest.main()
