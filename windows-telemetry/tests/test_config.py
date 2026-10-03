import unittest
import os
from config.settings import Settings

class TestConfig(unittest.TestCase):
    def test_default_config(self):
        settings = Settings()
        self.assertTrue(settings.app_name)
        self.assertTrue(settings.version)
        self.assertTrue(settings.log_level)
        self.assertTrue(settings.data_dir)
        self.assertTrue(os.path.exists(settings.data_dir))
