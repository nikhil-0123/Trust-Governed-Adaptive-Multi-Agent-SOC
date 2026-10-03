import unittest
import platform
import tempfile
import shutil
from core.runtime import TelemetryRuntime
from config.settings import config

class TestRuntime(unittest.TestCase):
    def test_runtime_startup_shutdown(self):
        if platform.system() != "Windows":
            self.skipTest("Skipping runtime test on non-Windows platform")
            
        runtime = TelemetryRuntime()
        
        # Override data dir so we don't pollute real directories
        test_dir = tempfile.mkdtemp()
        original_data_dir = config.data_dir
        config.data_dir = test_dir
        
        try:
            runtime.start()
            self.assertIsNotNone(runtime.identity)
            self.assertIsNotNone(runtime.health)
            runtime.stop()
        finally:
            config.data_dir = original_data_dir
            for handler in runtime.logger.handlers[:]:
                handler.close()
                runtime.logger.removeHandler(handler)
            shutil.rmtree(test_dir)
