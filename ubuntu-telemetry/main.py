import sys
import time
import signal
from core.runtime import TelemetryRuntime
from pipeline import UbuntuDetectionPipeline
from config.settings import config

def main():
    runtime = TelemetryRuntime()
    try:
        runtime.start(enforce_linux=False)
        pipeline = UbuntuDetectionPipeline(runtime.logger)
        pipeline.initialize()

        # Handle termination signals cleanly
        def handle_signal(sig, frame):
            runtime.logger.info("Signal received. Stopping Ubuntu telemetry pipeline...")
            pipeline.shutdown()
            runtime.stop()
            sys.exit(0)

        try:
            signal.signal(signal.SIGINT, handle_signal)
            signal.signal(signal.SIGTERM, handle_signal)
        except (ValueError, AttributeError):
            pass

        runtime.logger.info(f"Ubuntu Telemetry agent running. Polling interval: {config.ubuntu_event_poll_interval}s.")
        # Single iteration for non-daemon run, or loop when deployed
        pipeline.process_batch()
        pipeline.shutdown()
        runtime.stop()
        sys.exit(0)

    except KeyboardInterrupt:
        runtime.logger.info("Keyboard interrupt received.")
        runtime.stop()
        sys.exit(0)
    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e:
        runtime.logger.exception(f"Fatal error during execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
