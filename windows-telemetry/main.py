import sys
import time
import signal
from core.runtime import TelemetryRuntime
from pipeline import WindowsDetectionPipeline
from config.settings import config

def main():
    runtime = TelemetryRuntime()
    pipeline = None
    try:
        runtime.start()
        pipeline = WindowsDetectionPipeline(runtime.logger)
        pipeline.initialize()

        def handle_signal(sig, frame):
            runtime.logger.info("Signal received. Stopping Windows telemetry pipeline...")
            if pipeline:
                pipeline.shutdown()
            runtime.stop()
            sys.exit(0)

        try:
            signal.signal(signal.SIGINT, handle_signal)
            signal.signal(signal.SIGTERM, handle_signal)
        except (ValueError, AttributeError):
            pass

        runtime.logger.info(f"Windows Telemetry agent running. Polling interval: {config.windows_event_poll_interval}s.")

        if "--once" in sys.argv:
            pipeline.process_batch()
            pipeline.shutdown()
            runtime.stop()
            sys.exit(0)

        while True:
            pipeline.process_batch()
            time.sleep(config.windows_event_poll_interval)

    except KeyboardInterrupt:
        runtime.logger.info("Keyboard interrupt received.")
        if pipeline:
            try:
                pipeline.shutdown()
            except Exception:
                pass
        runtime.stop()
        sys.exit(0)
    except SystemExit as e:
        sys.exit(e.code)
    except RuntimeError as e:
        runtime.logger.error(f"Startup failed: {e}")
        sys.exit(1)
    except Exception as e:
        runtime.logger.exception(f"Fatal error during execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
