import sys
from core.runtime import TelemetryRuntime

def main():
    runtime = TelemetryRuntime()
    try:
        runtime.start()
        # For Step 1 foundation, we just initialize, report health, and exit cleanly.
        # Future collectors will loop or block here.
        runtime.stop()
        sys.exit(0)
    except KeyboardInterrupt:
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
