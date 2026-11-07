import logging
import os
import sys

class StructuredFormatter(logging.Formatter):
    """
    Structured logging formatter that serializes standard log messages
    and appends structured extra fields (event_type, eviction_tier, etc.)
    when present on the LogRecord.
    """
    STRUCTURED_FIELDS = (
        "event_type",
        "eviction_tier",
        "forced_eviction_count",
        "current_size",
        "max_capacity",
        "low_watermark",
    )

    def format(self, record: logging.LogRecord) -> str:
        base_msg = super().format(record)
        structured_extras = {
            k: getattr(record, k)
            for k in self.STRUCTURED_FIELDS
            if hasattr(record, k)
        }
        if structured_extras:
            extras_str = " ".join(f"{k}={v}" for k, v in structured_extras.items())
            return f"{base_msg} | {extras_str}"
        return base_msg


def setup_logger(name: str, log_level: str, data_dir: str) -> logging.Logger:
    logger = logging.getLogger(name)
    
    # Avoid adding handlers multiple times if instantiated repeatedly
    if logger.handlers:
        return logger
        
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(level)

    formatter = StructuredFormatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler
    log_dir = os.path.join(data_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "telemetry.log")
    
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setLevel(level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger
