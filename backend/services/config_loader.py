import yaml
import os
import logging

logger  = logging.getLogger(__name__)
_config = None


def load_rules(path: str = None) -> dict:
    """Load detection rules from YAML config file. Cached after first load."""
    global _config
    if _config is not None:
        return _config

    if not path:
        path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "detection_rules.yaml"
        )

    try:
        with open(path, "r") as f:
            _config = yaml.safe_load(f)
        logger.info(f"Detection rules loaded from {path}")
    except FileNotFoundError:
        logger.error(f"Detection rules file not found at {path}. Using defaults.")
        _config = {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing detection rules: {e}. Using defaults.")
        _config = {}

    return _config


def get_rule(key: str, default=None):
    """
    Get a value from the detection rules using dot notation.
    Example: get_rule("brute_force.thresholds.medium", 5)
    """
    rules = load_rules()
    keys  = key.split(".")
    val   = rules

    for k in keys:
        if isinstance(val, dict):
            val = val.get(k)
            if val is None:
                return default
        else:
            return default

    return val if val is not None else default


def is_enabled(rule: str) -> bool:
    """Check if a rule is enabled. Defaults to True if not specified."""
    return get_rule(f"{rule}.enabled", True)


def reload_rules():
    """Force reload of rules from disk — useful for hot reloading."""
    global _config
    _config = None
    return load_rules()
