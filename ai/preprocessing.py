import numpy as np

FEATURES = [
    "request_rate",
    "failed_logins",
    "cpu_fraction",
    "process_count",
]


def validate_features(values) -> np.ndarray:
    """Return a (1, 4) float32 array or raise ValueError."""
    try:
        x = np.asarray(values, dtype=np.float32).reshape(1, len(FEATURES))
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid input shape or type") from exc
    if not np.isfinite(x).all():
        raise ValueError("Invalid numerical input")
    if (x < 0).any():
        raise ValueError("Negative feature")
    if not 0 <= x[0, 2] <= 1:
        raise ValueError("Invalid CPU fraction")
    return x
