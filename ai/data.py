"""Synthetic training data. Demo only: not real security telemetry."""
import numpy as np
import pandas as pd

from ai.preprocessing import FEATURES


def create_dataset(samples: int = 5000):
    rng = np.random.default_rng(42)
    normal = np.column_stack([
        rng.gamma(2, 5, samples),
        rng.poisson(0.25, samples),
        rng.beta(2, 8, samples),
        rng.poisson(5, samples),
    ])
    labels = np.zeros(samples, dtype=np.int64)

    count = samples // 10
    normal[:count, 0] += rng.uniform(30, 100, count)
    normal[:count, 1] += rng.integers(5, 30, count)
    normal[:count, 2] = rng.uniform(0.75, 1, count)
    normal[:count, 3] += rng.integers(20, 80, count)
    labels[:count] = 1

    df = pd.DataFrame(normal, columns=FEATURES)
    return df, labels


if __name__ == "__main__":
    data, labels = create_dataset()
    data["label"] = labels
    data.to_csv("security_data.csv", index=False)
