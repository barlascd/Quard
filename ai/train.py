import json

import numpy as np
import torch
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from ai.data import create_dataset
from ai.model import SecurityModel
from ai.paths import MODELS_DIR, SCALER_PATH, TORCH_PATH


def train():
    torch.manual_seed(42)

    data, labels = create_dataset()
    x_train, x_test, y_train, y_test = train_test_split(
        data.to_numpy(dtype=np.float32),
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    # Fit the scaler on the training split only (no test-set leakage).
    scaler = StandardScaler()
    x_train = scaler.fit_transform(x_train).astype(np.float32)
    x_test = scaler.transform(x_test).astype(np.float32)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with open(SCALER_PATH, "w") as f:
        json.dump(
            {"mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist()}, f
        )

    train_data = TensorDataset(
        torch.tensor(x_train),
        torch.tensor(y_train, dtype=torch.float32).view(-1, 1),
    )
    loader = DataLoader(train_data, batch_size=64, shuffle=True)

    model = SecurityModel()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    loss_function = nn.BCELoss()

    for epoch in range(20):
        model.train()
        for xb, yb in loader:
            optimizer.zero_grad()
            loss = loss_function(model(xb), yb)
            loss.backward()
            optimizer.step()
        print(f"Epoch {epoch + 1}: {loss.item():.4f}")

    model.eval()
    with torch.no_grad():
        predictions = model(torch.tensor(x_test)).numpy().ravel()

    print(classification_report(y_test, (predictions >= 0.5).astype(int)))
    print("ROC-AUC:", roc_auc_score(y_test, predictions))

    torch.save(model.state_dict(), TORCH_PATH)


if __name__ == "__main__":
    train()
