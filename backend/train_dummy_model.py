"""
Creates a placeholder model + encoders matching the feature schema:
bytes_sent, bytes_received, duration, port, protocol_type, service, flag

REPLACE THIS with your own trained model — just make sure you save:
  - model.pkl      -> your trained classifier (must expose .predict())
  - encoders.pkl   -> dict of {"protocol_type": LabelEncoder, "service": LabelEncoder, "flag": LabelEncoder}
    fit on the SAME categories you used during training, matching the ones
    flow_extractor.py can produce (see PROTO_MAP / SERVICE_MAP / _classify_flag).

Run once: python3 train_dummy_model.py
"""
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

np.random.seed(42)
N = 2000

protocol_types = ["tcp", "udp", "icmp", "other"]
services = ["http", "https", "dns", "ssh", "ftp", "smtp", "telnet", "other"]
flags = ["SF", "S0", "S1", "REJ", "RSTO", "OTH"]

df = pd.DataFrame({
    "bytes_sent": np.random.exponential(500, N).astype(int),
    "bytes_received": np.random.exponential(500, N).astype(int),
    "duration": np.random.exponential(2, N),
    "port": np.random.choice([80, 443, 22, 53, 21, 25, 8080, 3389], N),
    "protocol_type": np.random.choice(protocol_types, N, p=[0.7, 0.25, 0.04, 0.01]),
    "service": np.random.choice(services, N),
    "flag": np.random.choice(flags, N, p=[0.6, 0.15, 0.05, 0.1, 0.05, 0.05]),
})

# crude synthetic anomaly rule so the demo model isn't pure noise
anomaly = (
    (df["flag"].isin(["S0", "REJ"])) |
    (df["bytes_sent"] > df["bytes_sent"].quantile(0.97)) |
    (df["duration"] > df["duration"].quantile(0.97))
).astype(int)

encoders = {}
X = df.copy()
for col in ["protocol_type", "service", "flag"]:
    le = LabelEncoder()
    le.fit(list(X[col].unique()) + ["other" if col != "flag" else "OTH"])
    X[col] = le.transform(X[col])
    encoders[col] = le

feature_cols = ["bytes_sent", "bytes_received", "duration", "port",
                 "protocol_type", "service", "flag"]

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X[feature_cols], anomaly)

joblib.dump(model, "model.pkl")
joblib.dump(encoders, "encoders.pkl")
joblib.dump(feature_cols, "feature_cols.pkl")
print("Saved model.pkl, encoders.pkl, feature_cols.pkl")
