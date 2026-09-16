import os
import tempfile

import joblib
import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from flow_extractor import extract_flows

app = FastAPI(title="Network Anomaly Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in production
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
ENCODERS_PATH = os.path.join(os.path.dirname(__file__), "encoders.pkl")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "feature_cols.pkl")

model = joblib.load(MODEL_PATH)
encoders = joblib.load(ENCODERS_PATH)
feature_cols = joblib.load(FEATURES_PATH)


def _encode(df: pd.DataFrame) -> pd.DataFrame:
    """Apply saved LabelEncoders; unseen categories fall back to 'other'/'OTH'."""
    out = df.copy()
    for col, le in encoders.items():
        fallback = "OTH" if col == "flag" else "other"
        known = set(le.classes_)
        out[col] = out[col].apply(lambda v: v if v in known else fallback)
        out[col] = le.transform(out[col])
    return out


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(400, "Please upload a .pcap or .pcapng file")

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        flows = extract_flows(tmp_path)
    finally:
        os.remove(tmp_path)

    if flows.empty:
        return {"flows": []}

    encoded = _encode(flows[feature_cols])
    preds = model.predict(encoded[feature_cols])

    flows = flows.copy()
    flows["prediction"] = ["anomaly" if p == 1 else "normal" for p in preds]

    return {"flows": flows.to_dict(orient="records")}
