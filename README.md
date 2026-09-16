# Network Anomaly Detector — Web UI

Upload a `.pcap`/`.pcapng` file (e.g. captured with Wireshark), the backend
aggregates packets into flows using `tshark`, and runs your ML model on
features: `bytes_sent, bytes_received, duration, port, protocol_type, service, flag`.

## Setup

```bash
# 1. Install tshark (Linux)
sudo apt-get install tshark
# macOS: brew install wireshark
# Windows: install Wireshark, tshark.exe ships with it — add to PATH

# 2. Install Python deps
cd backend
pip install -r requirements.txt
```

`train_dummy_model.py` creates a **placeholder** model so the whole pipeline
runs end-to-end out of the box. Replace it with your own:

1. Train your model as usual with columns in this exact order:
   `bytes_sent, bytes_received, duration, port, protocol_type, service, flag`
2. Save three files into `backend/`:
   - `model.pkl` — your trained classifier (must support `.predict()`, output 0=normal / 1=anomaly)
   - `encoders.pkl` — a dict `{"protocol_type": LabelEncoder, "service": LabelEncoder, "flag": LabelEncoder}` fit on the same categories used at training time
   - `feature_cols.pkl` — list of the 7 feature column names in the order your model expects

If you didn't use `LabelEncoder`/scikit-learn, just rewrite the `_encode()`
function in `main.py` to match whatever preprocessing you used.

To regenerate the placeholder anytime: `python3 train_dummy_model.py`

## Run

```bash
# Terminal 1 — backend
cd backend
uvicorn main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
python3 -m http.server 5500
# open http://localhost:5500 in your browser
```

Upload a pcap in the browser and you'll see a table of flows with
normal/anomaly predictions, anomalies highlighted in red.

## Notes / known simplifications

- `flag` (SF/S0/REJ/RSTO/...) is derived from TCP SYN/ACK/FIN/RST flag counts
  per flow in `flow_extractor.py::_classify_flag()`. It's a reasonable
  approximation of NSL-KDD-style flags but not identical to what a real
  stateful tool like Zeek computes — tune it if your model is sensitive to it.
- `service` is guessed from the destination port via a small lookup table in
  `flow_extractor.py::SERVICE_MAP`. Add more ports as needed.
- Unseen categorical values at inference time fall back to `"other"`/`"OTH"`
  rather than crashing.
- For **live capture** instead of file upload, swap `tshark -r <file>` for
  `tshark -i <interface>` running as a long-lived subprocess, and stream new
  flows to the frontend over a WebSocket instead of one HTTP response.
