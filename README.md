# FakeGuard Overnight Prototype

## A. Install
```bash
python -m pip install -r requirements.txt
```

## B. Train
```bash
python train.py
```
This downloads UCI Phishing Websites (dataset 327), 11,055 records and 30 features.

## C. Run
```bash
python app.py
```
Open:
http://127.0.0.1:5000

## Architecture
User URL
 -> safe retrieval
 -> URL feature extraction
 -> URL ML model
 -> HTML/DOM behavior extraction
 -> deception/identity signals
 -> evidence fusion
 -> contradiction analysis
 -> risk level + explanation + report

## Important research note
The UCI dataset is a benchmark and should not be represented as a current live-threat dataset. The prototype's live webpage features are approximations of several UCI features and additional runtime signals.

## Patent note
The existence of a working prototype does not establish patentability. Prior-art search, claim drafting and legal examination are required.
