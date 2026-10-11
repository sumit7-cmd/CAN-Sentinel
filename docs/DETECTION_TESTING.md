# Detection Testing Guide

CAN-Sentinel's automated tests exercise feature extraction and rule-based classification without requiring a live CAN interface.

## Run the tests

Create and activate the project's virtual environment, install the declared dependencies, and run:

```bash
python -m pip install -r requirements.txt
python -m compileall -q src scripts tests
pytest -q
```

## Detection behaviors covered

- The feature vector always contains eight values.
- An empty monitoring window produces zeroed features and no top CAN ID.
- A non-positive window duration is guarded against division by zero.
- Unknown CAN IDs can be classified as injection candidates.
- Baseline-like traffic does not create an alert under the test conditions.
- DLC deviations are counted per CAN ID, not per anomalous frame.
- Repeated payloads raise the replay-ratio feature.

## Lab safety

Tests use synthetic messages and do not need a physical vehicle or CAN interface. Keep live experimentation restricted to an isolated virtual CAN interface such as `vcan0`. Never attach experimental traffic generators to a real vehicle bus.
