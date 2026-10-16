# Detection Test Notes

This note records the intent of the focused regression tests in `tests/test_detection.py`.

## Covered behaviors

- **Feature vector contract:** a monitoring window returns eight numeric features and tracks frame/ID counts.
- **Empty windows:** no frames yield a zero-filled vector, zero frame rate, and no top CAN ID.
- **Duration guard:** a zero or negative duration is clamped to a small positive value, avoiding division by zero.
- **Unknown-ID classification:** sustained traffic from an ID absent from the calibration baseline can produce an alert.
- **Normal baseline:** ordinary synthetic traffic should not create a rule-based alert when the supplied ML score is non-anomalous.
- **DLC deviations:** multiple DLC mismatches for the same CAN ID count once per monitoring window.
- **Repeated payload behavior:** a burst containing one repeated payload should produce a replay ratio of 1.0.

## Run the tests

From the repository root, activate the project's virtual environment and run:

```bash
pytest -q
```

These are deterministic unit tests over synthetic message tuples. They do not require a live CAN interface or interact with a real vehicle.

## Scope and limitations

The tests validate specific feature-extraction and classification expectations. Passing them does not establish production readiness or prove detection performance on real vehicle traffic. All runtime CAN demonstrations must remain isolated to `vcan*` interfaces, as required by the project safety guidance.
