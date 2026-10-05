# CAN-Sentinel V2 — Project Report Skeleton

## Abstract

CAN-Sentinel V2 is a defensive automotive cybersecurity laboratory platform designed to detect suspicious behavior on a virtual Controller Area Network. It combines Linux SocketCAN telemetry, statistical feature engineering, ECU behavioral fingerprinting, deterministic attack-pattern classification, Isolation Forest anomaly detection, SQLite evidence storage, and a PyQt6 security operations dashboard.

## 1. Introduction

Modern vehicles contain many electronic control units (ECUs) that exchange time-sensitive messages. This project demonstrates how a monitoring system can establish a baseline of normal traffic and identify anomalous behavior in an isolated virtual network.

## 2. Problem Statement

The project addresses the challenge of identifying abnormal CAN traffic using message frequency, timing behavior, identifiers, and payload metadata.

## 3. Objectives

- Configure a Linux virtual CAN environment.
- Simulate normal ECU traffic.
- Collect raw frames.
- Learn a traffic baseline.
- Create ECU behavioral fingerprints.
- Detect anomalies with Isolation Forest.
- Classify simulated traffic anomalies.
- Persist incidents in SQLite.
- Visualize telemetry with a SOC-style UI.

## 4. Technologies Used

| Technology | Purpose |
|---|---|
| Linux SocketCAN | Virtual CAN transport |
| C | Low-level raw frame capture |
| Python | Monitoring and analytics |
| python-can | CAN interface access |
| NumPy | Feature processing |
| scikit-learn | Isolation Forest |
| PyQt6 | Desktop SOC dashboard |
| Matplotlib | Live charts |
| SQLite | Local evidence store |

## 5. Modules

### 5.1 Virtual CAN Environment
Use `vcan0` to isolate the demonstration.

### 5.2 Synthetic Vehicle Generator
Simulates RPM, speed, temperature, and brake-state traffic.

### 5.3 Raw CAN Sniffer
Uses Linux PF_CAN / CAN_RAW sockets.

### 5.4 Feature Extraction
Builds per-window traffic statistics.

### 5.5 ML Engine
Learns baseline feature distributions with Isolation Forest.

### 5.6 ECU Fingerprinting
Estimates expected rate, timing period, and DLC.

### 5.7 Incident Classifier
Maps observed evidence to high-level labels such as CAN Flood / DoS and Unknown-ID Injection.

### 5.8 SOC Dashboard
Displays live telemetry, traffic, ECU profiles, and incidents.

## 6. Testing

### Baseline Test
1. Start the normal generator.
2. Complete calibration.
3. Confirm `MONITORING` status.
4. Record normal frame rate and ECU profile values.

### Flood Test
1. Stop normal traffic.
2. Start flood mode using `0x321`.
3. Confirm a high-rate alert.
4. Capture a screenshot of the incident.

### Injection Test
1. Run unknown-ID injection.
2. Confirm the unknown ID is flagged.
3. Record the classification and confidence.

### Replay-like Test
1. Run replay mode.
2. Confirm repeated-payload detection.

## 7. Results

Insert:
- dashboard overview screenshot
- live traffic screenshot
- ECU fingerprint screenshot
- incident screenshot
- C sniffer screenshot

## 8. Limitations

The implementation is an educational virtual-lab detector. Real vehicle traffic has protocol-specific semantics, gateway behavior, CAN-FD, diagnostics, and safety constraints that require substantially more validation.

## 9. Future Work

- sequence-aware models
- CAN-FD
- gateway correlation
- SIEM integration
- richer payload semantics
- hardware-in-the-loop testing
- signed forensic reports

## 10. Conclusion

CAN-Sentinel V2 demonstrates an end-to-end defensive workflow from telemetry collection through detection, classification, evidence storage, and operator visualization.
