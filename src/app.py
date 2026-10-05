from __future__ import annotations

import sys
from collections import deque

from PyQt6.QtCore import QThread
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QFrame, QGridLayout, QHBoxLayout, QLabel, QMainWindow,
    QPushButton, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout,
    QWidget
)
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from src.config import DB_PATH, HISTORY_POINTS, INTERFACE
from src.database import Database
from src.monitor import CANMonitor


class Chart(FigureCanvas):
    def __init__(self, title: str, ylabel: str):
        self.figure = Figure(figsize=(5, 2.5), tight_layout=True)
        self.ax = self.figure.add_subplot(111)
        super().__init__(self.figure)
        self.title = title
        self.ylabel = ylabel
        self.ax.set_title(title, fontsize=10)
        self.ax.set_ylabel(ylabel)
        self.ax.grid(True, alpha=0.25)

    def update(self, xs, ys):
        self.ax.clear()
        self.ax.plot(xs, ys)
        self.ax.set_title(self.title, fontsize=10)
        self.ax.set_ylabel(self.ylabel)
        self.ax.grid(True, alpha=0.25)
        self.figure.canvas.draw_idle()


class Card(QFrame):
    def __init__(self, title: str, value: str = "—"):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        self.title = QLabel(title)
        self.title.setStyleSheet("font-size: 11px;")
        self.value = QLabel(value)
        self.value.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(self.title)
        layout.addWidget(self.value)

    def set_value(self, text: str):
        self.value.setText(text)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CAN-Sentinel V2 — Automotive Security Operations Center")
        self.resize(1280, 820)

        self.db = Database(DB_PATH)
        self.thread = QThread(self)
        self.monitor = CANMonitor(self.db, INTERFACE)
        self.monitor.moveToThread(self.thread)

        self.frame_rows = deque(maxlen=300)
        self.fps_history = deque(maxlen=HISTORY_POINTS)
        self.anomaly_history = deque(maxlen=HISTORY_POINTS)
        self.incident_count = 0

        self._build_ui()
        self._connect_signals()

        self.thread.started.connect(self.monitor.run)
        self.thread.start()

        self.reload_incidents()
        self.reload_ecus()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)

        header = QHBoxLayout()
        title = QLabel("CAN-SENTINEL")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        subtitle = QLabel("Automotive Security Operations Center • Virtual CAN Lab")
        subtitle.setStyleSheet("font-size: 13px;")
        left = QVBoxLayout()
        left.addWidget(title)
        left.addWidget(subtitle)
        header.addLayout(left)
        header.addStretch()

        self.status = QLabel("BOOTING")
        self.status.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        header.addWidget(self.status)
        outer.addLayout(header)

        self.cards = {}
        cards_layout = QGridLayout()
        for idx, name in enumerate([
            "Frames / sec", "Unique IDs", "Anomaly Score",
            "Incidents", "Top CAN ID", "System State"
        ]):
            self.cards[name] = Card(name)
            cards_layout.addWidget(self.cards[name], idx // 3, idx % 3)
        outer.addLayout(cards_layout)

        tabs = QTabWidget()
        self.overview_tab = self._build_overview()
        self.traffic_tab = self._build_traffic()
        self.ecu_tab = self._build_ecu()
        self.incident_tab = self._build_incidents()
        tabs.addTab(self.overview_tab, "Overview")
        tabs.addTab(self.traffic_tab, "Traffic")
        tabs.addTab(self.ecu_tab, "ECU Fingerprints")
        tabs.addTab(self.incident_tab, "Incidents")
        outer.addWidget(tabs)

        self.stop_button = QPushButton("Stop Monitor")
        self.stop_button.clicked.connect(self.stop_monitor)
        outer.addWidget(self.stop_button)

    def _build_overview(self):
        w = QWidget()
        layout = QHBoxLayout(w)
        self.fps_chart = Chart("Live CAN Traffic", "Frames / sec")
        self.anomaly_chart = Chart("Isolation Forest Score", "Score")
        layout.addWidget(self.fps_chart)
        layout.addWidget(self.anomaly_chart)
        return w

    def _build_traffic(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        self.traffic_table = QTableWidget(0, 4)
        self.traffic_table.setHorizontalHeaderLabels(["Time", "CAN ID", "DLC", "Payload"])
        layout.addWidget(self.traffic_table)
        return w

    def _build_ecu(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        self.ecu_table = QTableWidget(0, 7)
        self.ecu_table.setHorizontalHeaderLabels([
            "CAN ID", "Observed Count", "Rate", "Period",
            "DLC", "Fingerprint Score", "Status"
        ])
        layout.addWidget(self.ecu_table)
        return w

    def _build_incidents(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        self.incident_table = QTableWidget(0, 8)
        self.incident_table.setHorizontalHeaderLabels([
            "Timestamp", "Severity", "Classification", "CAN ID",
            "ML Score", "Confidence", "Reason", "Evidence"
        ])
        layout.addWidget(self.incident_table)
        return w

    def _connect_signals(self):
        self.monitor.status_signal.connect(self.on_status)
        self.monitor.metrics.connect(self.on_metrics)
        self.monitor.frame_signal.connect(self.on_frame)
        self.monitor.incident_signal.connect(self.on_incident)
        self.monitor.ecu_signal.connect(self.on_ecu)

    def on_status(self, text: str):
        self.status.setText(text)
        self.cards["System State"].set_value(text)

    def on_metrics(self, m: dict):
        self.cards["Frames / sec"].set_value(f"{m.get('fps', 0):.1f}")
        self.cards["Unique IDs"].set_value(str(m.get("unique_ids", 0)))
        self.cards["Anomaly Score"].set_value(f"{m.get('anomaly', 0):+.3f}")
        self.cards["Top CAN ID"].set_value(
            f"0x{m['top_id']:03X}" if m.get("top_id") is not None else "—"
        )
        self.fps_history.append(m.get("fps", 0))
        self.anomaly_history.append(m.get("anomaly", 0))
        xs = list(range(len(self.fps_history)))
        self.fps_chart.update(xs, list(self.fps_history))
        self.anomaly_chart.update(xs, list(self.anomaly_history))

    def on_frame(self, row: dict):
        self.frame_rows.append(row)
        self.traffic_table.insertRow(0)
        values = [row["time"], f"0x{row['can_id']:03X}", str(row["dlc"]), row["data"]]
        for c, value in enumerate(values):
            self.traffic_table.setItem(0, c, QTableWidgetItem(value))
        while self.traffic_table.rowCount() > 150:
            self.traffic_table.removeRow(self.traffic_table.rowCount() - 1)

    def on_incident(self, e: dict):
        self.incident_count += 1
        self.cards["Incidents"].set_value(str(self.incident_count))

        self.incident_table.insertRow(0)
        values = [
            e["timestamp"], e["severity"], e["classification"],
            f"0x{e['can_id']:03X}" if e["can_id"] is not None else "—",
            f"{e['anomaly_score']:+.4f}", f"{e['confidence']:.2f}",
            e["reason"], e["evidence"]
        ]
        for c, value in enumerate(values):
            self.incident_table.setItem(0, c, QTableWidgetItem(str(value)))

    def on_ecu(self, e: dict):
        can_id = e["can_id"]
        existing = None
        for r in range(self.ecu_table.rowCount()):
            if self.ecu_table.item(r, 0) and self.ecu_table.item(r, 0).text() == f"0x{can_id:03X}":
                existing = r
                break

        if existing is None:
            row = self.ecu_table.rowCount()
            self.ecu_table.insertRow(row)
        else:
            row = existing

        values = [
            f"0x{can_id:03X}", str(e["count"]), f"{e['rate']:.1f} fps",
            f"{e['period'] * 1000:.2f} ms", str(e["dlc"]),
            f"{e['score']:.2f}", e["status"]
        ]
        for c, value in enumerate(values):
            self.ecu_table.setItem(row, c, QTableWidgetItem(value))

    def reload_incidents(self):
        rows = self.db.recent_incidents(100)
        self.incident_count = len(rows)
        self.cards["Incidents"].set_value(str(self.incident_count))
        self.incident_table.setRowCount(0)
        for rowdata in rows:
            row = self.incident_table.rowCount()
            self.incident_table.insertRow(row)
            values = [
                rowdata[0], rowdata[1], rowdata[2],
                f"0x{rowdata[3]:03X}" if rowdata[3] is not None else "—",
                f"{rowdata[4]:+.4f}", f"{rowdata[5]:.2f}",
                rowdata[6], ""
            ]
            for c, value in enumerate(values):
                self.incident_table.setItem(row, c, QTableWidgetItem(str(value)))

    def reload_ecus(self):
        self.ecu_table.setRowCount(0)
        for rowdata in self.db.ecu_profiles():
            row = self.ecu_table.rowCount()
            self.ecu_table.insertRow(row)
            values = [
                f"0x{rowdata[0]:03X}", str(rowdata[3]), f"{rowdata[4]:.1f} fps",
                f"{rowdata[5] * 1000:.2f} ms", str(rowdata[6]), "1.00", "BASELINE"
            ]
            for c, value in enumerate(values):
                self.ecu_table.setItem(row, c, QTableWidgetItem(value))

    def stop_monitor(self):
        self.monitor.stop()
        self.stop_button.setEnabled(False)
        self.status.setText("STOPPING")

    def closeEvent(self, event):
        self.monitor.stop()
        self.thread.quit()
        self.thread.wait(3000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
