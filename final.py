import sys
import subprocess
import socket
import time
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextBrowser,
    QProgressBar,
    QTabWidget,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QButtonGroup,
    QRadioButton,
    QFileDialog,
)
from PyQt5.QtCore import QThread, pyqtSignal, QMutex, QMutexLocker
from PyQt5.QtGui import QFont

# === Thread Class for Port Scanning ===
class PortScannerThread(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, target_ip, start_port, end_port):
        super().__init__()
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.mutex = QMutex()  # Mutex for thread-safe stopping
        self.running = True

    def run(self):
        open_ports = []
        total_ports = self.end_port - self.start_port + 1

        try:
            target_ip = socket.gethostbyname(self.target_ip)  # Convert host name to IP address
        except socket.gaierror:
            try:
                target_ip = socket.gethostbyname(socket.gethostbyname(self.target_ip))  # Attempt to resolve IP directly
            except socket.gaierror:
                self.update_signal.emit(f'Invalid targeted IP or domain: {self.target_ip}')
                self.finished_signal.emit()
                return

        for port in range(self.start_port, self.end_port + 1):
            with QMutexLocker(self.mutex):
                if not self.running:
                    break

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            try:
                sock.connect((target_ip, port))
                open_ports.append(port)
                sock.close()
            except (socket.timeout, socket.error):
                pass

            progress = (port - self.start_port + 1) / total_ports * 100
            self.update_signal.emit(f"Scanning... {progress:.2f}%")

        with QMutexLocker(self.mutex):
            if open_ports:
                self.update_signal.emit(f'Open ports on {target_ip}: {", ".join(map(str, open_ports))}')
            else:
                self.update_signal.emit(f'No open ports found on {target_ip}')

        self.finished_signal.emit()

    def stop(self):
        with QMutexLocker(self.mutex):
            self.running = False

# === Thread Class for Ping Scanner ===
class PingScannerThread(QThread):
    update_signal = pyqtSignal(str)

    def __init__(self, target, packet_count=6, interval=1):
        super().__init__()
        self.target = target
        self.packet_count = packet_count
        self.interval = interval
        self.running = True

    def run(self):
        sent_count = 0
        received_count = 0

        try:
            while self.running and sent_count < self.packet_count:
                result = subprocess.run(["ping", "-n", "1", self.target], capture_output=True, text=True)
                self.update_signal.emit(result.stdout)
                time.sleep(self.interval)

                sent_count += 1
                if "Reply from" in result.stdout:
                    received_count += 1

        except subprocess.CalledProcessError:
            self.update_signal.emit(f"Ping to {self.target} failed.")

        self.update_signal.emit(f"\nPing statistics for {self.target}:\n"
                                 f"    Packets: Sent = {sent_count}, Received = {received_count}, "
                                 f"Lost = {sent_count - received_count} ({(sent_count - received_count) / sent_count * 100}% loss)")

    def stop(self):
        self.running = False

# === Thread Class for Service Detection ===
class ServiceDetectionThread(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, target_ip, start_port, end_port):
        super().__init__()
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.mutex = QMutex()  # Mutex for thread-safe stopping
        self.running = True

    def run(self):
        open_services = {}
        total_ports = self.end_port - self.start_port + 1

        try:
            target_ip = socket.gethostbyname(self.target_ip)  # Convert host name to IP address
        except socket.gaierror:
            try:
                target_ip = socket.gethostbyname(socket.gethostbyname(self.target_ip))  # Attempt to resolve IP directly
            except socket.gaierror:
                self.update_signal.emit(f'Invalid targeted IP or domain: {self.target_ip}')
                self.finished_signal.emit()
                return

        for port in range(self.start_port, self.end_port + 1):
            with QMutexLocker(self.mutex):
                if not self.running:
                    break

            try:
                service_info = socket.getservbyport(port)
                open_services[port] = service_info
            except (socket.error, socket.herror, socket.gaierror, socket.timeout):
                pass

            progress = (port - self.start_port + 1) / total_ports * 100
            progress_message = f"Scanning... {progress:.2f}%"
            self.update_signal.emit(progress_message)

        with QMutexLocker(self.mutex):
            if open_services:
                self.update_signal.emit(f'Services detected on {target_ip}:')
                for port, service in open_services.items():
                    self.update_signal.emit(f'Port {port}: {service}')
            else:
                self.update_signal.emit(f'No services detected on {target_ip}')

        self.finished_signal.emit()
        

    def stop(self):
        with QMutexLocker(self.mutex):
            self.running = False


# === GUI Class ===
class NetworkScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Network Scanner')
        self.setGeometry(100, 100, 1200, 800)  # Increased window size

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.tabs = QTabWidget(self.central_widget)
        self.tabs.setGeometry(20, 20, 1160, 740)  # Increased tab widget size

        # Tab 1: Port Scanner
        self.tab_port_scanner = QWidget()
        self.tabs.addTab(self.tab_port_scanner, "Port Scanner")
        self.init_port_scanner_tab()

        # Tab 2: Ping Scanner
        self.tab_ping_scanner = QWidget()
        self.tabs.addTab(self.tab_ping_scanner, "Ping")
        self.init_ping_tab()

        # Tab 3: Service Detection
        self.tab_service_detection = QWidget()
        self.tabs.addTab(self.tab_service_detection, "Service Detection")
        self.init_service_detection_tab()

    def init_port_scanner_tab(self):
        layout = QVBoxLayout()

        self.label_ip = QLabel('Enter target IP or host name', self.tab_port_scanner)
        layout.addWidget(self.label_ip)

        self.ip_input = QLineEdit(self.tab_port_scanner)
        layout.addWidget(self.ip_input)

        self.scan_mode_group = QButtonGroup(self.tab_port_scanner)

        self.scan_specific_port_radio = QRadioButton('Scan Specific Port', self.tab_port_scanner)
        self.scan_specific_port_radio.setChecked(True)
        self.scan_mode_group.addButton(self.scan_specific_port_radio)

        self.scan_port_range_radio = QRadioButton('Scan Port Range', self.tab_port_scanner)
        self.scan_mode_group.addButton(self.scan_port_range_radio)

        scan_mode_layout = QHBoxLayout()
        scan_mode_layout.addWidget(self.scan_specific_port_radio)
        scan_mode_layout.addWidget(self.scan_port_range_radio)
        layout.addLayout(scan_mode_layout)

        self.port_range_label = QLabel('Enter port range (e.g., 20-80):', self.tab_port_scanner)
        layout.addWidget(self.port_range_label)

        self.port_range_input = QLineEdit(self.tab_port_scanner)
        layout.addWidget(self.port_range_input)

        self.port_number_label = QLabel('Enter specific port number:', self.tab_port_scanner)
        layout.addWidget(self.port_number_label)

        self.port_number_input = QLineEdit(self.tab_port_scanner)
        layout.addWidget(self.port_number_input)

        self.scan_button = QPushButton('Scan Ports', self.tab_port_scanner)
        self.scan_button.clicked.connect(self.start_port_scan)
        layout.addWidget(self.scan_button)

        self.result_browser_port = QTextBrowser(self.tab_port_scanner)
        layout.addWidget(self.result_browser_port)

        self.progress_bar_port = QProgressBar(self.tab_port_scanner)
        layout.addWidget(self.progress_bar_port)

        button_layout = QHBoxLayout()
        self.reset_button_port = QPushButton('Reset', self.tab_port_scanner)
        self.reset_button_port.clicked.connect(self.reset_port_scan)
        button_layout.addWidget(self.reset_button_port)

        self.save_button_port = QPushButton('Save Result', self.tab_port_scanner)
        self.save_button_port.clicked.connect(self.save_port_scan_result)
        button_layout.addWidget(self.save_button_port)

        layout.addLayout(button_layout)

        self.tab_port_scanner.setLayout(layout)

    def start_port_scan(self):
        target_ip = self.ip_input.text()

        if self.scan_specific_port_radio.isChecked():
            try:
                port = int(self.port_number_input.text())
            except ValueError:
                self.result_browser_port.append('Invalid port number. Please enter a valid port number.')
                return

            start_port = end_port = port
        else:
            port_range = self.port_range_input.text()
            try:
                start_port, end_port = map(int, port_range.split('-'))
            except ValueError:
                self.result_browser_port.append('Invalid port range')
                return

            if start_port > end_port:
                start_port, end_port = end_port, start_port

        self.result_browser_port.clear()
        self.progress_bar_port.setValue(0)

        self.stop_port_scanner_thread()

        self.port_scanner_thread = PortScannerThread(target_ip, start_port, end_port)
        self.port_scanner_thread.update_signal.connect(self.update_port_scan_result)
        self.port_scanner_thread.finished_signal.connect(self.port_scan_finished)
        self.port_scanner_thread.start()

    def update_port_scan_result(self, message):
        if message.startswith('Scanning'):
            progress_value = float(message.split()[-1][:-1])
            self.progress_bar_port.setValue(int(progress_value))
        else:
            self.result_browser_port.append(message)

    def port_scan_finished(self):
        self.scan_button.setEnabled(True)

    def stop_port_scanner_thread(self):
        if hasattr(self, 'port_scanner_thread'):
            self.port_scanner_thread.stop()
            self.port_scanner_thread.wait()

    def reset_port_scan(self):
        self.ip_input.clear()
        self.port_range_input.clear()
        self.port_number_input.clear()
        self.result_browser_port.clear()
        self.progress_bar_port.setValue(0)

    def save_port_scan_result(self):
        result_text = self.result_browser_port.toPlainText()
        if result_text:
            file_path, _ = QFileDialog.getSaveFileName(self, 'Save Result', '', 'Text Files (*.txt)')
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(result_text)

    def init_ping_tab(self):
        layout = QVBoxLayout()

        self.label_target = QLabel('Enter target IP or domain:', self.tab_ping_scanner)
        layout.addWidget(self.label_target)

        self.target_input = QLineEdit(self.tab_ping_scanner)
        layout.addWidget(self.target_input)

        self.ping_button = QPushButton('Ping', self.tab_ping_scanner)
        self.ping_button.clicked.connect(self.start_ping)
        layout.addWidget(self.ping_button)

        self.continuous_ping_button = QPushButton('Continuous Ping', self.tab_ping_scanner)
        self.continuous_ping_button.clicked.connect(self.start_continuous_ping)
        layout.addWidget(self.continuous_ping_button)

        self.stop_button = QPushButton('Stop', self.tab_ping_scanner)
        self.stop_button.clicked.connect(self.stop_ping)
        layout.addWidget(self.stop_button)

        self.result_browser_ping = QTextBrowser(self.tab_ping_scanner)
        layout.addWidget(self.result_browser_ping)

        self.reset_button_ping = QPushButton('Reset', self.tab_ping_scanner)
        self.reset_button_ping.clicked.connect(self.reset_ping)
        layout.addWidget(self.reset_button_ping)

        self.tab_ping_scanner.setLayout(layout)

        self.ping_scanner_thread = None

    def start_ping(self):
        target = self.target_input.text()
        self.result_browser_ping.clear()

        result = subprocess.run(["ping", "-n", "1", target], capture_output=True, text=True)
        self.result_browser_ping.append(result.stdout)

    def reset_ping(self):
        self.target_input.clear()
        self.result_browser_ping.clear()

    def start_continuous_ping(self):
        target = self.target_input.text()
        self.result_browser_ping.clear()

        self.stop_ping()  # Stop any existing continuous ping

        self.ping_scanner_thread = PingScannerThread(target, packet_count=6, interval=1)
        self.ping_scanner_thread.update_signal.connect(self.update_ping_result)
        self.ping_scanner_thread.start()

    def stop_ping(self):
        if self.ping_scanner_thread and self.ping_scanner_thread.isRunning():
            self.ping_scanner_thread.stop()
            self.ping_scanner_thread.wait()

    def update_ping_result(self, message):
        self.result_browser_ping.append(message)
        QApplication.processEvents()  # Process events to update the GUI

    def init_service_detection_tab(self):
        layout = QVBoxLayout()

        self.label_ip_service = QLabel('Enter target IP or host name', self.tab_service_detection)
        layout.addWidget(self.label_ip_service)

        self.ip_input_service = QLineEdit(self.tab_service_detection)
        layout.addWidget(self.ip_input_service)

        self.scan_mode_group_service = QButtonGroup(self.tab_service_detection)

        self.scan_specific_port_radio_service = QRadioButton('Scan Specific Port', self.tab_service_detection)
        self.scan_specific_port_radio_service.setChecked(True)
        self.scan_mode_group_service.addButton(self.scan_specific_port_radio_service)

        self.scan_port_range_radio_service = QRadioButton('Scan Port Range', self.tab_service_detection)
        self.scan_mode_group_service.addButton(self.scan_port_range_radio_service)

        scan_mode_layout_service = QHBoxLayout()
        scan_mode_layout_service.addWidget(self.scan_specific_port_radio_service)
        scan_mode_layout_service.addWidget(self.scan_port_range_radio_service)
        layout.addLayout(scan_mode_layout_service)

        self.port_range_label_service = QLabel('Enter port range (e.g., 20-80):', self.tab_service_detection)
        layout.addWidget(self.port_range_label_service)

        self.port_range_input_service = QLineEdit(self.tab_service_detection)
        layout.addWidget(self.port_range_input_service)

        self.port_number_label_service = QLabel('Enter specific port number:', self.tab_service_detection)
        layout.addWidget(self.port_number_label_service)

        self.port_number_input_service = QLineEdit(self.tab_service_detection)
        layout.addWidget(self.port_number_input_service)

        self.scan_button_service = QPushButton('Scan Services', self.tab_service_detection)
        self.scan_button_service.clicked.connect(self.start_service_scan)
        layout.addWidget(self.scan_button_service)

        self.result_browser_service = QTextBrowser(self.tab_service_detection)
        layout.addWidget(self.result_browser_service)

        self.progress_bar_service = QProgressBar(self.tab_service_detection)
        layout.addWidget(self.progress_bar_service)

        button_layout_service = QHBoxLayout()
        self.reset_button_service = QPushButton('Reset', self.tab_service_detection)
        self.reset_button_service.clicked.connect(self.reset_service_scan)
        button_layout_service.addWidget(self.reset_button_service)

        self.save_button_service = QPushButton('Save Result', self.tab_service_detection)
        self.save_button_service.clicked.connect(self.save_service_scan_result)
        button_layout_service.addWidget(self.save_button_service)

        layout.addLayout(button_layout_service)

        self.tab_service_detection.setLayout(layout)

    def start_service_scan(self):
        target_ip = self.ip_input_service.text()

        if self.scan_specific_port_radio_service.isChecked():
            try:
                port = int(self.port_number_input_service.text())
            except ValueError:
                self.result_browser_service.append('Invalid port number. Please enter a valid port number.')
                return

            start_port = end_port = port
        else:
            port_range = self.port_range_input_service.text()
            try:
                start_port, end_port = map(int, port_range.split('-'))
            except ValueError:
                self.result_browser_service.append('Invalid port range')
                return

            if start_port > end_port:
                start_port, end_port = end_port, start_port

        self.result_browser_service.clear()
        self.progress_bar_service.setValue(0)

        self.stop_service_detection_thread()

        self.service_detection_thread = ServiceDetectionThread(target_ip, start_port, end_port)
        self.service_detection_thread.update_signal.connect(self.update_service_scan_result)
        self.service_detection_thread.finished_signal.connect(self.service_scan_finished)
        self.service_detection_thread.start()

    def update_service_scan_result(self, message):
        if message.startswith('Scanning'):
            progress_value = float(message.split()[-1][:-1])
            self.progress_bar_service.setValue(progress_value)
        else:
            self.result_browser_service.append(message)

    def service_scan_finished(self):
        self.scan_button_service.setEnabled(True)

    def stop_service_detection_thread(self):
        if hasattr(self, 'service_detection_thread'):
            self.service_detection_thread.stop()
            self.service_detection_thread.wait()

    def reset_service_scan(self):
        self.ip_input_service.clear()
        self.port_range_input_service.clear()
        self.port_number_input_service.clear()
        self.result_browser_service.clear()
        self.progress_bar_service.setValue(0)

    def save_service_scan_result(self):
        result_text = self.result_browser_service.toPlainText()
        if result_text:
            file_path, _ = QFileDialog.getSaveFileName(self, 'Save Result', '', 'Text Files (*.txt)')
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(result_text)

def main():
    app = QApplication(sys.argv)
    
    # Set a custom font for the entire application
    font = QFont("Arial", 10)  
    app.setFont(font)

    
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec_())



if __name__ == '__main__':
    main()