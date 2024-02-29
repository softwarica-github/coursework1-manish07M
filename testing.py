import unittest
import logging
from unittest.mock import patch
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtTest import QTest
from final import NetworkScannerGUI, PortScannerThread, ServiceDetectionThread


class TestNetworkScannerGUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Configure logging
        logger = logging.getLogger()
        file_handler = logging.FileHandler('test_output.log')
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    def setUp(self):
        self.app = QApplication(sys.argv)
        self.window = NetworkScannerGUI()

    def tearDown(self):
        self.window.close()

    def test_port_scan_specific_port(self):
        logging.info("Running test_port_scan_specific_port")
        # Simulate user input for scanning a specific port
        ip_input = self.window.ip_input
        port_number_input = self.window.port_number_input
        scan_button = self.window.scan_button
        result_browser_port = self.window.result_browser_port

        QTest.keyClicks(ip_input, "127.0.0.1")
        QTest.keyClicks(port_number_input, "80")
        QTest.mouseClick(scan_button, Qt.LeftButton)

        # Wait for the scan to complete
        QTest.qWait(3000)

        # Check if result browser has output
        result = result_browser_port.toPlainText()
        logging.info(f"Port scan result: {result}")
        self.assertNotEqual(result, "")

    def test_port_scan_port_range(self):
        # Simulate user input for scanning a port range
        ip_input = self.window.ip_input
        port_range_input = self.window.port_range_input
        scan_button = self.window.scan_button
        result_browser_port = self.window.result_browser_port

        QTest.keyClicks(ip_input, "127.0.0.1")
        QTest.keyClicks(port_range_input, "20-80")
        QTest.mouseClick(scan_button, Qt.LeftButton)

        # Wait for the scan to complete
        QTest.qWait(5000)

        # Check if result browser has output
        result = result_browser_port.toPlainText()
        self.assertNotEqual(result, "")


    def test_service_detection_no_services_found(self):
        # Simulate user input for service detection where no services are found
        ip_input_service = self.window.ip_input_service
        port_number_input_service = self.window.port_number_input_service
        scan_button_service = self.window.scan_button_service
        result_browser_service = self.window.result_browser_service

        QTest.keyClicks(ip_input_service, "127.0.0.1")
        QTest.keyClicks(port_number_input_service, "9999")  
        QTest.mouseClick(scan_button_service, Qt.LeftButton)

        
        QTest.qWait(3000)

        # Check if result browser has output indicating no services found
        result = result_browser_service.toPlainText()
        self.assertIn("No services detected on 127.0.0.1", result)


class TestPortScannerThread(unittest.TestCase):
    def test_port_scanner_thread(self):
        # Test the behavior of the port scanner thread
        # Instantiate the port scanner thread and verify its functionality
        target_ip = "127.0.0.1"
        start_port = 1
        end_port = 100

        # Create an instance of PortScannerThread
        port_scanner_thread = PortScannerThread(target_ip, start_port, end_port)

        # Connect signals to slots for updating and finishing
        port_scanner_thread.update_signal.connect(self.on_update)
        port_scanner_thread.finished_signal.connect(self.on_finished)

        # Start the thread
        port_scanner_thread.start()

        # Simulate waiting for the thread to finish
        QTest.qWait(5000)  

    def on_update(self, message):
        print("Update:", message)

    def on_finished(self):
        print("Thread finished.")



class pingScannerThread(unittest.TestCase):
    def setUp(self):
        self.app = QApplication([])  

    def tearDown(self):
        self.app.quit() 

    def test_ping_scan_single_ping(self):
        # Create an instance of NetworkScannerGUI
        window = NetworkScannerGUI()

        # Simulate user input for single ping
        target_input = window.target_input
        ping_button = window.ping_button
        result_browser_ping = window.result_browser_ping

        QTest.keyClicks(target_input, "127.0.0.1")
        QTest.mouseClick(ping_button, Qt.LeftButton)

        QTest.qWait(5000)

        # Check if result browser has output
        result = result_browser_ping.toPlainText()
        self.assertNotEqual(result, "")

    def test_ping_scan_continuous_ping(self):
        # Create an instance of NetworkScannerGUI
        window = NetworkScannerGUI()

        # Simulate user input for continuous ping
        target_input = window.target_input
        continuous_ping_button = window.continuous_ping_button
        stop_button = window.stop_button
        result_browser_ping = window.result_browser_ping

        QTest.keyClicks(target_input, "127.0.0.1")
        QTest.mouseClick(continuous_ping_button, Qt.LeftButton)

        # Wait for some time to allow continuous ping to run
        QTest.qWait(5000)

        # Stop continuous ping
        QTest.mouseClick(stop_button, Qt.LeftButton)

        # Check if result browser has output
        result = result_browser_ping.toPlainText()
        self.assertNotEqual(result, "")

class TestServiceDetectionThread(unittest.TestCase):
    def setUp(self):
        self.app = QApplication([])

    def tearDown(self):
        self.app.quit() 

    def test_service_detection_thread(self):
        # Test the behavior of the service detection thread
        # Instantiate the service detection thread and verify its functionality
        target_ip = "127.0.0.1"
        start_port = 1
        end_port = 100

        # Create an instance of ServiceDetectionThread
        service_detection_thread = ServiceDetectionThread(target_ip, start_port, end_port)

        # Connect signals to slots for updating and finishing
        service_detection_thread.update_signal.connect(self.on_update)
        service_detection_thread.finished_signal.connect(self.on_finished)

        # Start the thread
        service_detection_thread.start()

        # Simulate waiting for the thread to finish
        QTest.qWait(5000) 

    def on_update(self, message):
        # Slot for handling update signals from the thread
        print("Update:", message)

    def on_finished(self):
        # Slot for handling finished signals from the thread
        print("Thread finished.")

if __name__ == '__main__':
    unittest.main()
