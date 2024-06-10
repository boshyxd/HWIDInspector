import sys
import os
import wmi
import winreg
import datetime
import uuid
from getmac import get_mac_address
from PySide6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox

def get_hwid():
    c = wmi.WMI()
    bios_info = c.Win32_BIOS()[0]
    system_info = c.Win32_ComputerSystemProduct()[0]

    # Fetch BIOS Serial Number
    bios_serial = bios_info.SerialNumber if bios_info.SerialNumber else "Unknown"

    # Fetch Manufacturer and Model from different WMI classes
    computer_system = c.Win32_ComputerSystem()[0]
    manufacturer = computer_system.Manufacturer if computer_system.Manufacturer else "Unknown"
    model = computer_system.Model if computer_system.Model else "Unknown"

    hwid = system_info.UUID if system_info.UUID else "Unknown"

    return hwid, bios_serial, manufacturer, model

def get_mac():
    mac_address = get_mac_address()
    return mac_address if mac_address else "Unknown"

def get_last_changed():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001")
        timestamp, _ = winreg.QueryValueEx(key, "Last Known Good Time")
        last_changed = datetime.datetime.fromtimestamp(timestamp)
        return last_changed
    except FileNotFoundError:
        return "Registry key not found"
    except Exception as e:
        return f"An error occurred: {e}"

def update_hwid(new_hwid):
    try:
        c = wmi.WMI()
        system_info = c.Win32_ComputerSystemProduct()[0]
        system_info.UUID = new_hwid
        system_info.put()  # Save changes
        QMessageBox.information(None, "Success", "HWID updated successfully!")
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to update HWID: {e}")

class HWIDInspector(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("HWID Inspector")
        self.setFixedSize(400, 400)

        self.hwid_label = QLabel("Hardware ID (UUID): ", self)
        self.mac_label = QLabel("MAC Address: ", self)
        self.bios_label = QLabel("BIOS Serial Number: ", self)
        self.manufacturer_label = QLabel("Manufacturer: ", self)
        self.model_label = QLabel("Model: ", self)
        self.last_changed_label = QLabel("Last Changed/Updated: ", self)

        self.hwid_entry_label = QLabel("Enter new HWID: ", self)
        self.hwid_entry = QLineEdit(self)

        self.generate_hwid_button = QPushButton("Generate HWID", self)
        self.generate_hwid_button.clicked.connect(self.generate_hwid)

        self.change_hwid_button = QPushButton("Change HWID", self)
        self.change_hwid_button.clicked.connect(self.change_hwid)

        self.display_info_button = QPushButton("Refresh Info", self)
        self.display_info_button.clicked.connect(self.display_info)

        layout = QVBoxLayout()

        layout.addWidget(self.hwid_label)
        layout.addWidget(self.mac_label)
        layout.addWidget(self.bios_label)
        layout.addWidget(self.manufacturer_label)
        layout.addWidget(self.model_label)
        layout.addWidget(self.last_changed_label)
        
        hwid_entry_layout = QHBoxLayout()
        hwid_entry_layout.addWidget(self.hwid_entry_label)
        hwid_entry_layout.addWidget(self.hwid_entry)
        layout.addLayout(hwid_entry_layout)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.generate_hwid_button)
        button_layout.addWidget(self.change_hwid_button)
        button_layout.addWidget(self.display_info_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.display_info()

    def display_info(self):
        hwid, bios_serial, manufacturer, model = get_hwid()
        mac_address = get_mac()
        last_changed = get_last_changed()

        self.hwid_label.setText(f"Hardware ID (UUID): {hwid}")
        self.mac_label.setText(f"MAC Address: {mac_address}")
        self.bios_label.setText(f"BIOS Serial Number: {bios_serial}")
        self.manufacturer_label.setText(f"Manufacturer: {manufacturer}")
        self.model_label.setText(f"Model: {model}")
        self.last_changed_label.setText(f"Last Changed/Updated: {last_changed}")

    def change_hwid(self):
        new_hwid = self.hwid_entry.text()
        if new_hwid:
            update_hwid(new_hwid)
            self.display_info()
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a valid HWID.")

    def generate_hwid(self):
        new_hwid = str(uuid.uuid4())
        self.hwid_entry.setText(new_hwid)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Print the current working directory
    print("Current working directory:", os.getcwd())
    
    # Load and apply the dark theme stylesheet
    script_dir = os.path.dirname(os.path.realpath(__file__))
    stylesheet_path = os.path.join(script_dir, "dark_theme.qss")
    try:
        with open(stylesheet_path, "r") as stylesheet:
            app.setStyleSheet(stylesheet.read())
    except FileNotFoundError:
        print(f"Stylesheet file not found: {stylesheet_path}")
    
    inspector = HWIDInspector()
    inspector.show()
    sys.exit(app.exec())
