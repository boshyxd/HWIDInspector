import sys
import os
import wmi
import winreg
import datetime
import uuid
import ctypes
import re
import subprocess
import threading
from getmac import get_mac_address
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QTextEdit,
    QFileDialog,
    QComboBox,
)
from PySide6.QtCore import QTimer

def get_hwid():
    try:
        c = wmi.WMI(namespace=r"root\\CIMV2")
    except Exception:
        return "Unknown", "Unknown", "Unknown", "Unknown"

    # BIOS serial
    try:
        bios_list = c.Win32_BIOS()
        bios_info = bios_list[0] if bios_list else None
        bios_serial = getattr(bios_info, "SerialNumber", None) or "Unknown"
    except Exception:
        bios_serial = "Unknown"

    # Manufacturer / Model
    try:
        cs_list = c.Win32_ComputerSystem()
        computer_system = cs_list[0] if cs_list else None
        manufacturer = getattr(computer_system, "Manufacturer", None) or "Unknown"
        model = getattr(computer_system, "Model", None) or "Unknown"
    except Exception:
        manufacturer, model = "Unknown", "Unknown"

    # UUID / HWID
    try:
        csp_list = c.Win32_ComputerSystemProduct()
        system_info = csp_list[0] if csp_list else None
        hwid = getattr(system_info, "UUID", None) or "Unknown"
    except Exception:
        hwid = "Unknown"

    return hwid, bios_serial, manufacturer, model

def get_mac():
    mac_address = get_mac_address()
    return mac_address if mac_address else "Unknown"

def get_last_changed():
    try:
        profile_id = get_active_hw_profile_id()
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\{profile_id}",
        )
        timestamp, _ = winreg.QueryValueEx(key, "Last Known Good Time")
        last_changed = datetime.datetime.fromtimestamp(timestamp)
        return last_changed
    except FileNotFoundError:
        return "Registry key not found"
    except Exception as e:
        return f"An error occurred: {e}"

def get_active_hw_profile_id():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\IDConfigDB\CurrentConfig",
            0,
            winreg.KEY_READ,
        ) as key:
            val, _ = winreg.QueryValueEx(key, "CurrentConfig")
            try:
                idx = int(val)
            except Exception:
                try:
                    idx = int(str(val).strip())
                except Exception:
                    idx = 1
            return f"{idx:04d}"
    except Exception:
        return "0001"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def normalize_guid(raw):
    try:
        u = uuid.UUID(str(raw))
        machine_guid = str(u)  # no braces
        hwprofile_guid = "{" + str(u).upper() + "}"
        return machine_guid, hwprofile_guid
    except Exception:
        return None, None

def get_machine_guid():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as key:
            val, _ = winreg.QueryValueEx(key, "MachineGuid")
            return val
    except Exception:
        return "Unknown"

def set_machine_guid(new_guid):
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_SET_VALUE | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as key:
            winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, new_guid)
        return True
    except PermissionError:
        QMessageBox.critical(None, "Permission Denied", "Administrator privileges are required to change MachineGuid.")
        return False
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to change MachineGuid: {e}")
        return False

def get_hw_profile_guid():
    try:
        profile_id = get_active_hw_profile_id()
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\{profile_id}",
            0,
            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as key:
            val, _ = winreg.QueryValueEx(key, "HwProfileGuid")
            return val
    except Exception:
        return "Unknown"

def set_hw_profile_guid(new_guid):
    try:
        profile_id = get_active_hw_profile_id()
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\{profile_id}",
            0,
            winreg.KEY_SET_VALUE | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as key:
            winreg.SetValueEx(key, "HwProfileGuid", 0, winreg.REG_SZ, new_guid)
        return True
    except PermissionError:
        QMessageBox.critical(None, "Permission Denied", "Administrator privileges are required to change HwProfileGuid.")
        return False
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to change HwProfileGuid: {e}")
        return False

# ---- Computer name and InstallationID helpers ----

def get_computer_name():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
            0,
            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as key:
            val, _ = winreg.QueryValueEx(key, "ComputerName")
            return val
    except Exception:
        return os.environ.get("COMPUTERNAME", "Unknown")

def rename_computer(new_name):
    if not is_admin():
        QMessageBox.warning(None, "Administrator Required", "Renaming the computer requires Administrator privileges.")
        return False
    if not new_name or len(new_name) > 15:
        QMessageBox.warning(None, "Input Error", "Computer name must be 1-15 characters.")
        return False
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            f"Rename-Computer -NewName '{new_name}' -Force -PassThru"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            QMessageBox.information(None, "Rename Scheduled", "Hostname changed. Reboot is required for full effect.")
            return True
        else:
            QMessageBox.critical(None, "Rename Failed", result.stderr or "Failed to rename computer.")
            return False
    except Exception as e:
        QMessageBox.critical(None, "Rename Error", str(e))
        return False

def get_installation_id():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            0,
            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as key:
            val, _ = winreg.QueryValueEx(key, "InstallationID")
            return val
    except FileNotFoundError:
        return "(not set)"
    except Exception:
        return "Unknown"

def set_installation_id(new_id):
    if not is_admin():
        QMessageBox.warning(None, "Administrator Required", "Changing InstallationID requires Administrator privileges.")
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            0,
            winreg.KEY_SET_VALUE | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as key:
            winreg.SetValueEx(key, "InstallationID", 0, winreg.REG_SZ, str(new_id))
        QMessageBox.information(None, "Updated", "InstallationID updated. A reboot may be required for some apps to read it.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to set InstallationID: {e}")
        return False

def update_hwid(new_hwid):
    if not is_admin():
        QMessageBox.warning(
            None,
            "Administrator Required",
            (
                "Changing identifiers requires running as Administrator.\n"
                "Please close the app and re-launch it with elevated privileges."
            ),
        )
        return False, None, None

    machine_guid, hwprofile_guid = normalize_guid(new_hwid)
    if not machine_guid:
        QMessageBox.warning(None, "Input Error", "Please enter a valid GUID.")
        return False, None, None

    prev_machine = get_machine_guid()
    prev_profile = get_hw_profile_guid()

    ok1 = set_machine_guid(machine_guid)
    ok2 = set_hw_profile_guid(hwprofile_guid)

    if ok1 or ok2:
        QMessageBox.information(
            None,
            "Change Applied",
            (
                "Updated the following (restart recommended):\n"
                f"- MachineGuid: {prev_machine} -> {machine_guid}\n"
                f"- HwProfileGuid: {prev_profile} -> {hwprofile_guid}\n\n"
                "Note: System UUID (firmware) remains read-only and cannot be changed via WMI."
            ),
        )
        return True, prev_machine, prev_profile
    else:
        QMessageBox.critical(None, "No Changes", "Failed to change any identifier.")
        return False, prev_machine, prev_profile

def revert_identifiers(prev_machine, prev_profile):
    if not is_admin():
        QMessageBox.warning(
            None,
            "Administrator Required",
            (
                "Reverting identifiers requires running as Administrator.\n"
                "Please close the app and re-launch it with elevated privileges."
            ),
        )
        return False

    ok1 = True
    ok2 = True
    if prev_machine:
        ok1 = set_machine_guid(prev_machine)
    if prev_profile:
        ok2 = set_hw_profile_guid(prev_profile)
    if ok1 or ok2:
        QMessageBox.information(None, "Reverted", "Previous identifiers restored (restart recommended).")
        return True
    QMessageBox.critical(None, "No Changes", "Failed to revert identifiers.")
    return False

def restart_as_admin():
    if is_admin():
        QMessageBox.information(None, "Already Elevated", "The application is already running as Administrator.")
        return
    try:
        script = os.path.abspath(__file__)
        args = f'"{script}"'
        if len(sys.argv) > 1:
            extra = " ".join([f'"{a}"' for a in sys.argv[1:]])
            args += " " + extra
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
        if ret <= 32:
            QMessageBox.critical(None, "Elevation Failed", f"ShellExecute returned error code {ret}.")
            return
        app = QApplication.instance()
        if app is not None:
            app.quit()
    except Exception as e:
        QMessageBox.critical(None, "Elevation Error", f"Failed to restart as admin: {e}")

# ---- Network adapter spoofing (MAC) ----

NET_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

def get_primary_adapter_info():
    try:
        c = wmi.WMI(namespace=r"root\\CIMV2")
        # Prefer the adapter whose MAC matches getmac() output
        current_mac = get_mac()
        adapters = [a for a in c.Win32_NetworkAdapter(PhysicalAdapter=True) if getattr(a, 'MACAddress', None)]
        primary = None
        if current_mac and current_mac != "Unknown":
            for a in adapters:
                if str(a.MACAddress).lower().replace('-',':') == str(current_mac).lower().replace('-',':'):
                    primary = a
                    break
        if not primary:
            # fallback: first enabled adapter with MAC
            for a in adapters:
                if getattr(a, 'NetEnabled', False):
                    primary = a
                    break
            if not primary and adapters:
                primary = adapters[0]
        if not primary:
            return None
        # Return minimal info
        return {
            'Name': getattr(primary, 'Name', 'Unknown'),
            'GUID': getattr(primary, 'GUID', None),
            'MAC': getattr(primary, 'MACAddress', 'Unknown')
        }
    except Exception:
        return None

def list_adapters():
    try:
        c = wmi.WMI(namespace=r"root\\CIMV2")
        adapters = [a for a in c.Win32_NetworkAdapter(PhysicalAdapter=True) if getattr(a, 'MACAddress', None)]
        out = []
        for a in adapters:
            out.append({
                'Name': getattr(a, 'Name', 'Unknown'),
                'GUID': getattr(a, 'GUID', None),
                'MAC': getattr(a, 'MACAddress', 'Unknown'),
                'Enabled': getattr(a, 'NetEnabled', False)
            })
        return out
    except Exception:
        return []

def find_adapter_class_subkey_by_guid(adapter_guid):
    if not adapter_guid:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NET_CLASS_KEY, 0, winreg.KEY_READ) as class_key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(class_key, i)
                except OSError:
                    break
                i += 1
                if not re.match(r"^\d{4}$", subkey_name):
                    continue
                try:
                    with winreg.OpenKey(class_key, subkey_name, 0, winreg.KEY_READ) as k:
                        val, _ = winreg.QueryValueEx(k, "NetCfgInstanceId")
                        if str(val).lower() == str(adapter_guid).lower():
                            return subkey_name
                except Exception:
                    continue
    except Exception:
        return None
    return None

def get_adapter_networkaddress(adapter_guid):
    try:
        subkey = find_adapter_class_subkey_by_guid(adapter_guid)
        if not subkey:
            return None
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{NET_CLASS_KEY}\\{subkey}", 0, winreg.KEY_READ) as k:
            try:
                val, _ = winreg.QueryValueEx(k, "NetworkAddress")
                return val
            except FileNotFoundError:
                return None
    except Exception:
        return None

def set_adapter_networkaddress(adapter_guid, mac12):
    try:
        subkey = find_adapter_class_subkey_by_guid(adapter_guid)
        if not subkey:
            QMessageBox.critical(None, "Adapter Not Found", "Could not locate adapter registry key.")
            return False
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{NET_CLASS_KEY}\\{subkey}", 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "NetworkAddress", 0, winreg.REG_SZ, mac12)
        return True
    except PermissionError:
        QMessageBox.critical(None, "Permission Denied", "Administrator privileges are required to change adapter MAC.")
        return False
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to set adapter MAC: {e}")
        return False

def clear_adapter_networkaddress(adapter_guid):
    try:
        subkey = find_adapter_class_subkey_by_guid(adapter_guid)
        if not subkey:
            return False
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{NET_CLASS_KEY}\\{subkey}", 0, winreg.KEY_SET_VALUE) as k:
            try:
                winreg.DeleteValue(k, "NetworkAddress")
            except FileNotFoundError:
                pass
        return True
    except PermissionError:
        QMessageBox.critical(None, "Permission Denied", "Administrator privileges are required to change adapter MAC.")
        return False
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to clear adapter MAC: {e}")
        return False

def restart_adapter_by_guid(adapter_guid):
    try:
        c = wmi.WMI(namespace=r"root\\CIMV2")
        adps = c.Win32_NetworkAdapter(GUID=adapter_guid)
        if not adps:
            return False
        a = adps[0]
        try:
            a.Disable()
        except Exception:
            pass
        try:
            a.Enable()
        except Exception:
            pass
        return True
    except Exception:
        return False

def mac_from_guid_like(guid_str):
    # Derive a stable, locally-administered unicast MAC from a GUID
    # Strip to hex and take last 12 chars
    hexchars = re.sub(r"[^0-9A-Fa-f]", "", str(guid_str))
    if len(hexchars) < 12:
        hexchars = (hexchars * 12)[:12]
    mac_hex = hexchars[-12:]
    first = int(mac_hex[0:2], 16)
    first = (first & 0xFE) | 0x02  # clear multicast bit, set local-admin bit
    mac_hex = f"{first:02X}" + mac_hex[2:]
    return mac_hex.upper()

class HWIDInspector(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("HWID Inspector")
        self.setFixedSize(520, 640)

        self.hwid_label = QLabel("Hardware ID (UUID): ", self)
        self.machine_guid_label = QLabel("MachineGuid: ", self)
        self.hwprofile_guid_label = QLabel("HwProfileGuid: ", self)
        self.adapter_label = QLabel("Primary Adapter: ", self)
        self.adapter_mac_label = QLabel("Adapter MAC: ", self)
        self.adapter_select_label = QLabel("Select Adapter:", self)
        self.adapter_combo = QComboBox(self)
        self.mac_label = QLabel("MAC Address: ", self)
        self.bios_label = QLabel("BIOS Serial Number: ", self)
        self.manufacturer_label = QLabel("Manufacturer: ", self)
        self.model_label = QLabel("Model: ", self)
        self.last_changed_label = QLabel("Last Changed/Updated: ", self)
        self.computer_name_label = QLabel("Computer Name: ", self)
        self.computer_name_entry = QLineEdit(self)
        self.rename_button = QPushButton("Rename Computer", self)
        self.rename_button.clicked.connect(self.rename_computer_action)

        self.installation_id_label = QLabel("InstallationID: ", self)
        self.installation_id_entry = QLineEdit(self)
        self.set_installation_id_button = QPushButton("Set InstallationID", self)
        self.set_installation_id_button.clicked.connect(self.set_installation_id_action)
        self.gen_installation_id_button = QPushButton("Generate InstallationID", self)
        self.gen_installation_id_button.clicked.connect(self.generate_installation_id)

        self.hwid_entry_label = QLabel("Enter new HWID: ", self)
        self.hwid_entry = QLineEdit(self)

        self.generate_hwid_button = QPushButton("Generate HWID", self)
        self.generate_hwid_button.clicked.connect(self.generate_hwid)

        self.change_hwid_button = QPushButton("Change HWID", self)
        self.change_hwid_button.clicked.connect(self.change_hwid)

        self.display_info_button = QPushButton("Refresh Info", self)
        self.display_info_button.clicked.connect(self.display_info)

        self.revert_button = QPushButton("Revert Changes", self)
        self.revert_button.clicked.connect(self.revert_changes)

        self.elevate_button = QPushButton("Restart as Admin", self)
        self.elevate_button.clicked.connect(restart_as_admin)

        self.spoof_mac_checkbox = QCheckBox("Spoof primary adapter MAC", self)

        self.vm_uuid_button = QPushButton("VM UUID Guide", self)
        self.vm_uuid_button.clicked.connect(self.show_vm_uuid_guide)

        self.launch_with_spoof_button = QPushButton("Launch With Spoof", self)
        self.launch_with_spoof_button.setToolTip("Temporarily apply spoof, run an app, then revert when it exits.")
        self.launch_with_spoof_button.clicked.connect(self.launch_with_spoof)

        layout = QVBoxLayout()

        layout.addWidget(self.hwid_label)
        layout.addWidget(self.machine_guid_label)
        layout.addWidget(self.hwprofile_guid_label)
        layout.addWidget(self.mac_label)
        layout.addWidget(self.adapter_label)
        layout.addWidget(self.adapter_mac_label)
        adapter_select_layout = QHBoxLayout()
        adapter_select_layout.addWidget(self.adapter_select_label)
        adapter_select_layout.addWidget(self.adapter_combo)
        layout.addLayout(adapter_select_layout)
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
        button_layout.addWidget(self.revert_button)
        button_layout.addWidget(self.elevate_button)
        layout.addLayout(button_layout)

        layout.addWidget(self.spoof_mac_checkbox)
        layout.addWidget(self.vm_uuid_button)
        layout.addWidget(self.launch_with_spoof_button)

        # Computer name rename section
        layout.addWidget(self.computer_name_label)
        compname_layout = QHBoxLayout()
        compname_layout.addWidget(self.computer_name_entry)
        compname_layout.addWidget(self.rename_button)
        layout.addLayout(compname_layout)

        # Installation ID section
        layout.addWidget(self.installation_id_label)
        install_layout = QHBoxLayout()
        install_layout.addWidget(self.installation_id_entry)
        install_layout.addWidget(self.set_installation_id_button)
        install_layout.addWidget(self.gen_installation_id_button)
        layout.addLayout(install_layout)

        self.setLayout(layout)
        self.last_prev_machine_guid = None
        self.last_prev_hwprofile_guid = None
        self.last_prev_machine_guid = None
        self.last_prev_hwprofile_guid = None
        self.last_prev_adapter_guid = None
        self.last_prev_adapter_networkaddress = None
        self._spoof_process_thread = None
        self.display_info()

    def display_info(self):
        hwid, bios_serial, manufacturer, model = get_hwid()
        mac_address = get_mac()
        last_changed = get_last_changed()
        machine_guid = get_machine_guid()
        hw_profile_guid = get_hw_profile_guid()
        adapter = get_primary_adapter_info() or {}
        adapters = list_adapters()
        current_name = get_computer_name()
        current_installation_id = get_installation_id()

        self.hwid_label.setText(f"Hardware ID (UUID): {hwid}")
        self.machine_guid_label.setText(f"MachineGuid: {machine_guid}")
        self.hwprofile_guid_label.setText(f"HwProfileGuid: {hw_profile_guid}")
        self.mac_label.setText(f"MAC Address: {mac_address}")
        self.adapter_label.setText(f"Primary Adapter: {adapter.get('Name','Unknown')}")
        self.adapter_mac_label.setText(f"Adapter MAC: {adapter.get('MAC','Unknown')}")
        # Populate adapter combo
        self.adapter_combo.clear()
        self.adapter_combo.addItem("Auto (primary)", None)
        for a in adapters:
            label = f"{a['Name']} ({a['MAC']})"
            self.adapter_combo.addItem(label, a['GUID'])
        # Computer name and InstallationID
        self.computer_name_label.setText(f"Computer Name: {current_name}")
        self.installation_id_label.setText(f"InstallationID: {current_installation_id}")
        self.bios_label.setText(f"BIOS Serial Number: {bios_serial}")
        self.manufacturer_label.setText(f"Manufacturer: {manufacturer}")
        self.model_label.setText(f"Model: {model}")
        self.last_changed_label.setText(f"Last Changed/Updated: {last_changed}")

    def change_hwid(self):
        new_hwid = self.hwid_entry.text()
        if new_hwid:
            changed, prev_machine, prev_profile = update_hwid(new_hwid)
            if changed:
                self.last_prev_machine_guid = prev_machine
                self.last_prev_hwprofile_guid = prev_profile
            # Optionally spoof MAC
            if self.spoof_mac_checkbox.isChecked():
                if not is_admin():
                    QMessageBox.warning(self, "Administrator Required", "Spoofing MAC requires Administrator privileges.")
                else:
                    sel_guid = self.adapter_combo.currentData()
                    adapter = get_primary_adapter_info() if not sel_guid else {'GUID': sel_guid}
                    if not adapter or not adapter.get('GUID'):
                        QMessageBox.critical(self, "Adapter Not Found", "Could not find a primary adapter to spoof.")
                    else:
                        prev_netaddr = get_adapter_networkaddress(adapter['GUID'])
                        target_mac = mac_from_guid_like(new_hwid)
                        if set_adapter_networkaddress(adapter['GUID'], target_mac):
                            restart_adapter_by_guid(adapter['GUID'])
                            self.last_prev_adapter_guid = adapter['GUID']
                            self.last_prev_adapter_networkaddress = prev_netaddr
            self.display_info()
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a valid HWID.")

    def generate_hwid(self):
        new_hwid = str(uuid.uuid4())
        self.hwid_entry.setText(new_hwid)

    def revert_changes(self):
        did_any = False
        if self.last_prev_machine_guid or self.last_prev_hwprofile_guid:
            if revert_identifiers(self.last_prev_machine_guid, self.last_prev_hwprofile_guid):
                did_any = True
        if self.last_prev_adapter_guid is not None:
            if not is_admin():
                QMessageBox.warning(self, "Administrator Required", "Reverting MAC requires Administrator privileges.")
            else:
                if self.last_prev_adapter_networkaddress:
                    if set_adapter_networkaddress(self.last_prev_adapter_guid, self.last_prev_adapter_networkaddress):
                        restart_adapter_by_guid(self.last_prev_adapter_guid)
                        did_any = True
                else:
                    if clear_adapter_networkaddress(self.last_prev_adapter_guid):
                        restart_adapter_by_guid(self.last_prev_adapter_guid)
                        did_any = True
        if did_any:
            QMessageBox.information(self, "Reverted", "Previous settings restored where possible (restart may be required).")
            self.display_info()
        else:
            QMessageBox.information(self, "Nothing to Revert", "No previous change recorded in this session.")

    def rename_computer_action(self):
        desired = self.computer_name_entry.text().strip()
        if not desired:
            QMessageBox.warning(self, "Input Error", "Enter a new computer name (1-15 characters).")
            return
        if rename_computer(desired):
            self.display_info()

    def set_installation_id_action(self):
        val = self.installation_id_entry.text().strip()
        if not val:
            QMessageBox.warning(self, "Input Error", "Enter a value for InstallationID or click Generate.")
            return
        if set_installation_id(val):
            self.display_info()

    def generate_installation_id(self):
        self.installation_id_entry.setText(str(uuid.uuid4()))

    def show_vm_uuid_guide(self):
        raw = self.hwid_entry.text().strip()
        machine_guid, hwprofile_guid = normalize_guid(raw)
        if not machine_guid:
            QMessageBox.warning(self, "Input Error", "Please enter a valid GUID in the input field.")
            return
        vbox_guid = machine_guid.upper()
        vm_name_placeholder = "Your-VM-Name"
        text = []
        text.append("VirtualBox (set SMBIOS/UUID for a VM):")
        text.append(f"  VBoxManage setextradata \"{vm_name_placeholder}\" \"VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid\" \"{vbox_guid}\"")
        text.append(f"  VBoxManage setextradata \"{vm_name_placeholder}\" \"VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor\" \"CustomVendor\"")
        text.append(f"  VBoxManage setextradata \"{vm_name_placeholder}\" \"VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct\" \"CustomModel\"")
        text.append("")
        text.append("VMware (add lines to the .vmx file):")
        text.append(f"  uuid.bios = \"{machine_guid}\"")
        text.append(f"  uuid.location = \"{machine_guid}\"")
        text.append("  smbios.reflectHost = \"FALSE\"")
        text.append("")
        text.append("Notes:")
        text.append("- Power off the VM before applying changes.")
        text.append("- These changes affect what apps inside the VM see as the firmware UUID.")
        text.append("- This does not change the host machine's firmware UUID.")

        dlg = QDialog(self)
        dlg.setWindowTitle("VM UUID Guide")
        layout = QVBoxLayout(dlg)
        txt = QTextEdit(dlg)
        txt.setReadOnly(True)
        txt.setText("\n".join(text))
        layout.addWidget(txt)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dlg.accept)
        layout.addWidget(buttons)
        dlg.resize(640, 360)
        dlg.exec()

    def launch_with_spoof(self):
        new_hwid = self.hwid_entry.text().strip()
        if not new_hwid:
            QMessageBox.warning(self, "Input Error", "Please enter a valid GUID in the input field.")
            return
        if not is_admin():
            QMessageBox.warning(self, "Administrator Required", "Launch With Spoof requires Administrator privileges.")
            return
        # Choose executable
        exe_path, _ = QFileDialog.getOpenFileName(self, "Select Application to Launch", os.getcwd(), "Programs (*.exe);;All Files (*.*)")
        if not exe_path:
            return

        # Apply registry spoof
        changed, prev_machine, prev_profile = update_hwid(new_hwid)
        if changed:
            self.last_prev_machine_guid = prev_machine
            self.last_prev_hwprofile_guid = prev_profile
        # Optionally spoof MAC
        mac_applied = False
        prev_netaddr = None
        adapter_guid = None
        if self.spoof_mac_checkbox.isChecked():
            sel_guid = self.adapter_combo.currentData()
            if sel_guid:
                adapter_guid = sel_guid
            else:
                pa = get_primary_adapter_info()
                adapter_guid = pa.get('GUID') if pa else None
            if adapter_guid:
                prev_netaddr = get_adapter_networkaddress(adapter_guid)
                target_mac = mac_from_guid_like(new_hwid)
                if set_adapter_networkaddress(adapter_guid, target_mac):
                    restart_adapter_by_guid(adapter_guid)
                    mac_applied = True
        self.display_info()

        # Launch process and revert when it exits (in background thread)
        def _run_and_revert():
            try:
                proc = subprocess.Popen([exe_path])
                proc.wait()
            except Exception:
                pass
            # Revert MAC
            if adapter_guid is not None:
                if prev_netaddr:
                    set_adapter_networkaddress(adapter_guid, prev_netaddr)
                else:
                    clear_adapter_networkaddress(adapter_guid)
                restart_adapter_by_guid(adapter_guid)
            # Revert registry
            if self.last_prev_machine_guid or self.last_prev_hwprofile_guid:
                revert_identifiers(self.last_prev_machine_guid, self.last_prev_hwprofile_guid)
            # Refresh UI on main thread
            QTimer.singleShot(0, self.display_info)

        self._spoof_process_thread = threading.Thread(target=_run_and_revert, daemon=True)
        self._spoof_process_thread.start()
        QMessageBox.information(self, "Launched", "Application started with spoof applied. It will revert after the app exits.")

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
