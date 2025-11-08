# HWID Inspector

A simple Windows-only GUI tool to inspect common hardware identifiers. It shows the current firmware HWID (system UUID), MachineGuid, Hardware Profile GUID, MAC address, BIOS serial number, system manufacturer and model, and the Hardware Profile last change time. The interface is built with PySide6 and ships with a dark theme stylesheet.

- Features
- Requirements
- Installation
- Usage
- UI Overview
- Troubleshooting
- Notes & Warnings
- License

## Features

- View current Hardware ID (UUID)
- View MachineGuid and Hardware Profile GUID
- View MAC address
- View BIOS serial number, manufacturer, and model
- View Hardware Profile last change/update time
- Generate a new random UUID
- Change MachineGuid and the active HwProfileGuid (Admin required)
- Revert last changes within the session
- Spoof primary network adapter MAC (Admin required; driver support needed)
- Clean, minimal PySide6 GUI with optional dark theme (`dark_theme.qss`)

## Requirements

- Windows 10/11
- Python 3.8+
- Python packages: `PySide6`, `wmi`, `getmac`

## Installation

1) Clone the repository

```sh
git clone https://github.com/boshyxd/HWIDInspector.git
cd HWIDInspector
```

2) (Optional) Create and activate a virtual environment

```sh
python -m venv .venv
.\.venv\Scripts\activate
```

3) Install dependencies

```sh
pip install PySide6 wmi getmac
```

## Usage

Run the application from the project root:

```sh
python HWIDInspector.py
```

Main actions:
- Generate HWID: fills the input with a new random UUID (for reference, or to apply to registry-based identifiers).
- Change HWID: when run as Administrator, sets MachineGuid and HwProfileGuid in the registry to the input GUID. The firmware System UUID remains read-only.
- Revert Changes: restores the previous MachineGuid and HwProfileGuid from this session.
- Restart as Admin: relaunches the app elevated to allow changes.
- Refresh Info: reloads and displays current values from the system.
- Spoof primary adapter MAC: enable the checkbox to also set a locally-administered MAC derived from the input GUID and restart the adapter. Network may briefly drop.

## UI Overview

- Hardware ID (UUID): current system UUID
- MAC Address: primary MAC as reported by `getmac`
- BIOS Serial Number: BIOS serial from WMI
- Manufacturer / Model: system info from WMI
- Last Changed/Updated: Hardware Profile last change time from registry
- Enter new HWID: text field to provide a target UUID
- Generate HWID / Change HWID / Refresh Info: action buttons

## Troubleshooting

- Import errors on non-Windows platforms: this tool only supports Windows.
- If `wmi` installation fails, install `pywin32` then retry: `pip install pywin32 wmi`.
- If the dark theme does not load, ensure `dark_theme.qss` sits next to `HWIDInspector.py`.
- If "Administrator Required" appears when changing/reverting: click "Restart as Admin" in the app, or launch the app from an elevated terminal.

## Notes & Warnings

- The firmware System UUID/HWID exposed by WMI is read-only and cannot be changed via software. Attempts via WMI fail with a provider error ("provider not capable").
- As an alternative, this app can change registry-based identifiers (MachineGuid and HwProfileGuid) when run as Administrator. This may affect software licensing, device identity in some apps/services, and may require a system restart to fully take effect.
- MAC spoofing relies on the NIC driver honoring the `NetworkAddress` setting; not all drivers support it. The app restarts the adapter; connectivity will momentarily drop.
- Editing the registry is risky. Ensure you understand the implications and back up your system or registry beforehand.
- Modifying hardware identifiers can affect software licensing and anti-cheat systems. Use at your own risk and ensure you comply with applicable policies and laws.

## License

MIT
