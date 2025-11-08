# HWID Inspector

A simple Windows-only GUI tool to inspect common hardware identifiers and attempt to update the system Hardware ID (UUID). It shows the current HWID, MAC address, BIOS serial number, system manufacturer and model, and the Hardware Profile last change time. The interface is built with PySide6 and ships with a dark theme stylesheet.

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
- View MAC address
- View BIOS serial number, manufacturer, and model
- View Hardware Profile last change/update time
- Generate a new random UUID
- Attempt to set HWID to a user-specified value
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
- Generate HWID: fills the input with a new random UUID.
- Change HWID: attempts to set the system UUID/HWID to the input value.
- Refresh Info: reloads and displays current values from the system.

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

## Notes & Warnings

- Changing the system UUID/HWID may require Administrator privileges and may not be supported on all hardware/firmware configurations. The application will show an error if the change is rejected.
- Modifying hardware identifiers can affect software licensing and anti-cheat systems. Use at your own risk and ensure you comply with applicable policies and laws.

## License

MIT
