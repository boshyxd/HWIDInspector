<div align="center">

# HWID Inspector 🔍

<img src="https://i.ibb.co/placeholder-image/hwidinspector.png" alt="HWID Inspector Logo" width="200"/>

HWID Inspector is a Python tool that allows users to inspect and modify their system's Hardware ID (HWID) and view other system information like BIOS serial number, manufacturer, model, MAC address, and the last change/update time. It features a clean and user-friendly graphical interface built using `PySide6` (Qt for Python).

[Features](#-features) •
[Requirements](#-requirements) •
[Installation](#-installation) •
[Usage](#-usage) •
[UI Elements](#-ui-elements) •
[Example Output](#-example-output) •
[License](#-license)

</div>

## 🌟 Features

- View current Hardware ID (HWID)
- View MAC address of the system
- View BIOS serial number, manufacturer, and model
- View the last change/update time of the hardware profile
- Generate a new random HWID
- Change the system's HWID to a user-specified value
- Clean and user-friendly interface

## 🛠️ Requirements

- Python 3.7+
- `wmi` library
- `getmac` library
- `PySide6` library

## 📥 Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/boshyxd/HWIDInspector.git
   cd HWIDInspector
   ```
2. Install the required dependencies:
   ```sh
   pip install wmi getmac PySide6
   ```

## 🚀 Usage

Run the script to start the HWID Inspector application:

```sh
python HWIDInspector.py
```

## 🖥️ UI Elements

- **Hardware ID (UUID)**: Displays the current HWID of the system.
- **MAC Address**: Displays the MAC address of the system.
- **BIOS Serial Number**: Displays the BIOS serial number.
- **Manufacturer**: Displays the manufacturer of the system.
- **Model**: Displays the model of the system.
- **Last Changed/Updated**: Displays the last change/update time of the hardware profile.
- **Enter new HWID**: Text entry to input a new HWID.
- **Generate HWID**: Button to generate a new random HWID and fill it in the text entry.
- **Change HWID**: Button to change the system's HWID to the value specified in the text entry.
- **Refresh Info**: Button to refresh and display the latest system information.

## 📊 Example Output

```bash
Hardware ID (UUID): 06681AA8-9290-D361-3BB5-244BFE7DB4C1
MAC Address: 00:1A:2B:3C:4D:5E
BIOS Serial Number: 1234567890
Manufacturer: ExampleManufacturer
Model: ExampleModel
Last Changed/Updated: 2024-06-10 12:34:56
Enter new HWID: [               ]
[Generate HWID] [Change HWID] [Refresh Info]
```

## 📄 License

This project is licensed under the MIT License.

<div align="center">

---

Made with ❤️ by [boshyxd](https://github.com/boshyxd)

</div>
