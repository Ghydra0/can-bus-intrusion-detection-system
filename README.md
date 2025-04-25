# CAN Bus Intrusion Detection
**Project:** CAN-IDS (Intrusion Detection System) for automotive applications

 ## Overview
This repository provides two Arduino sketches for a lightweight CAN-bus IDS running on RP2040-based boards with an MCP2515 CAN controller (https://learn.adafruit.com/adafruit-rp2040-can-bus-feather/overview):
1. Receiver (CAN_IDS_Receiver.INO)
- Monitors a strict sequence of CAN frames (0x100 → 0x200 → 0x300).
- Detects:
  - DoS: Rapid re-transmission of the same ID (interval < 1 ms).
  - Spoofing: Out-of-range data values and addresses for each message type.
  - Replay: Repeated sequences within a 5 s window.
- Alerts via onboard LED and serial logs.

2. Sender Test Node (CAN_IDS_Sender.INO)
- Generates valid and malicious CAN traffic to exercise the IDS logic:
  - Normal sequences with randomized valid values.
  - DoS simulations (rapid back-to-back sequences).
  - Priority based DoS attacks (Attacks taking advantage of CAN bus priority system)
  - Spoof tests (out-of-range commands).
  - Replay attacks (duplicate sequences within 5 s).
- Trigger tests via serial commands (1–5).

## Features
- Sequence Enforcement: Ensures messages arrive in the correct order.
- Anomaly Detection: Built-in checks for DoS, spoof, and replay attacks.
- Easy Testing: Dedicated sender sketch to simulate attacks.
- Real-time Alerts: LED pulse and detailed serial logging.
- Wish to haves:
  - Logging alerts to SD card
  - RTOS implementation for multitasking/multithreading on logging
  - TinyML implementation for better detection, CAN is notoriously hard to implement robust security methods through traditional methods due to its focus on speed and fault-tolerance in its design. TinyML models could be a good solution.

## Important Note:
This project was specifically built for the Cal Poly Pomona Autonomous Vehicle Lab project. It is not generalized and is the detection methods used take advantage of its specific architecture (i.e. the fact that packets are sent in sequences is used for replay detection). You can use this as inspiration or a skeleton of your own implementation but it is definitely not plug and play.

## License
This project is released under the MIT License.
