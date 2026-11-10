# Hardware support

Run `python3 -m pairinglens.cli hardware` for local capability reporting. Adapter sysfs presence is not proof of usable hardware.

Offline JSON metadata import is available without a radio. Local BLE adapters, dedicated sniffers, and SDRs are not integrated. HCI traces are not silently treated as over-the-air traffic. No hardware testing was possible in this environment and no device security verification is claimed. Frequency and sample rate are not applicable to this offline metadata utility.
