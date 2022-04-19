# u2f

u2f dongle implementation for MIT's 6.858 - Spring 2022

## Project Structure

- `arduino/`: arduino code that is uploaded to the actual dongle
  - `main/`: our implementation
  - `sha256/`: sha256 implementation from [crypto-algorithms](https://github.com/B-Con/crypto-algorithms).
  - `uECC/`: ECDH and ECDSA implementation for 8-bit, 32-bit, and 64-bit processors. See [micro-ecc](https://github.com/kmackay/micro-ecc).
- `server/`: test webauthn capable server in python
- `chrome/`: js that establishes a connection between the dongle and chrome via usb protocol
- `google-u2f-ref-code`: git submodule of google's u2f reference code

## Implementation

![doc/security_key_flow_diagram.png](doc/security_key_flow_diagram.png)

For communication protocol, look at

- https://fidoalliance.org/specs/u2f-specs-master/fido-u2f-hid-protocol.html#:~:text=With%20a%20packet%20size%20of,%2D%205)%20%3D%207609%20bytes
- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html

## Getting Started
To set up the submodule, run:
```
git submodule init
git submodule update --init --recursive
```

## Hardware notes

Our current implementation is developed and tested on the Teensy 3.2. The hardware limitations
are requiring RawHID and EEPROM/persistent storage.

Need to upgrade USB version to 2.1 by modifying `#define USB_VERSION 0x200` to `#define USB_VERSION 0x210` in `/Applications/Arduino.app/Contents/Java/hardware/arduino/avr/cores/arduino/USBCore.h`.

We will be using RawHID to communicate. Run the [helpers/setup_hid_iface.sh](helpers/setup_hid_iface.sh)
[Teensyduino location]
to setup the teensyduino core lib USB headers. For reference check out 
[helpers/teensy3_core_usb_desc.h](helpers/teensy3_core_usb_desc.h), 
namely `RAWHID_USAGE_PAGE` and `RAWHID_USAGE`.

### Useful for debugging hardware

Chrome pages:

`about://device-log`: see all USB device related events

`about://usb-internals`: simulate connection and disconnection of virtual WebUSB devices

U2F test pages:
- https://webauthn.bin.coffee/  
- https://demo.yubico.com/webauthn-technical/registration
- https://akisec.com/demo/
- https://webauthn.io/

### Resources used for hardware definitions

- List of vendor usb id's: http://www.linux-usb.org/usb.ids
  - `0x2341` for Arduino
  - `0x16c0` for Teensyduino
- USB spec device descriptors: https://www.beyondlogic.org/usbnutshell/usb5.shtml#DeviceDescriptors
- WebUSB API: https://wicg.github.io/webusb/
- WebUSB arduino (useful to allow communication with arduino): https://github.com/webusb/arduino
- Access USB Devices on the Web: https://web.dev/usb/
- uECC doc: https://github.com/kmackay/micro-ecc/blob/master/examples/ecc_test/ecc_test.ino
- Message headers: https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f.h
- SW Command status responses: [ISO-7816]()

## References

[1] J. Lang, A. Czeskis, D. Balfanz, M. Schilder, and S. Srinivas, “Security Keys: Practical Cryptographic Second Factors for the Modern Web,” in Financial Cryptography and Data Security, vol. 9603, J. Grossklags and B. Preneel, Eds. Berlin, Heidelberg: Springer Berlin Heidelberg, 2017, pp. 422–440. doi: 10.1007/978-3-662-54970-4_25. Available: https://css.csail.mit.edu/6.858/2022/readings/u2f-fc.pdf

[2] Reference code for U2F specifications. Google, 2022. Accessed: Apr. 02, 2022. [Online]. Available: https://github.com/google/u2f-ref-code
