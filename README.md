## SCADASentry — Low cost SCADA PLC Network Monitor
Purpose-built Allen Bradley ControlLogix PLC network monitor with SNMP trap or SMTP alerting  
![SCADASentry Sensor Image](https://github.com/Xorlent/SCADASentry/blob/main/images/SCADASentry.jpg)
## Background
This device extends the features of the [PoE Honeypot](https://github.com/Xorlent/PoE-Honeypot) project with purpose-built features for proactively monitoring an Allen Bradley ControlLogix PLC network environment.

## To-do
- End-to-end SMTP testing
- Network stress test

## Requirements
1. M5Stack [Unit-PoE-P4](https://shop.m5stack.com/products/unit-poe-with-esp32-p4), currently $21.50 USD
2. USB-C cable for programming
3. An SNMP trap receiver (NMS such as PRTG) or an available SMTP relay
4. An accessible NTP server for time synchronization

## Functional Description
SCADASentry is a honeypot that listens on any number of user-configurable TCP and UDP ports and reports activity via **SNMPv2c traps** (or email via SMTP). It is designed to detect devices joining and leaving the local PLC LAN, alerts on scanning, reconnaissance, and lateral movement.  Additionally, SCADASentry reports basic ControlLogix device information and will notify on run-key or firmware version change.

When activity is detected, the device immediately sends a trap or email containing the source IP, protocol, destination port (or ICMP type), and service name. The following events are reported:

| Event | Trap |
|-------|------|
| TCP connection on a monitored port | `tcpConnectionTrap` |
| UDP packet on a monitored port | `udpConnectionTrap` |
| ICMP request of a monitored type | `icmpRequestTrap` |
| Fragmented IP packet (suspicious) | `ipFragmentTrap` |
| IP packet with options (suspicious) | `ipOptionsTrap` |
| Device comes online (boot or link recovery) | `deviceOnlineTrap` |

The device sends a `deviceOnlineTrap` when it boots (power recovery) or when its Ethernet link recovers, with a `honeypotStartReason` varbind distinguishing the cause (`powerOn` vs `linkUp`).

For Rockwell Automation / EtherNet/IP broadcast traffic, the device listens on UDP ports **44818** and **2222** and reports only `ListIdentity` browse/discovery traffic (encapsulation command `0x0063`), silently ignoring device I/O data. This detects RSLogix/RSLinx device browsing activity from unauthorized devices.

The device also periodically scans the local LAN (every `LAN_SCAN_INTERVAL_SECONDS`, default 240s) using ARP to discover devices. ControlLogix PLCs are identified via an EtherNet/IP `ListIdentity` broadcast and queried over TCP 44818 for their identity, firmware, serial, state, and run-switch mode. Newly discovered devices are reported via `newDeviceDiscoveredTrap`, including the MAC address and — for PLCs — the vendor, product name, firmware, serial, state, and run-switch mode. Devices that stop responding are reported via `deviceDisappearedTrap` and removed from the tracked-IP holdoff list.  Note that a departed device is detected only after its ARP entry expires (5 minutes), so `deviceDisappearedTrap` can lag a device's actual departure by up to 5 minutes.  For discovered PLCs, the run-switch mode and firmware version are re-checked every Nth scan (default 1h) and reported via `deviceModeChangedTrap` / `deviceFirmwareChangedTrap` when they change.

The device can also be configured to alert on ICMP ping requests (note: it will not respond to pings when ICMP monitoring is enabled).
## Programming
### Prepare configuration details for your device:  
- Host name
- Device IP address, gateway, and subnet mask
- DNS servers (optional)
- SNMP trap receiver IP and community string if email (USE_SMTP) is _false_ (default)
- Email to and from addresses and SMTP relay IP if email (USE_SMTP) is _true_
- NTP server
- TCP and/or UDP ports to listen on (defaults are recommended)
- LAN scan interval and hosts excluded from network scans (optional)
### Configure and flash the device:
_Once you've successfully programmed a single unit, skip steps 1 & 2.  Repeating this process takes 3 minutes from start to finish._  
1. [Set up your Arduino programming environment](https://github.com/Xorlent/SCADASentry/blob/main/ARDUINO-SETUP.md)
2. In Arduino, open the project file (SCADASentry.ino)
   - Select Tools->Board->esp32 and select "ESP32P4 Dev Module"
   - Configure board settings according to the [Unit-PoE-P4 Board Configuration](https://github.com/Xorlent/SCADASentry/blob/main/images/ESP32P4-Config.jpg)
3. Connect the Unit-PoE-P4 to your computer via USB
   - Select Tools->Port and select the device port
     - If you're unsure, unplug the device, look at the port list, then plug it back in and select the new entry
> [!WARNING]
> Do not plug the device into a PoE-powered Ethernet port until after step 6 or you risk damaging your USB port!
4. In Arduino
   - Edit Config.h with configuration details for the device
   - Select Sketch->Upload to flash the device
   - When you see something similar to the following, proceed to step 5
```
Writing at 0x000f4830 [==============================] 100.0% 495157/495157 bytes... 
Wrote 935984 bytes (495157 compressed) at 0x00010000 in 3.6 seconds (2098.6 kbit/s).
Hash of data verified.

Hard resetting via RTS pin...
```
5. In Arduino
   - Select Tools->Serial Monitor
   - Address any configuration errors or warnings shown in the serial console
     - If you did not immediately open the serial monitor, you may need to re-connect the device to see the configuration check output
6. When configuration is complete, disconnect the USB cable
7. Connect the device to a PoE network port and mount as appropriate
8. Configure your SNMP trap alerts:
    - Import SCADASENTRY-MIB.mib into your NMS to resolve trap OIDs to human-readable names
    - Add alert triggers based on traps received from the device to get immediate notice of potential scanning and lateral movement
    - Example trap for IP 10.70.103.12 connecting to TCP port 443:
      - Trap OID: 1.3.6.1.4.1.99999.0.1 (tcpConnectionTrap)
      - Varbinds: honeypotSourceIp=10.70.103.12, honeypotProtocol=6, honeypotDestPort=443, honeypotServiceName="https", honeypotEventTime="2026-08-16T21:12:52Z"
    - Example trap for IP 10.70.103.12 connecting to UDP port 137:
      - Trap OID: 1.3.6.1.4.1.99999.0.2 (udpConnectionTrap)
      - Varbinds: honeypotSourceIp=10.70.103.12, honeypotProtocol=17, honeypotDestPort=137, honeypotServiceName="netbios-ns"
    - Example trap for IP 10.70.103.12 sending a ping request to the honeypot:
      - Trap OID: 1.3.6.1.4.1.99999.0.3 (icmpRequestTrap)
      - Varbinds: honeypotSourceIp=10.70.103.12, honeypotProtocol=1, honeypotIcmpType=8, honeypotServiceName="echo-request"
## SNMP Trap Reference
All traps are SNMPv2c, sent to UDP port 162 (configurable). Import `SCADASENTRY-MIB.mib` into your NMS to resolve OIDs to human-readable names and translate enumerated values.

| Trap | OID | Varbinds |
|------|-----|----------|
| `tcpConnectionTrap` | `1.3.6.1.4.1.99999.0.1` | eventTime, sourceIp, protocol, destPort, serviceName |
| `udpConnectionTrap` | `1.3.6.1.4.1.99999.0.2` | eventTime, sourceIp, protocol, destPort, serviceName |
| `icmpRequestTrap` | `1.3.6.1.4.1.99999.0.3` | eventTime, sourceIp, protocol, icmpType, serviceName |
| `ipFragmentTrap` | `1.3.6.1.4.1.99999.0.4` | eventTime, sourceIp, protocol, serviceName |
| `ipOptionsTrap` | `1.3.6.1.4.1.99999.0.5` | eventTime, sourceIp, protocol, serviceName |
| `deviceOnlineTrap` | `1.3.6.1.4.1.99999.0.6` | eventTime, sourceIp, startReason |

### LAN device discovery traps

| Trap | OID | Varbinds |
|------|-----|----------|
| `newDeviceDiscoveredTrap` | `1.3.6.1.4.1.99999.0.8` | eventTime, deviceIp, deviceMac, (PLC: vendor, productName, firmware, serial, state, mode) |
| `deviceDisappearedTrap` | `1.3.6.1.4.1.99999.0.9` | eventTime, deviceIp, deviceMac |
| `deviceModeChangedTrap` | `1.3.6.1.4.1.99999.0.10` | eventTime, deviceIp, deviceMac, prevMode, mode |
| `deviceFirmwareChangedTrap` | `1.3.6.1.4.1.99999.0.11` | eventTime, deviceIp, deviceMac, prevFirmware, firmware, firmwareVulnerable |

Every trap also carries the standard `sysUpTime.0` (TimeTicks) and `snmpTrapOID.0` varbinds.

### Device object varbinds

| OID | Name | Type |
|-----|------|------|
| `.1.6.0` | `deviceIpAddress` | IpAddress |
| `.1.7.0` | `deviceMacAddress` | OCTET STRING (6) |
| `.1.8.0` | `deviceVendor` | INTEGER (CIP vendor ID) |
| `.1.9.0` | `deviceProductName` | OCTET STRING |
| `.1.10.0` | `deviceFirmwareVersion` | OCTET STRING |
| `.1.11.0` | `deviceSerial` | OCTET STRING |
| `.1.12.0` | `deviceState` | INTEGER (enum) |
| `.1.13.0` | `deviceMode` | INTEGER (enum) |
| `.1.14.0` | `devicePreviousFirmwareVersion` | OCTET STRING |
| `.1.15.0` | `devicePreviousMode` | INTEGER (enum) |
| `.1.16.0` | `deviceFirmwareVulnerable` | INTEGER (enum) |

### Enumerated varbinds (translated by the MIB)

- `honeypotProtocol`: `icmp(1)`, `tcp(6)`, `udp(17)`
- `honeypotStartReason`: `powerOn(1)`, `linkUp(2)`
- `honeypotIcmpType`: `ping(8)`, `pingExtended(42)`
- `deviceState`: `nonexistent(0)`, `selfTesting(1)`, `standby(2)`, `operational(3)`, `majorRecoverableFault(4)`, `majorUnrecoverableFault(5)`, `communicationFault(6)`, `unconfigured(7)`
- `deviceMode`: `program(0)`, `run(1)`, `testRemote(2)`
- `deviceFirmwareVulnerable`: `notVulnerable(0)`, `vulnerable(1)`, `unknown(2)`

## Guidance and Limitations
- The device produces SNMPv2c traps on UDP port 162 (community string configurable in Config.h).
- SMTP alerts require an unauthenticated SMTP relay that is configured to allow the SCADASentry device IP address.
- TCP and UDP listening ports are fully user-configurable with no constraints.
- It is recommended you exempt the SCADASentry device IP addresses in any legitimate vulnerability or network scanners to avoid triggering alerts.
- If ICMP is disabled in Config.h, the device will respond to pings from any IP address within the routable network.
- LAN device discovery scans the local subnet using ARP, so it only sees devices on the same L2 segment (ARP doesn't cross routers).

## Technical Information
- CPU and Memory
  - 360MHz dual core + 40MHz LP core RISC-V
  - 768KBytes RAM
  - 16MBytes Flash + 32MBytes PSRAM
- Operating Specifications
  - Operating temperature: 0°F (-17.7°C) to 104°F (40°C)
  - Operating humidity: 5% to 90% (RH), non-condensing
- Power Consumption
  - 6W maximum via 802.3af Power-over-Ethernet
- Ethernet
  - IP101GRI or TLK110 PHY
  - 10/100 Mbit twisted pair copper
  - IEEE 802.3af Power-over-Ethernet
