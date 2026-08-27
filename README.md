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

When unexpected activity is detected, the device immediately sends a trap or email containing the source IP, protocol, destination port (or ICMP type), and service name. The following events are reported:

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

The device also periodically scans the local LAN (every `LAN_SCAN_INTERVAL_SECONDS`, default 240s) using ARP to discover devices. ControlLogix PLCs are identified via an EtherNet/IP `ListIdentity` broadcast and queried over TCP 44818 for their identity, firmware, serial, state, and run-switch mode. ARP-discovered hosts that do not answer the `ListIdentity` broadcast are also probed directly on TCP 44818, so PLCs that suppress discovery responses are still identified. Newly discovered devices are reported via `newDeviceDiscoveredTrap`, including the MAC address and — for PLCs — the vendor, product name, firmware, serial, state, and run-switch mode. Devices that stop responding are reported via `deviceDisappearedTrap` and removed from the tracked-IP holdoff list.  Note that a departed device is detected only after its ARP entry expires (5 minutes), so `deviceDisappearedTrap` can lag a device's actual departure by up to 5 minutes.  For discovered PLCs, the run-switch mode and firmware version are re-checked every Nth scan (default 1h) and reported via `deviceModeChangedTrap` / `deviceFirmwareChangedTrap` when they change.  For each discovered PLC, the device also enumerates the CPU and any Ethernet modules in the rack (including redundant/secondary CPUs) and derives an Advisory CVE search URL for each module from its device type and product name.  These URLs are held in memory (for a future in-memory database) and printed to the serial console in debug mode.  To minimize query load on production PLCs, backplane slots are probed only up to the highest slot previously detected on each PLC; a full re-probe of the remaining (higher) slots runs every `SLOT_EXPANSION_CHECK_MULTIPLIER` scans (default 360, i.e. 24 hours) to catch modules added to higher slots, and the highest detected slot is updated accordingly.  The PLC hostname and program name are read only when a PLC is first detected (or re-detected after it disappears), not on every status re-check.

The device can also be configured to alert on ICMP ping requests (note: it will not respond to pings when ICMP monitoring is enabled).
## Firmware Vulnerability Lookup
SCADASentry can determine whether a discovered ControlLogix CPU or Ethernet module is running firmware with known vulnerabilities. It uses DNS TXT records (no direct CVE database access), so it works entirely against your own DNS infrastructure.

### How it works
1. For each module, the device extracts the full catalog suffix from the product name (e.g. `1756-EN2T/B` → `EN2T/B`, `1756-L55/A …` → `L55/A`) and converts it to a valid DNS label (`/` becomes `-`, e.g. `EN2T/B` → `EN2T-B`).
2. It prepends that label to `vulnSearchSuffix` (Config.h) to form the TXT record name, e.g. `EN2T-B.vuln.plc.local`.
3. It queries the configured DNS servers (`dns1`, then `dns2`) for a TXT record at that name, with a 1-second timeout.

### TXT record format
The TXT value is the **minimum firmware revision that is not vulnerable**, formatted `major.minor` (e.g. `11.2`), or the literal string `EOL` (case-insensitive) for end-of-life products. For example, `EN2T-B.vuln.plc.local  TXT  "11.2"` marks any `1756-EN2T/B` running firmware older than `11.2` as vulnerable.

### Example DNS TXT records
The TXT record name is the module's full catalog suffix (with `/` replaced by `-`) prepended to `vulnSearchSuffix`. For example, a `1756-EN2T/D` module (`EN2T/D` → `EN2T-D`) with `vulnSearchSuffix = "vuln.plc.local"` resolves `EN2T-D.vuln.plc.local`. For CPUs whose product name has no catalog prefix (e.g. `ControlLogix 5580 Controller`), the short search term (`5580`) is used instead.

Starter records (the value is the minimum non-vulnerable firmware, or `EOL`):

| Label | TXT value | Module |
|-------|-----------|--------|
| `5580` | `37.013` | ControlLogix 5580 CPU |
| `L55-A` | `EOL` | 1756-L55 |
| `ENBT-A` | `EOL` | 1756-ENBT |
| `EN2T-A` | `EOL` | 1756-EN2T |
| `EN2T-B` | `EOL` | 1756-EN2T |
| `EN2T-C` | `EOL` | 1756-EN2T |
| `EN2T-D` | `12.002` | 1756-EN2T |
| `EN2F-A` | `EOL` | 1756-EN2F |
| `EN2F-B` | `EOL` | 1756-EN2F |
| `EN2F-C` | `12.002` | 1756-EN2F |
| `EN3TR-A` | `EOL` | 1756-EN3TR |
| `EN3TR-B` | `12.002` | 1756-EN3TR |
| `EN3TR-C` | `12.002` | 1756-EN3TR |

Each record's full name is `<label>.<vulnSearchSuffix>` (e.g. `EN2T-D.vuln.plc.local`). In a zone file:

```
EN2T-D.vuln.plc.local.  IN  TXT  "12.002"
L55-A.vuln.plc.local.   IN  TXT  "EOL"
```

### Result
Each module is marked `YES` (vulnerable), `NO` (not vulnerable), or `N/A` (could not be determined):
- `YES` — firmware is below the published threshold, or the record is `EOL`.
- `NO` — firmware is at or above the published threshold.
- `N/A` — the DNS server was unreachable, or the feature is disabled (empty `vulnSearchSuffix`).

When a lookup cannot be completed (no TXT record, DNS timeout, or an unparseable value), the module is conservatively treated as **vulnerable**.

### When it runs
- DNS availability is checked at the start of every LAN scan.
- Vulnerability status is evaluated when a device is first discovered and re-evaluated on every status check (`LAN_STATUS_CHECK_MULTIPLIER`, default hourly), so newly published advisories are picked up automatically.

The per-module vulnerability status is reflected in email alerts — the firmware version is color-coded (green = `NO`, red = `YES`, black = `N/A`) and firmware-change emails use an `ALERT` subject when vulnerable, otherwise `Notice`. The status is also held in memory (for a future in-memory database), like the advisory search URL.

## Programming
### Prepare configuration details for your device:  
- Host name
- Device IP address, gateway, and subnet mask
- DNS servers (optional)
- Vulnerability lookup DNS search suffix (`vulnSearchSuffix`) — optional
- SNMP trap receiver IP and community string if email (USE_SMTP) is _false_ (default)
- Email to and from addresses and SMTP relay IP if email (USE_SMTP) is _true_
- NTP server
- TCP and/or UDP ports to listen on (defaults are recommended)
- LAN scan interval, slot expansion check interval, and hosts excluded from network scans (optional)
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
| `newDeviceDiscoveredTrap` | `1.3.6.1.4.1.99999.0.8` | eventTime, deviceIp, deviceMac, (PLC: vendor, productName, firmware, serial, state, mode, and per-module slot/type/productName/firmware) |
| `deviceDisappearedTrap` | `1.3.6.1.4.1.99999.0.9` | eventTime, deviceIp, deviceMac |
| `deviceModeChangedTrap` | `1.3.6.1.4.1.99999.0.10` | eventTime, deviceIp, deviceMac, prevMode, mode |
| `deviceFirmwareChangedTrap` | `1.3.6.1.4.1.99999.0.11` | eventTime, deviceIp, deviceMac, moduleSlot, moduleType, moduleProductName, modulePreviousFirmware, moduleFirmware |
| `internetDetectedTrap` | `1.3.6.1.4.1.99999.0.12` | eventTime, gatewayIp, dhcpServerIp, internetAccessible, detectionMethod |
| `rogueDhcpServerTrap` | `1.3.6.1.4.1.99999.0.13` | eventTime, dhcpServerIp, gatewayIp |

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
| `.1.15.0` | `devicePreviousMode` | INTEGER (enum) |
| `.1.21.0` | `internetDhcpServerIp` | IpAddress |
| `.1.22.0` | `internetAccessible` | INTEGER (enum) |
| `.1.23.0` | `internetDetectionMethod` | INTEGER (enum) |
| `.1.24.0` | `internetGatewayIp` | IpAddress |
| `.1.25.1.1` | `moduleIndex` | INTEGER |
| `.1.25.1.2` | `moduleSlot` | INTEGER (0 = CPU) |
| `.1.25.1.3` | `moduleType` | INTEGER (enum) |
| `.1.25.1.4` | `moduleProductName` | OCTET STRING |
| `.1.25.1.5` | `moduleFirmware` | OCTET STRING |
| `.1.25.1.6` | `modulePreviousFirmware` | OCTET STRING |

### Enumerated varbinds (translated by the MIB)

- `honeypotProtocol`: `icmp(1)`, `tcp(6)`, `udp(17)`
- `honeypotStartReason`: `powerOn(1)`, `linkUp(2)`
- `honeypotIcmpType`: `ping(8)`, `pingExtended(42)`
- `deviceState`: `nonexistent(0)`, `selfTesting(1)`, `standby(2)`, `operational(3)`, `majorRecoverableFault(4)`, `majorUnrecoverableFault(5)`, `communicationFault(6)`, `unconfigured(7)`
- `deviceMode`: `program(0)`, `run(1)`, `testRemote(2)`
- `moduleType`: `cpu(14)`, `ethernet(12)`
- `internetAccessible`: `no(0)`, `yes(1)`
- `internetDetectionMethod`: `none(0)`, `tcpConnect(1)`, `dnsQuery(2)`

## Guidance and Limitations
- The device produces SNMPv2c traps on UDP port 162 (community string configurable in Config.h).
- SMTP alerts require an unauthenticated SMTP relay that is configured to allow the SCADASentry device IP address.
- TCP and UDP listening ports are fully user-configurable with no constraints.
- It is recommended you exempt the SCADASentry device IP addresses in any legitimate vulnerability or network scanners to avoid triggering alerts.
- If ICMP is disabled in Config.h, the device will respond to pings from any IP address within the routable network.
- LAN device discovery scans the local subnet using ARP, so it only sees devices on the same L2 segment (ARP doesn't cross routers).
- Internet detection probes for a DHCP server on the segment (retrieving both the server identifier and the advertised default gateway) and verifies Internet reachability through that gateway and/or the configured default gateway (TCP connect to a public anycast IP on port 443, falling back to a DNS query to a public resolver). It reports `internetDetectedTrap` when Internet access is detected, including the gateway and any DHCP server found.
- The Internet detection DHCP probe sends only a DHCPDISCOVER (never a DHCPREQUEST), so it does not obtain or reserve an IP address from any DHCP server; the device always keeps its statically-configured IP.
- If a DHCP server advertises a default gateway outside the device's statically-configured subnet, the device treats it as a rogue DHCP server: it skips testing that gateway and reports `rogueDhcpServerTrap` (including the rogue server IP and the advertised gateway) instead.
- A physical reset button (GPIO 45, active-high) clears all detected-device and holdoff state when held for at least 1 second, restarting detection as if the device had just booted.

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
