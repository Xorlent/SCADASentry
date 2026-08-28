## SCADASentry - SCADA PLC Network Monitoring for the Rest of Us
### Ultra low-cost, no maintenance, purpose-built Allen Bradley ControlLogix PLC network and vulnerability monitor ###

> [!WARNING]
> _USE AT YOUR OWN RISK._  This solution is not recommended where a malfunction could carry injury, life, or financial risk.
> 
![SCADASentry Sensor Image](https://github.com/Xorlent/SCADASentry/blob/main/images/SCADASentry.jpg)

## Table of Contents
- [Background](#background)
- [To-do](#to-do)
- [Requirements](#requirements)
- [Functional Description](#functional-description)
  - [Activity monitoring](#activity-monitoring)
  - [EtherNet/IP monitoring](#ethernetip-monitoring)
  - [LAN device discovery](#lan-device-discovery)
  - [Minimizing PLC impact](#minimizing-plc-impact)
  - [Internet and DHCP detection](#internet-and-dhcp-detection)
- [Firmware Vulnerability Lookup](#firmware-vulnerability-lookup)
  - [How it works](#how-it-works)
  - [TXT record format](#txt-record-format)
  - [Example DNS TXT records](#example-dns-txt-records)
  - [Result](#result)
  - [When it runs](#when-it-runs)
- [Programming](#programming)
  - [Prepare configuration details for your device](#prepare-configuration-details-for-your-device)
  - [Configure and flash the device](#configure-and-flash-the-device)
- [SNMP Trap Reference](#snmp-trap-reference)
  - [LAN device discovery traps](#lan-device-discovery-traps)
  - [Device object varbinds](#device-object-varbinds)
  - [Enumerated varbinds (translated by the MIB)](#enumerated-varbinds-translated-by-the-mib)
- [Guidance and Notes](#guidance-and-notes)
- [Technical Information](#technical-information)

## Background
Commercial OT/SCADA vulnerability and monitoring platforms are expensive to license, time-consuming to stand up, and finicky to keep running - and once they are running they tend to flood operators with unnecessary notifications that cause alert fatigue. For many, the cost and operational overhead can be hard to justify, especially in smaller environments.

SCADASentry takes a different approach. It is a purpose-built, ultra low-cost (~$21.50 in hardware), zero-maintenance device that plugs into a PoE port and quietly watches your PLC LAN. It reports only the events that matter: new or departed devices, run-key and firmware changes, and scanning/reconnaissance activity - All via standard SNMP traps or email.  No servers, specialized network appliances, span ports, agent software, cloud dependency, and no tuning required.

This device was designed specifically for monitoring Allen Bradley ControlLogix PLC network environments and is intentionally simple.  If detailed device activity (tag create/delete, program load, etc.) is needed, a commercial OT/SCADA platform is likely the better choice.

## To-do
- End-to-end SMTP testing
- Network stress test

## Requirements
1. M5Stack [Unit-PoE-P4](https://shop.m5stack.com/products/unit-poe-with-esp32-p4), currently $21.50 USD
2. PoE network port or PoE power injector or a USB charger to power the device once deployed
3. USB-C cable for programming
4. An SNMP trap receiver (NMS such as PRTG) or an available SMTP relay
5. An accessible NTP server for time synchronization

## Functional Description
SCADASentry is a honeypot that listens on any number of user-configurable TCP and UDP ports and reports activity via **SNMPv2c traps** (or email via SMTP). It detects devices joining and leaving the local PLC LAN, alerts on scanning, reconnaissance, and lateral movement, and reports basic ControlLogix device information - notifying on run-key or firmware version changes.

### Activity monitoring
When unexpected activity is detected, the device immediately sends a trap or email containing the source IP, protocol, destination port (or ICMP type), and service name. The following events are reported:

| Event | Trap |
|-------|------|
| TCP connection on a monitored port | `tcpConnectionTrap` |
| UDP packet on a monitored port | `udpConnectionTrap` |
| ICMP request of a monitored type | `icmpRequestTrap` |
| Fragmented IP packet (suspicious) | `ipFragmentTrap` |
| IP packet with options (suspicious) | `ipOptionsTrap` |
| Device comes online (boot or link recovery) | `deviceOnlineTrap` |

The device sends a `deviceOnlineTrap` when it boots (power recovery) or when its Ethernet link recovers, with a `honeypotStartReason` varbind distinguishing the cause (`powerOn` vs `linkUp`). It can also be configured to alert on ICMP ping requests (note: it will not respond to pings when ICMP monitoring is enabled).

### EtherNet/IP monitoring
For Rockwell Automation / EtherNet/IP broadcast traffic, the device listens on UDP ports **44818** and **2222** and reports only `ListIdentity` browse/discovery traffic, silently ignoring device I/O data. This detects RSLogix/RSLinx device browsing activity from unauthorized devices.

### LAN device discovery
The device periodically scans the local LAN using ARP to discover devices. For each discovered device it:

- Identifies ControlLogix PLCs via an EtherNet/IP `ListIdentity` broadcast, then queries them over TCP 44818 for identity, firmware, serial, state, and run-switch mode.
- Probes hosts that do not answer the `ListIdentity` broadcast directly on TCP 44818, so PLCs that suppress discovery responses are still identified.
- Reports newly discovered devices via `newDeviceDiscoveredTrap`, including the MAC address and the vendor, product name, firmware, serial, state, and run-switch mode if it is a PLC.
- Reports devices that stop responding via `deviceDisappearedTrap`. A departed device is detected only after its ARP entry expires, so this trap can lag a device's actual departure by up to 5 minutes.
- Re-checks the run-switch mode and firmware version of discovered PLCs periodically (configurable), reporting changes via `deviceModeChangedTrap` / `deviceFirmwareChangedTrap`.
- Enumerates the CPU and any Ethernet modules in the rack (including redundant/secondary CPUs) and derives an Advisory CVE search URL for each module.

### Minimizing PLC impact
SCADASentry is designed to be a passive observer of production PLCs, so it goes out of its way to avoid disturbing the controllers it monitors.

**No ICMP traffic.** Device discovery does not use ICMP echo requests (ping). Instead, the device sweeps the local subnet with ARP requests (`etharp_request`), which are answered by the network interface at the link layer and never touch a PLC's IP stack or CPU the way an ICMP echo would. Each host is probed with a single ARP request, and requests are throttled between hosts (`LAN_SCAN_ARP_THROTTLE_MS` in Config.h) to keep the scan's impact on the segment low.

**Only the data we need.** When querying a discovered PLC, the device reads only the CIP Identity object - product name, firmware revision, keyswitch position, serial number, and state - plus the Identity of each CPU and Ethernet module in the rack. Backplane slots are probed only up to the highest slot previously detected on each PLC, with a periodic full re-probe to catch modules added to higher slots (`SLOT_EXPANSION_CHECK_MULTIPLIER` in Config.h).

### Internet and DHCP detection
The device periodically probes the local LAN for a DHCP server and verifies Internet reachability:

- It retrieves the DHCP server identifier and the advertised default gateway, then tests Internet reachability through that gateway and/or the configured default gateway (a TCP connection to a public anycast IP on port 443, falling back to a DNS query to a public resolver).
- When Internet access is detected, it reports `internetDetectedTrap`, including the gateway and any DHCP server found.
- The DHCP probe sends only a DHCPDISCOVER, so it does not obtain or reserve an IP address - the device always keeps its statically-configured IP.
- If a DHCP server advertises a default gateway outside the device's configured subnet, the device treats it as a rogue DHCP server: it skips testing that gateway and reports `rogueDhcpServerTrap` (including the rogue server IP and the advertised gateway) instead.

## Firmware Vulnerability Lookup
SCADASentry can determine whether a discovered ControlLogix CPU or Ethernet module is running firmware with known vulnerabilities. It uses DNS TXT records, so it works using your own DNS infrastructure in a disconnected environment.

### How it works
1. For each module, the device extracts the full catalog suffix from the product name (e.g. `1756-EN2T/B` -> `EN2T/B`, `1756-L55/A` -> `L55/A`) and converts it to a valid DNS label (`/` becomes `-`, e.g. `EN2T/B` -> `EN2T-B`).
2. It prepends that label to `vulnSearchSuffix` (Config.h) to form the TXT record name, e.g. `EN2T-B.vuln.plc.local`.
3. It queries the configured DNS servers (`dns1`, then `dns2`) for a TXT record at that name.

### TXT record format
The TXT value is the **minimum firmware revision that is _not_ vulnerable**, formatted `major.minor` (e.g. `11.2`), or the literal string `EOL` (case-insensitive) for end-of-life products. For example, `EN2T-B.vuln.plc.local  TXT  "11.2"` marks any `1756-EN2T/B` running firmware older than `11.2` as vulnerable.

### Example DNS TXT records
The TXT record name is the module's full catalog suffix (with `/` replaced by `-`) prepended to `vulnSearchSuffix` in Config.h. For example, a `1756-EN2T/D` module (`EN2T/D` -> `EN2T-D`) with `vulnSearchSuffix = "vuln.plc.local"` resolves `EN2T-D.vuln.plc.local`. For CPUs whose product name has no catalog prefix (e.g. `ControlLogix 5580 Controller`), the short search term (`5580`) is used instead.

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
Windows DNS Server example:  
[DNS Vulnerability DB](https://github.com/Xorlent/SCADASentry/blob/main/images/DNSVulnerabilityDB.png)
### Result
Each module is marked `YES` (vulnerable), `NO` (not vulnerable), or `N/A` (could not be determined):
- `YES` - firmware is below the published threshold, or the record is `EOL`.
- `NO` - firmware is at or above the published threshold.
- `N/A` - the DNS server was unreachable, or the feature is disabled (empty `vulnSearchSuffix` in Config.h).

When a lookup cannot be completed (no TXT record, DNS timeout, or an unparseable value), the module is conservatively treated as **vulnerable**.

### When it runs
- DNS availability is checked at the start of every LAN scan.
- Vulnerability status is evaluated when a device is first discovered and re-evaluated on every status check (`LAN_STATUS_CHECK_MULTIPLIER` in Config.h, default hourly), so newly published advisories are picked up automatically.

The per-module vulnerability status is reflected in email alerts - the firmware version is color-coded (green = `NO`, red = `YES`, black = `N/A`) and firmware-change emails use an `ALERT` subject when vulnerable, otherwise `Notice`. The status is also held in memory, like the advisory search URL.

## Programming
### Prepare configuration details for your device:  
- Host name
- Device IP address, gateway, and subnet mask
- Local DNS servers (recommended)
- Vulnerability lookup DNS search suffix (recommended)
- SNMP trap receiver IP and community string if email (USE_SMTP) is _false_ (default)
- Email to, from addresses, and SMTP relay IP if email (USE_SMTP) is _true_
- List of IP addresses (`excludedHosts` in Config.h) to exclude from the LAN scan and from honeypot alerting (traffic from these IPs does not generate alerts)
  - Example: RSLinx/FactoryTalk PC
- List of PLC IP addresses (`excludedPLCs` in Config.h) to exclude from ARP and EtherNet/IP discovery (these PLCs are not probed and not reported, even if they answer the `ListIdentity` broadcast)
- NTP server (required)
- TCP and/or UDP ports to listen on (defaults are recommended)
- LAN scan interval, slot expansion check interval, and hosts excluded from network scans (defaults are recommended)
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
   - Edit Config.h with configuration details you have collected for the device
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
8. If using SNMP (versus SMTP), configure your SNMP trap alerts:
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

## Guidance and Notes
- The device produces SNMPv2c traps on UDP port 162 (community string configurable in Config.h).
- SMTP alerts require an unauthenticated SMTP relay that is configured to allow the SCADASentry device IP address.
- TCP and UDP listening ports are fully user-configurable with no constraints.
- It is recommended you exempt the SCADASentry device IP addresses in any legitimate vulnerability or network scanners to avoid triggering honeypot alerts.
- If ICMP is disabled in Config.h, the device will respond to pings from any IP address within the routable network.
- LAN device discovery scans the local subnet using ARP, so it only sees devices on the same L2 segment.
- Pressing the button on the side of the Unit-PoE-P4 clears all detected-device and holdoff state when held for at least 1 second, restarting detection as if the device had just booted.

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
