/*
 * LanScanner.h
 * 
 * LAN device discovery scanner for SCADASentry.
 * Periodically pings the local subnet, probes port 44818/TCP for
 * ControlLogix devices, queries their identity/status, and reports
 * devices via SNMP traps through HoneypotLogging.
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#ifndef LAN_SCANNER_H
#define LAN_SCANNER_H

#include <Arduino.h>
#include <IPAddress.h>
#include "Config.h"
#include "HoneypotLogging.h"
#include "ControlLogixDiscovery.h"

// Maximum number of CPU/Ethernet modules tracked per PLC (CPU + up to 5 more).
#define MAX_MODULES_PER_PLC 6

// A single detected CPU or Ethernet module within a PLC.
struct DeviceModule {
  uint8_t  slot;           // 0 = CPU, 1..16 = Ethernet module / secondary CPU
  uint16_t deviceType;     // 0x0E = CPU, 0x0C = Ethernet module
  char     searchTerm[8];  // extracted Tenable search term (max 7 chars + NUL)
  bool     isRun;          // run key status (CPU only; false for Ethernet)
  uint8_t  majorRevision;  // firmware major revision
  uint8_t  minorRevision;  // firmware minor revision
};

// A discovered LAN device
struct DeviceEntry {
  IPAddress ip;
  uint8_t mac[6];
  bool hasMac;
  bool isPlc;
  // PLC identity info (valid when isPlc)
  uint16_t vendor;
  char productName[64];
  char firmware[16];
  char serial[16];
  uint8_t state;
  int32_t mode;
  // Detected CPU/Ethernet modules (valid when isPlc)
  DeviceModule modules[MAX_MODULES_PER_PLC];
  uint8_t moduleCount;
  // Previous values for change detection
  char prevFirmware[16];
  int32_t prevMode;
  bool hasStatus;       // has status been queried at least once?
  // Timing
  uint32_t lastSeen;    // millis() of last successful ping
  uint32_t lastStatusCheck; // millis() of last status query
};

class LanScanner {
public:
  LanScanner(HoneypotLogging* logger, IPAddress localIP, IPAddress gateway, IPAddress subnetMask);
  void begin();
  // Run one scan cycle; returns immediately after a full sweep.
  // Called from the scanner FreeRTOS task at the configured interval.
  void runScan();

private:
  HoneypotLogging* logger;
  IPAddress localIP;
  IPAddress gateway;
  IPAddress subnetMask;
  IPAddress networkAddr;
  IPAddress broadcastAddr;

  DeviceEntry devices[MAX_DEVICES];
  int deviceCount;

  uint32_t scanCount;

  // EtherNet/IP discovery client (ListIdentity broadcast + CIP reads)
  ControlLogixDiscovery clx;

  // Helpers
  bool isExcluded(IPAddress ip);
  int findDevice(IPAddress ip);
  bool pingHost(IPAddress ip, uint32_t timeoutMs);
  bool getMac(IPAddress ip, uint8_t mac[6]);
  void populatePlc(DeviceEntry& dev, const ClxDiscoveryResult& d);
  void queryPlcMode(DeviceEntry& dev);
  void checkStatus(DeviceEntry& dev);
  void addDevice(const DeviceEntry& dev);
  void removeDevice(int index);
};

#endif // LAN_SCANNER_H
