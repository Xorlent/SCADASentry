/*
 * LanScanner.cpp
 * 
 * LAN device discovery scanner for SCADASentry.
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#include "LanScanner.h"
#include <ETH.h>
#include <lwip/netif.h>
#include <lwip/etharp.h>
#include <esp_timer.h>

// Ping timeout per host (ms)
#define PING_TIMEOUT_MS 100
// How long to wait for ListIdentity discovery responses (ms)
#define DISCOVER_TIMEOUT_MS 3000
// Per-PLC TCP read timeout for getPlcInfo (ms)
#define PLC_INFO_TIMEOUT_MS 2000
// Maximum backplane slot index to probe (17-slot 1756 chassis: slots 0..16).
#define MAX_SLOT 16

// Advance an IPv4 address to the next host address
static bool nextHost(IPAddress &ip) {
  for (int i = 3; i >= 0; --i) {
    if (ip[i] < 255) { ++ip[i]; return true; }
    ip[i] = 0;
  }
  return false;
}

// Map a ControlLogix keyswitch position to the deviceMode enum (see MIB):
//   program(0), run(1); -1 = unknown/unreadable.
// Only the physical RUN keyswitch position is reported as "run"; REMOTE RUN
// and REMOTE PROG are treated as not-run.
static int32_t keyswitchToMode(const String& keyswitch) {
  if (keyswitch.isEmpty() || keyswitch == "UNKNOWN") return -1;
  return (keyswitch == "RUN") ? 1 : 0;
}

// Human-readable run status (the only thing we care about).
static const char* modeName(int32_t mode) {
  return (mode == 1) ? "in RUN" : "***NOT in RUN***";
}

// Find a discovery result matching an IP address (or nullptr).
static const ClxDiscoveryResult* findDiscovered(const std::vector<ClxDiscoveryResult>& list, IPAddress ip) {
  for (size_t i = 0; i < list.size(); i++) {
    if (list[i].ipAddress == ip) return &list[i];
  }
  return nullptr;
}

// Tenable CVE search URL components (constant prefix/suffix).
static const char* TENABLE_URL_PREFIX   = "https://www.tenable.com/cve/search?q=controllogix+AND+";
static const char* TENABLE_URL_SUFFIX   = "&sort=newest";
static const char* TENABLE_URL_FALLBACK = "https://www.tenable.com/cve/search?q=controllogix&sort=newest";

// Extract the Tenable search term from a ControlLogix device type and product
// name. CPU (0x0E): the space-delimited string of numbers (e.g. "5561").
// Ethernet module (0x0C): the three characters after '-' (e.g. "ENB").
// Returns an empty string when no term can be extracted. The result is capped
// at 7 characters to fit the 8-byte searchTerm buffer.
static String tenableSearchTerm(uint16_t deviceType, const String& productName) {
  String searchResult;

  if (deviceType == 0x0E) {
    // CPU: find the space-delimited string of numbers in the product name.
    // e.g. "1756-L61 ControlLogix 5561 Controller" -> "5561"
    int start = 0;
    int len = productName.length();
    while (start < len) {
      while (start < len && productName[start] == ' ') start++;   // skip spaces
      int end = start;
      while (end < len && productName[end] != ' ') end++;          // end of token
      String token = productName.substring(start, end);
      bool allDigits = token.length() > 0;
      for (unsigned int i = 0; i < token.length(); i++) {
        char c = token[i];
        if (c < '0' || c > '9') { allDigits = false; break; }
      }
      if (allDigits) { searchResult = token; break; }
      start = end;
    }
  } else if (deviceType == 0x0C) {
    // Ethernet module: remove spaces, then take the three characters after '-'.
    // e.g. "1756-ENBT/A ..." -> "ENB"
    String noSpaces = productName;
    noSpaces.replace(" ", "");
    int dash = noSpaces.indexOf('-');
    if (dash >= 0 && (dash + 3) < (int)noSpaces.length()) {
      searchResult = noSpaces.substring(dash + 1, dash + 4);
    }
  }

  // Cap at 7 characters (fits the 8-byte searchTerm buffer).
  if (searchResult.length() > 7) {
    searchResult = searchResult.substring(0, 7);
  }
  return searchResult;
}

// Build the full Tenable CVE search URL from a search term.
static String tenableURL(const String& searchTerm) {
  if (searchTerm.length() == 0) {
    return String(TENABLE_URL_FALLBACK);
  }
  return String(TENABLE_URL_PREFIX) + searchTerm + String(TENABLE_URL_SUFFIX);
}

// Build the per-module list (CPU + Ethernet modules) for a PLC from getPlcInfo
// results, computing each module's Tenable search term. Returns the number of
// modules stored (capped at MAX_MODULES_PER_PLC).
static uint8_t buildModules(DeviceModule* out, const ClxPlcInfo& info) {
  uint8_t count = 0;
  for (size_t i = 0; i < info.modules.size() && count < MAX_MODULES_PER_PLC; i++) {
    const ClxModule& m = info.modules[i];
    DeviceModule& dm = out[count];
    dm.slot = m.slot;
    dm.deviceType = m.deviceType;
    dm.isRun = m.isRun;
    dm.majorRevision = m.majorRevision;
    dm.minorRevision = m.minorRevision;
    strncpy(dm.productName, m.productName.c_str(), sizeof(dm.productName) - 1);
    dm.productName[sizeof(dm.productName) - 1] = '\0';
    String term = tenableSearchTerm(m.deviceType, m.productName);
    strncpy(dm.searchTerm, term.c_str(), sizeof(dm.searchTerm) - 1);
    dm.searchTerm[sizeof(dm.searchTerm) - 1] = '\0';
    count++;
  }
  return count;
}

// Build the per-module email info (firmware + Tenable URL) for a PLC's
// new-device email. Fills `out` (up to MAX_MODULES_PER_PLC entries) and the
// `urlBuf` scratch buffers, returning the number of modules populated.
static uint8_t buildModuleEmailInfo(DeviceModuleEmailInfo* out, char urlBuf[][160],
                                    const DeviceEntry& dev) {
  uint8_t count = 0;
  for (uint8_t i = 0; i < dev.moduleCount && i < MAX_MODULES_PER_PLC; i++) {
    out[i].slot = dev.modules[i].slot;
    out[i].deviceType = dev.modules[i].deviceType;
    out[i].productName = dev.modules[i].productName;
    out[i].majorRevision = dev.modules[i].majorRevision;
    out[i].minorRevision = dev.modules[i].minorRevision;
    String url = tenableURL(String(dev.modules[i].searchTerm));
    strncpy(urlBuf[i], url.c_str(), 159);
    urlBuf[i][159] = '\0';
    out[i].tenableUrl = urlBuf[i];
    count++;
  }
  return count;
}

// Highest backplane slot (1..16) where a module was detected; 0 if none.
static uint8_t highestModuleSlot(const ClxPlcInfo& info) {
  uint8_t hi = 0;
  for (size_t i = 0; i < info.modules.size(); i++) {
    if (info.modules[i].slot > hi) hi = info.modules[i].slot;
  }
  return hi;
}

// Compare two module lists for change detection.
static bool modulesEqual(const DeviceModule* a, uint8_t na,
                         const DeviceModule* b, uint8_t nb) {
  if (na != nb) return false;
  for (uint8_t i = 0; i < na; i++) {
    if (a[i].slot != b[i].slot ||
        a[i].deviceType != b[i].deviceType ||
        a[i].isRun != b[i].isRun ||
        a[i].majorRevision != b[i].majorRevision ||
        a[i].minorRevision != b[i].minorRevision ||
        strcmp(a[i].searchTerm, b[i].searchTerm) != 0) {
      return false;
    }
  }
  return true;
}

// Print each detected module (debug): slot, type (CPU/Ethernet), name, firmware
// revision, and Tenable URL.
static void printModuleUrls(HoneypotLogging* logger, const ClxPlcInfo& info) {
  for (size_t i = 0; i < info.modules.size(); i++) {
    const ClxModule& m = info.modules[i];
    const char* typeStr = (m.deviceType == 0x0E) ? "CPU" : "Ethernet";
    String url = tenableURL(tenableSearchTerm(m.deviceType, m.productName));
    char buf[256];
    snprintf(buf, sizeof(buf), "[DEBUG] Slot %u (%s): %s fw %u.%u - %s",
             (unsigned)m.slot, typeStr, m.productName.c_str(),
             (unsigned)m.majorRevision, (unsigned)m.minorRevision, url.c_str());
    logger->safePrintln(buf);
  }
}

LanScanner::LanScanner(HoneypotLogging* logger, IPAddress localIP, IPAddress gateway, IPAddress subnetMask)
    : logger(logger), localIP(localIP), gateway(gateway), subnetMask(subnetMask) {
  deviceCount = 0;
  scanCount = 0;
  resetRequested = false;
}

void LanScanner::begin() {
  // Compute network and broadcast addresses
  for (int i = 0; i < 4; i++) {
    networkAddr[i] = localIP[i] & subnetMask[i];
    broadcastAddr[i] = (localIP[i] & subnetMask[i]) | (~subnetMask[i] & 0xFF);
  }
  // Initialize device list
  for (int i = 0; i < MAX_DEVICES; i++) {
    devices[i].ip = IPAddress(0, 0, 0, 0);
    devices[i].hasMac = false;
    devices[i].isPlc = false;
    devices[i].hasStatus = false;
    devices[i].moduleCount = 0;
    devices[i].highestSlot = 0;
  }
}

void LanScanner::requestReset() {
  resetRequested = true;
}

void LanScanner::runScan() {
  // Apply a user-requested state reset (reset button) before starting the scan.
  if (resetRequested) {
    resetRequested = false;
    deviceCount = 0;
    scanCount = 0;
    if (DEBUG) {
      logger->safePrintln("[DEBUG] LAN scanner state reset");
    }
  }

  scanCount++;
  int64_t scanStart = esp_timer_get_time();
  bool doStatusCheck = (scanCount % LAN_STATUS_CHECK_MULTIPLIER == 0);
  bool doExpansionCheck = (scanCount % SLOT_EXPANSION_CHECK_MULTIPLIER == 0);

  if (DEBUG) {
    char buf[48];
    snprintf(buf, sizeof(buf), "LAN scan #%lu started", (unsigned long)scanCount);
    logger->safePrintln(buf);
  }

  // 1. EtherNet/IP discovery: broadcast a ListIdentity request and collect the
  //    ControlLogix PLCs (and other EtherNet/IP devices) on the segment.
  std::vector<ClxDiscoveryResult> discovered;
  int plcCount = clx.discover(discovered, DISCOVER_TIMEOUT_MS);
  if (DEBUG) {
    char buf[48];
    snprintf(buf, sizeof(buf), "EtherNet/IP discovery: %d device(s)", plcCount);
    logger->safePrintln(buf);
  }

  // 2. Sweep the LAN range (ARP) to discover all devices and their MACs.
  IPAddress ip = networkAddr;
  nextHost(ip);  // skip the network address
  while (ip != broadcastAddr) {
    if (ip == gateway || ip == localIP || isExcluded(ip)) {
      nextHost(ip);
      continue;
    }
    if (pingHost(ip, PING_TIMEOUT_MS)) {
      uint8_t mac[6];
      bool hasMac = getMac(ip, mac);
      int idx = findDevice(ip);
      if (idx < 0) {
        // New device
        DeviceEntry dev;
        dev.ip = ip;
        memset(dev.mac, 0, 6);
        if (hasMac) { memcpy(dev.mac, mac, 6); }
        dev.hasMac = hasMac;
        dev.isPlc = false;
        dev.hasStatus = false;
        dev.moduleCount = 0;
        dev.highestSlot = 0;
        dev.lastSeen = esp_timer_get_time();
        dev.lastStatusCheck = 0;

        const ClxDiscoveryResult* plc = findDiscovered(discovered, ip);
        if (plc) {
          populatePlc(dev, *plc);
          dev.isPlc = true;
          queryPlcMode(dev);
          dev.hasStatus = true;
          dev.lastStatusCheck = esp_timer_get_time();

          // Build per-module info (firmware + Tenable URL) for the new-device email.
          DeviceModuleEmailInfo moduleInfos[MAX_MODULES_PER_PLC];
          char moduleUrlBuf[MAX_MODULES_PER_PLC][160];
          uint8_t moduleInfoCount = buildModuleEmailInfo(moduleInfos, moduleUrlBuf, dev);

          logger->sendNewDeviceTrap(ip, dev.mac, true, dev.vendor, dev.productName,
                                    dev.firmware, dev.serial, dev.state, dev.mode,
                                    moduleInfos, moduleInfoCount);
        } else {
          logger->sendNewDeviceTrap(ip, dev.mac, false, 0, "", "", "", 0, 0);
        }
        addDevice(dev);
        {
          char buf[256];
          if (dev.isPlc) {
            snprintf(buf, sizeof(buf),
                     "New device: %d.%d.%d.%d (MAC %02X:%02X:%02X:%02X:%02X:%02X) - PLC %s fw %s mode %s",
                     dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3],
                     (unsigned)dev.mac[0], (unsigned)dev.mac[1], (unsigned)dev.mac[2],
                     (unsigned)dev.mac[3], (unsigned)dev.mac[4], (unsigned)dev.mac[5],
                     dev.productName, dev.firmware, modeName(dev.mode));
          } else {
            snprintf(buf, sizeof(buf),
                     "New device: %d.%d.%d.%d (MAC %02X:%02X:%02X:%02X:%02X:%02X)",
                     dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3],
                     (unsigned)dev.mac[0], (unsigned)dev.mac[1], (unsigned)dev.mac[2],
                     (unsigned)dev.mac[3], (unsigned)dev.mac[4], (unsigned)dev.mac[5]);
          }
          logger->safePrintln(buf);
        }
      } else {
        // Existing device
        devices[idx].lastSeen = esp_timer_get_time();
        if (hasMac) {
          memcpy(devices[idx].mac, mac, 6);
          devices[idx].hasMac = true;
        }
        // A device previously seen as non-PLC may now be identified as a PLC.
        if (!devices[idx].isPlc) {
          const ClxDiscoveryResult* plc = findDiscovered(discovered, ip);
          if (plc) {
            populatePlc(devices[idx], *plc);
            devices[idx].isPlc = true;
            queryPlcMode(devices[idx]);
            devices[idx].hasStatus = true;
            devices[idx].lastStatusCheck = esp_timer_get_time();

            DeviceModuleEmailInfo moduleInfos[MAX_MODULES_PER_PLC];
            char moduleUrlBuf[MAX_MODULES_PER_PLC][160];
            uint8_t moduleInfoCount = buildModuleEmailInfo(moduleInfos, moduleUrlBuf, devices[idx]);

            logger->sendNewDeviceTrap(ip, devices[idx].mac, true, devices[idx].vendor,
                                      devices[idx].productName, devices[idx].firmware,
                                      devices[idx].serial, devices[idx].state, devices[idx].mode,
                                      moduleInfos, moduleInfoCount);
          }
        }
      }
    }
    // Quiet time between ARP discovery requests (network-impact throttle)
    delay(LAN_SCAN_ARP_THROTTLE_MS);

    nextHost(ip);
  }

  // 3. Track PLCs discovered via ListIdentity but not seen in the ARP sweep
  //    (e.g. devices that do not answer ARP requests).
  for (size_t i = 0; i < discovered.size(); i++) {
    int idx = findDevice(discovered[i].ipAddress);
    if (idx < 0) {
      DeviceEntry dev;
      dev.ip = discovered[i].ipAddress;
      memset(dev.mac, 0, 6);
      dev.hasMac = false;
      dev.isPlc = true;
      dev.moduleCount = 0;
      dev.highestSlot = 0;
      populatePlc(dev, discovered[i]);
      queryPlcMode(dev);
      dev.hasStatus = true;
      dev.lastSeen = esp_timer_get_time();
      dev.lastStatusCheck = esp_timer_get_time();

      DeviceModuleEmailInfo moduleInfos[MAX_MODULES_PER_PLC];
      char moduleUrlBuf[MAX_MODULES_PER_PLC][160];
      uint8_t moduleInfoCount = buildModuleEmailInfo(moduleInfos, moduleUrlBuf, dev);

      logger->sendNewDeviceTrap(dev.ip, dev.mac, true, dev.vendor, dev.productName,
                                dev.firmware, dev.serial, dev.state, dev.mode,
                                moduleInfos, moduleInfoCount);
      addDevice(dev);

      char buf[256];
      snprintf(buf, sizeof(buf), "New device: %d.%d.%d.%d - PLC %s fw %s mode %s (no ARP response)",
               dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3], dev.productName, dev.firmware, modeName(dev.mode));
      logger->safePrintln(buf);
    } else {
      // Refresh lastSeen for PLCs already tracked (so they aren't reported gone).
      devices[idx].lastSeen = esp_timer_get_time();
    }
  }

  // 4. Check for disappeared devices
  for (int i = deviceCount - 1; i >= 0; i--) {
    if (devices[i].lastSeen < scanStart) {
      char buf[48];
      snprintf(buf, sizeof(buf), "Device disappeared: %d.%d.%d.%d",
               devices[i].ip[0], devices[i].ip[1], devices[i].ip[2], devices[i].ip[3]);
      logger->safePrintln(buf);
      logger->sendDeviceGoneTrap(devices[i].ip, devices[i].mac, devices[i].isPlc);
      logger->removeIPFromHoldoff(devices[i].ip);
      removeDevice(i);
    }
  }

  // 5. Status check (every Nth scan); an expansion check widens the slot scan.
  if (doStatusCheck || doExpansionCheck) {
    for (int i = 0; i < deviceCount; i++) {
      if (devices[i].isPlc) {
        checkStatus(devices[i], doExpansionCheck);
      }
    }
  }

  if (DEBUG) {
    char buf[48];
    snprintf(buf, sizeof(buf), "LAN scan #%lu complete: %d device(s)",
             (unsigned long)scanCount, deviceCount);
    logger->safePrintln(buf);
  }
}

bool LanScanner::isExcluded(IPAddress ip) {
  for (int i = 0; i < excludedHostsCount; i++) {
    if (ip == excludedHosts[i]) return true;
  }
  return false;
}

int LanScanner::findDevice(IPAddress ip) {
  for (int i = 0; i < deviceCount; i++) {
    if (devices[i].ip == ip) return i;
  }
  return -1;
}

bool LanScanner::pingHost(IPAddress ip, uint32_t timeoutMs) {
  ip4_addr_t ipaddr;
  IP4_ADDR(&ipaddr, ip[0], ip[1], ip[2], ip[3]);

  // Send an ARP request to discover the device on the local subnet
  etharp_request(netif_default, &ipaddr);

  // Poll the ARP table for the response
  uint32_t start = millis();
  while (millis() - start < timeoutMs) {
    struct eth_addr* eth_ret = NULL;
    const ip4_addr_t* ip_ret = NULL;
    if (etharp_find_addr(netif_default, &ipaddr, &eth_ret, &ip_ret) >= 0 && eth_ret != NULL) {
      return true;
    }
    delay(10);
  }
  return false;
}

bool LanScanner::getMac(IPAddress ip, uint8_t mac[6]) {
  ip4_addr_t ipaddr;
  IP4_ADDR(&ipaddr, ip[0], ip[1], ip[2], ip[3]);
  struct eth_addr *eth_ret = NULL;
  const ip4_addr_t *ip_ret = NULL;
  if (etharp_find_addr(netif_default, &ipaddr, &eth_ret, &ip_ret) >= 0 && eth_ret != NULL) {
    memcpy(mac, eth_ret->addr, 6);
    return true;
  }
  return false;
}

// Populate a DeviceEntry's PLC identity fields from a ListIdentity result.
void LanScanner::populatePlc(DeviceEntry& dev, const ClxDiscoveryResult& d) {
  dev.vendor = d.vendorId;
  strncpy(dev.productName, d.productName.c_str(), sizeof(dev.productName) - 1);
  dev.productName[sizeof(dev.productName) - 1] = '\0';
  snprintf(dev.firmware, sizeof(dev.firmware), "%u.%u", d.majorRevision, d.minorRevision);
  snprintf(dev.serial, sizeof(dev.serial), "%lu", (unsigned long)d.serialNumber);
  dev.state = d.state;
  dev.mode = -1;
  dev.moduleCount = 0;   // populated by queryPlcMode() via getPlcInfo()
  dev.highestSlot = 0;   // populated by queryPlcMode() via getPlcInfo()
}

// Query the run-switch keyswitch position (mode) and module list for a PLC.
void LanScanner::queryPlcMode(DeviceEntry& dev) {
  ClxPlcInfo info;
  if (clx.getPlcInfo(dev.ip, info, PLC_INFO_TIMEOUT_MS, MAX_SLOT, true)) {
    dev.mode = keyswitchToMode(info.keyswitch);
    dev.moduleCount = buildModules(dev.modules, info);
    dev.highestSlot = highestModuleSlot(info);
    if (DEBUG) {
      char buf[128];
      snprintf(buf, sizeof(buf), "[DEBUG] PLC %d.%d.%d.%d is %s mode and has a backplane populated up to slot %u",
               dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3], modeName(dev.mode), (unsigned)dev.highestSlot);
      logger->safePrintln(buf);
      printModuleUrls(logger, info);
    }
  } else {
    dev.mode = -1;
  }
  clx.disconnect();
}

// Re-query a PLC's firmware, mode and modules, emitting traps on change
void LanScanner::checkStatus(DeviceEntry& dev, bool doExpansionCheck) {
  ClxPlcInfo info;
  uint8_t maxSlot = doExpansionCheck ? MAX_SLOT : dev.highestSlot;
  if (!clx.getPlcInfo(dev.ip, info, PLC_INFO_TIMEOUT_MS, maxSlot, false)) {
    clx.disconnect();
    return;  // unreachable or query failed
  }

  char freshFirmware[16];
  snprintf(freshFirmware, sizeof(freshFirmware), "%u.%u", info.cpuMajorRevision, info.cpuMinorRevision);
  int32_t freshMode = keyswitchToMode(info.keyswitch);

  // Build the fresh module list for change detection.
  DeviceModule freshModules[MAX_MODULES_PER_PLC];
  uint8_t freshCount = buildModules(freshModules, info);
  dev.highestSlot = highestModuleSlot(info);

  clx.disconnect();

  // Firmware change
  if (freshFirmware[0] != '\0' && dev.firmware[0] != '\0' &&
      strcmp(freshFirmware, dev.firmware) != 0) {
    char buf[128];
    snprintf(buf, sizeof(buf), "PLC firmware change: %d.%d.%d.%d %s -> %s",
             dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3], dev.firmware, freshFirmware);
    logger->safePrintln(buf);
    String cpuUrl = tenableURL(tenableSearchTerm(0x0E, info.productName));
    logger->sendDeviceFirmwareChangeTrap(dev.ip, dev.mac, dev.productName,
                                         dev.firmware, freshFirmware,
                                         cpuUrl.c_str());
    strncpy(dev.prevFirmware, dev.firmware, sizeof(dev.prevFirmware) - 1);
    dev.prevFirmware[sizeof(dev.prevFirmware) - 1] = '\0';
    strncpy(dev.firmware, freshFirmware, sizeof(dev.firmware) - 1);
    dev.firmware[sizeof(dev.firmware) - 1] = '\0';
  }

  // Run-switch mode change
  if (freshMode >= 0 && dev.mode >= 0 && freshMode != dev.mode) {
    char buf[128];
    snprintf(buf, sizeof(buf), "PLC mode change: %d.%d.%d.%d %ld -> %ld",
             dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3], (long)dev.mode, (long)freshMode);
    logger->safePrintln(buf);
    logger->sendDeviceModeChangeTrap(dev.ip, dev.mac, dev.mode, freshMode);
    dev.prevMode = dev.mode;
    dev.mode = freshMode;
  }
  // Ethernet module firmware change detection (email-only notification).
  for (size_t i = 0; i < info.modules.size(); i++) {
    const ClxModule& m = info.modules[i];
    if (m.deviceType != 0x0C) continue;  // only Ethernet modules
    const DeviceModule* old = nullptr;
    for (uint8_t j = 0; j < dev.moduleCount; j++) {
      if (dev.modules[j].slot == m.slot) { old = &dev.modules[j]; break; }
    }
    if (old == nullptr) continue;  // newly added module, not a firmware change
    if (old->majorRevision == m.majorRevision && old->minorRevision == m.minorRevision) continue;

    char prevFw[16], newFw[16];
    snprintf(prevFw, sizeof(prevFw), "%u.%u", (unsigned)old->majorRevision, (unsigned)old->minorRevision);
    snprintf(newFw, sizeof(newFw), "%u.%u", (unsigned)m.majorRevision, (unsigned)m.minorRevision);
    String url = tenableURL(tenableSearchTerm(m.deviceType, m.productName));

    char buf[128];
    snprintf(buf, sizeof(buf), "PLC Ethernet module (slot %u) firmware change: %s -> %s",
             (unsigned)m.slot, prevFw, newFw);
    logger->safePrintln(buf);

    logger->sendEthernetModuleFirmwareChangeTrap(dev.ip, dev.mac, m.slot,
                                                 m.productName.c_str(), prevFw, newFw,
                                                 url.c_str());
  }



  // CPU/Ethernet module change
  if (!modulesEqual(freshModules, freshCount, dev.modules, dev.moduleCount)) {
    dev.moduleCount = freshCount;
    for (uint8_t i = 0; i < freshCount; i++) {
      dev.modules[i] = freshModules[i];
    }
    if (DEBUG) {
      printModuleUrls(logger, info);
    }
  }

  dev.lastStatusCheck = esp_timer_get_time();
}

void LanScanner::addDevice(const DeviceEntry& dev) {
  if (deviceCount < MAX_DEVICES) {
    devices[deviceCount++] = dev;
  }
}

void LanScanner::removeDevice(int index) {
  if (index < 0 || index >= deviceCount) return;
  for (int i = index; i < deviceCount - 1; i++) {
    devices[i] = devices[i + 1];
  }
  deviceCount--;
}

