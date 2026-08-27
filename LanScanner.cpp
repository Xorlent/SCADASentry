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
#include <WiFiUdp.h>
#include <lwip/netif.h>
#include <lwip/etharp.h>
#include <esp_timer.h>
#include <esp_system.h>

// ARP probe timeout per host (ms)
#define ARP_TIMEOUT_MS 100
// How long to wait for ListIdentity discovery responses (ms)
#define DISCOVER_TIMEOUT_MS 3000
// Per-PLC TCP read timeout for getPlcInfo (ms)
#define PLC_INFO_TIMEOUT_MS 2000
// Maximum backplane slot index to probe (17-slot 1756 chassis: slots 0..16).
#define MAX_SLOT 16

// DNS TXT query constants
#define DNS_PORT 53
#define DNS_QTYPE_TXT 16
#define DNS_QCLASS_IN 1
#define VULN_DNS_TIMEOUT_MS 1000

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

// Advisory CVE search URL components (constant prefix/suffix).
static const char* ADVISORY_URL_PREFIX   = "https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html?sort=pubAsc&ra-advisories-search-input=";
static const char* ADVISORY_URL_SUFFIX   = "&cvss-score=critical-9-0-10-0&cvss-score=high-7-0-8-9";
static const char* ADVISORY_URL_FALLBACK = "https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html?sort=pubAsc&cvss-score=critical-9-0-10-0&cvss-score=high-7-0-8-9";

// Extract the Advisory search term from a ControlLogix device type and product
// name. CPU (0x0E): a space-delimited string of numbers (e.g. "5561"), or the
// "L" + number catalog designator (e.g. "L55", "L340") for CPUs without one.
// Ethernet module (0x0C): the three characters after '-' (e.g. "ENB").
// Returns an empty string when no term can be extracted. The result is capped
// at 7 characters to fit the 8-byte searchTerm buffer.
static String advisorySearchTerm(uint16_t deviceType, const String& productName) {
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

    // Some Logix CPUs carry no standalone numeric token; their product name
    // begins with the "NNNN-Lxx" catalog number across platform families (1756,
    // 1768, 1769, 5069), e.g. "1756-L55/A ..." or "5069-L340ERM/A ...".
    // Fall back to the letter + digit designator after "-L" (e.g. "L55", "L340").
    if (searchResult.length() == 0) {
      int p = productName.indexOf("-L");
      if (p >= 0) {
        p += 1;  // skip '-', start at 'L'
        int q = p;
        while (q < len &&
               ((productName[q] >= 'A' && productName[q] <= 'Z') ||
                (productName[q] >= 'a' && productName[q] <= 'z'))) q++;
        int digitStart = q;
        while (q < len && productName[q] >= '0' && productName[q] <= '9') q++;
        if (digitStart > p && q > digitStart) {
          searchResult = productName.substring(p, q);
        }
      }
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

// Build the full Advisory CVE search URL from a search term.
static String advisoryURL(const String& searchTerm) {
  if (searchTerm.length() == 0) {
    return String(ADVISORY_URL_FALLBACK);
  }
  return String(ADVISORY_URL_PREFIX) + searchTerm + String(ADVISORY_URL_SUFFIX);
}

// Extract the full device catalog suffix (catalog number + revision) from a
// product name, e.g. "1756-EN2T/B" -> "EN2T/B" or "1756-L55/A 1756-M12/A
// LOGIX5555" -> "L55/A". This is intentionally separate from
// advisorySearchTerm(), which returns only the short search term; the full
// suffix (including the "/x" revision) is required for firmware vulnerability
// lookups.
static String fullCatalogSuffix(const String& productName) {
  int dash = productName.indexOf('-');
  if (dash < 0) return String();
  int start = dash + 1;
  int end = start;
  int len = productName.length();
  while (end < len && productName[end] != ' ') end++;
  return productName.substring(start, end);
}

// Convert a catalog suffix into a valid DNS hostname label. The only DNS-
// invalid character that appears in ControlLogix catalog names is '/', which
// is mapped to '-'. (Spaces never reach this point because fullCatalogSuffix()
// truncates at the first space; letters, digits and '-' are already valid.)
static String catalogToDnsName(const String& suffix) {
  String s = suffix;
  s.replace("/", "-");
  return s;
}

// Skip a (possibly compressed) DNS name in a message, returning the offset of
// the first byte after it.
static int skipDnsName(const uint8_t* msg, int len, int off) {
  while (off < len) {
    uint8_t b = msg[off];
    if (b == 0) { off++; break; }                  // zero-length root label
    if ((b & 0xC0) == 0xC0) { off += 2; break; }   // compression pointer
    off += 1 + b;                                  // label length + label bytes
  }
  return off;
}

// Build a DNS query for `hostname` (QTYPE `qtype`) into `query` (capacity
// `cap`), setting `id` to the random transaction ID. Returns the query length,
// or 0 if the name would overflow the buffer.
static int buildDnsQuery(uint8_t* query, int cap, uint16_t& id, const char* hostname, uint16_t qtype) {
  memset(query, 0, cap);
  id = (uint16_t)(esp_random() & 0xFFFF);
  query[0] = (id >> 8) & 0xFF;
  query[1] = id & 0xFF;
  query[2] = 0x01;  // RD (recursion desired)
  query[3] = 0x00;
  query[4] = 0x00; query[5] = 0x01;  // QDCOUNT = 1

  int pos = 12;
  const char* p = hostname;
  while (*p) {
    const char* dot = strchr(p, '.');
    int lblen = dot ? (int)(dot - p) : (int)strlen(p);
    if (pos + 1 + lblen >= cap) return 0;
    query[pos++] = (uint8_t)lblen;
    memcpy(query + pos, p, lblen);
    pos += lblen;
    if (dot) p = dot + 1; else break;
  }
  query[pos++] = 0;                                   // terminating root label
  query[pos++] = (qtype >> 8) & 0xFF; query[pos++] = qtype & 0xFF;  // QTYPE
  query[pos++] = 0x00; query[pos++] = DNS_QCLASS_IN;  // QCLASS = IN
  return pos;
}

// Perform a DNS TXT query for `hostname` against `dnsServer` and return the
// concatenated TXT character-strings, or an empty String on failure/timeout.
static String dnsTxtQuery(const char* hostname, IPAddress dnsServer, uint32_t timeoutMs) {
  WiFiUDP udp;
  if (!udp.begin(0)) return String();  // ephemeral source port

  uint8_t query[256];
  uint16_t id;
  int qlen = buildDnsQuery(query, sizeof(query), id, hostname, DNS_QTYPE_TXT);
  if (qlen == 0) { udp.stop(); return String(); }

  udp.beginPacket(dnsServer, DNS_PORT);
  udp.write(query, qlen);
  udp.endPacket();

  uint32_t start = millis();
  while (millis() - start < timeoutMs) {
    int size = udp.parsePacket();
    if (size >= 12) {
      uint8_t resp[512];
      int n = udp.read(resp, sizeof(resp));
      if (n >= 12 && resp[0] == query[0] && resp[1] == query[1]) {
        uint16_t flags = ((uint16_t)resp[2] << 8) | resp[3];
        uint16_t ancount = ((uint16_t)resp[6] << 8) | resp[7];
        if ((flags & 0x8000) && ((flags & 0x000F) == 0) && ancount > 0) {
          int off = 12;
          off = skipDnsName(resp, n, off);
          off += 4;  // skip QTYPE + QCLASS
          for (int a = 0; a < ancount; a++) {
            off = skipDnsName(resp, n, off);
            if (off + 10 > n) break;
            uint16_t type = ((uint16_t)resp[off] << 8) | resp[off + 1];
            uint16_t rdlen = ((uint16_t)resp[off + 8] << 8) | resp[off + 9];
            off += 10;
            if (type == DNS_QTYPE_TXT && off + rdlen <= n) {
              String result;
              int end = off + rdlen;
              while (off < end) {
                uint8_t slen = resp[off++];
                if (off + slen > end) break;
                for (int k = 0; k < slen; k++) result += (char)resp[off++];
              }
              udp.stop();
              return result;
            }
            off += rdlen;
          }
        }
      }
    }
    delay(10);
  }

  udp.stop();
  return String();
}

// Test whether `dnsServer` responds to a DNS query for `hostname` within
// `timeoutMs`. Returns true if any valid DNS response (QR bit set, matching
// transaction ID) is received, regardless of RCODE or answer count. Used to
// determine DNS server availability before per-module vulnerability lookups.
static bool dnsReachable(const char* hostname, IPAddress dnsServer, uint32_t timeoutMs) {
  WiFiUDP udp;
  if (!udp.begin(0)) return false;

  uint8_t query[256];
  uint16_t id;
  int qlen = buildDnsQuery(query, sizeof(query), id, hostname, DNS_QTYPE_TXT);
  if (qlen == 0) { udp.stop(); return false; }

  udp.beginPacket(dnsServer, DNS_PORT);
  udp.write(query, qlen);
  udp.endPacket();

  uint32_t start = millis();
  while (millis() - start < timeoutMs) {
    int size = udp.parsePacket();
    if (size >= 12) {
      uint8_t resp[512];
      int n = udp.read(resp, sizeof(resp));
      if (n >= 12 && resp[0] == query[0] && resp[1] == query[1]) {
        uint16_t flags = ((uint16_t)resp[2] << 8) | resp[3];
        if (flags & 0x8000) {  // QR bit set = a response
          udp.stop();
          return true;
        }
      }
    }
    delay(10);
  }
  udp.stop();
  return false;
}

// Parse a "major.minor" firmware revision string into a comparable integer
// (major * 1000 + minor). Integer comparison avoids the float rounding edge
// cases (e.g. "11.10" vs "11.2"). The minor revision may have up to three
// digits (e.g. "12.002"), so a 1000 multiplier keeps distinct versions from
// colliding. Returns -1 if the string is not a valid numeric revision, so
// callers can treat unparseable values as "assume vulnerable".
static int firmwareToInt(const String& s) {
  int dot = s.indexOf('.');
  String majorStr = (dot >= 0) ? s.substring(0, dot) : s;
  String minorStr = (dot >= 0) ? s.substring(dot + 1) : String("0");

  if (majorStr.length() == 0 || minorStr.length() == 0) return -1;
  for (unsigned int i = 0; i < majorStr.length(); i++) {
    if (majorStr[i] < '0' || majorStr[i] > '9') return -1;
  }
  for (unsigned int i = 0; i < minorStr.length(); i++) {
    if (minorStr[i] < '0' || minorStr[i] > '9') return -1;
  }

  return (int)majorStr.toInt() * 1000 + (int)minorStr.toInt();
}

// Determine whether a module is vulnerable to known firmware issues. Looks up
// the TXT record "<catalog>.<vulnSearchSuffix>" (e.g. "EN2T-B.vuln.example.com")
// on the configured DNS servers. The TXT value is the minimum firmware revision
// that is NOT vulnerable, or "EOL" for end-of-life products.
//
// Returns true (vulnerable, or assume vulnerable when unknown) when:
//   * the catalog suffix cannot be extracted,
//   * no TXT record is returned (NXDOMAIN, no answer, or DNS timeout),
//   * the TXT value is "EOL" (case-insensitive) or unparseable, or
//   * the module firmware revision is below the returned threshold.
// Returns false (not vulnerable) when firmware >= the returned threshold.
static bool isModuleVulnerable(uint16_t deviceType, const String& productName, uint8_t majorRevision, uint8_t minorRevision) {
  if (vulnSearchSuffix[0] == '\0') return true;  // lookups disabled -> assume vulnerable

  String host = catalogToDnsName(fullCatalogSuffix(productName));
  if (host.length() == 0) {
    // No "1756-" catalog prefix (e.g. "ControlLogix 5580 Controller"); fall
    // back to the short search term (e.g. "5580").
    host = advisorySearchTerm(deviceType, productName);
  }
  if (host.length() == 0) return true;  // no catalog suffix -> assume vulnerable

  String fqdn = host + "." + String(vulnSearchSuffix);

  String txt = dnsTxtQuery(fqdn.c_str(), dns1, VULN_DNS_TIMEOUT_MS);
  if (txt.length() == 0) {
    txt = dnsTxtQuery(fqdn.c_str(), dns2, VULN_DNS_TIMEOUT_MS);
  }
  if (txt.length() == 0) return true;  // no response -> assume vulnerable
  if (txt.equalsIgnoreCase("EOL")) return true;  // end-of-life -> vulnerable

  int threshold = firmwareToInt(txt);
  if (threshold < 0) return true;  // unparseable -> assume vulnerable

  int fw = (int)majorRevision * 1000 + (int)minorRevision;

  if (fw >= threshold) return false;  // firmware at/above the fixed revision
  return true;
}

// Build the per-module list (CPU + Ethernet modules) for a PLC from getPlcInfo
// results, computing each module's Advisory search term. Returns the number of
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
    String term = advisorySearchTerm(m.deviceType, m.productName);
    strncpy(dm.searchTerm, term.c_str(), sizeof(dm.searchTerm) - 1);
    dm.searchTerm[sizeof(dm.searchTerm) - 1] = '\0';
    count++;
  }
  return count;
}

// Build the per-module email info (firmware + Advisory URL) for a PLC's
// new-device email. Fills `out` (up to MAX_MODULES_PER_PLC entries) and the
// `urlBuf` scratch buffers, returning the number of modules populated.
static uint8_t buildModuleEmailInfo(DeviceModuleEmailInfo* out, char urlBuf[][224],
                                    const DeviceEntry& dev) {
  uint8_t count = 0;
  for (uint8_t i = 0; i < dev.moduleCount && i < MAX_MODULES_PER_PLC; i++) {
    out[i].slot = dev.modules[i].slot;
    out[i].deviceType = dev.modules[i].deviceType;
    out[i].productName = dev.modules[i].productName;
    out[i].majorRevision = dev.modules[i].majorRevision;
    out[i].minorRevision = dev.modules[i].minorRevision;
    out[i].isVulnerable = dev.modules[i].isVulnerable;
    String url = advisoryURL(String(dev.modules[i].searchTerm));
    strncpy(urlBuf[i], url.c_str(), 223);
    urlBuf[i][223] = '\0';
    out[i].advisoryUrl = urlBuf[i];
    count++;
  }
  return count;
}

// Highest backplane slot (1..16) where a module was detected; 0 if none.
// Ignores slot 0 (CPU) and the directly-connected-bridge sentinel (0xFF).
static uint8_t highestModuleSlot(const ClxPlcInfo& info) {
  uint8_t hi = 0;
  for (size_t i = 0; i < info.modules.size(); i++) {
    uint8_t s = info.modules[i].slot;
    if (s >= 1 && s <= MAX_SLOT && s > hi) hi = s;
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
// revision, and Advisory URL.
static void printModuleUrls(HoneypotLogging* logger, const ClxPlcInfo& info) {
  for (size_t i = 0; i < info.modules.size(); i++) {
    const ClxModule& m = info.modules[i];
    const char* typeStr = (m.deviceType == 0x0E) ? "CPU" : "Ethernet";
    String url = advisoryURL(advisorySearchTerm(m.deviceType, m.productName));
    char buf[256];
    // 0xFF is the sentinel for the directly-connected Ethernet bridge, whose
    // backplane slot is not exposed (see SLOT_DIRECT_BRIDGE).
    if (m.slot == 0xFF) {
      snprintf(buf, sizeof(buf), "[DEBUG] Ethernet bridge (directly connected): %s fw %u.%u - %s",
               m.productName.c_str(),
               (unsigned)m.majorRevision, (unsigned)m.minorRevision, url.c_str());
    } else {
      snprintf(buf, sizeof(buf), "[DEBUG] Slot %u (%s): %s fw %u.%u - %s",
               (unsigned)m.slot, typeStr, m.productName.c_str(),
               (unsigned)m.majorRevision, (unsigned)m.minorRevision, url.c_str());
    }
    logger->safePrintln(buf);
  }
}

LanScanner::LanScanner(HoneypotLogging* logger, IPAddress localIP, IPAddress gateway, IPAddress subnetMask)
    : logger(logger), localIP(localIP), gateway(gateway), subnetMask(subnetMask) {
  deviceCount = 0;
  scanCount = 0;
  resetRequested = false;
  isDNSAvailable = false;
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

  // Test DNS server availability (used to gate vulnerability lookups).
  isDNSAvailable = (vulnSearchSuffix[0] != '\0') &&
                   (dnsReachable(vulnSearchSuffix, dns1, VULN_DNS_TIMEOUT_MS) ||
                    dnsReachable(vulnSearchSuffix, dns2, VULN_DNS_TIMEOUT_MS));
  if (DEBUG) {
    char buf[64];
    snprintf(buf, sizeof(buf), "[DEBUG] DNS availability: %s",
             isDNSAvailable ? "available" : "unavailable");
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
    if (arpProbe(ip, ARP_TIMEOUT_MS)) {
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
        dev.vendor = 0;
        dev.productName[0] = '\0';
        dev.firmware[0] = '\0';
        dev.serial[0] = '\0';
        dev.state = 0xFF;
        dev.mode = -1;

        const ClxDiscoveryResult* plc = findDiscovered(discovered, ip);
        if (plc) {
          populatePlc(dev, *plc);
          dev.isPlc = true;
          queryPlcMode(dev);
        } else if (queryPlcMode(dev)) {
          // Not in the ListIdentity results, but answered on TCP 44818: a PLC
          // that does not respond to ListIdentity broadcasts.
          dev.isPlc = true;
        }

        if (dev.isPlc) {
          dev.hasStatus = true;
          dev.lastStatusCheck = esp_timer_get_time();

          // Build per-module info (firmware + Advisory URL) for the new-device email.
          DeviceModuleEmailInfo moduleInfos[MAX_MODULES_PER_PLC];
          char moduleUrlBuf[MAX_MODULES_PER_PLC][224];
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
        // A device previously seen as non-PLC may now be identified as a PLC
        // (via ListIdentity, or by probing TCP 44818 directly).
        if (!devices[idx].isPlc) {
          const ClxDiscoveryResult* plc = findDiscovered(discovered, ip);
          bool becamePlc = false;
          if (plc) {
            populatePlc(devices[idx], *plc);
            devices[idx].isPlc = true;
            queryPlcMode(devices[idx]);
            becamePlc = true;
          } else if (queryPlcMode(devices[idx])) {
            devices[idx].isPlc = true;
            becamePlc = true;
          }

          if (becamePlc) {
            devices[idx].hasStatus = true;
            devices[idx].lastStatusCheck = esp_timer_get_time();

            DeviceModuleEmailInfo moduleInfos[MAX_MODULES_PER_PLC];
            char moduleUrlBuf[MAX_MODULES_PER_PLC][224];
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
      char moduleUrlBuf[MAX_MODULES_PER_PLC][224];
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

bool LanScanner::arpProbe(IPAddress ip, uint32_t timeoutMs) {
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
bool LanScanner::queryPlcMode(DeviceEntry& dev) {
  ClxPlcInfo info;
  bool ok = clx.getPlcInfo(dev.ip, info, PLC_INFO_TIMEOUT_MS, MAX_SLOT, true);
  if (ok) {
    dev.mode = keyswitchToMode(info.keyswitch);
    dev.moduleCount = buildModules(dev.modules, info);
    dev.highestSlot = highestModuleSlot(info);
    setModuleVulnerability(dev.modules, dev.moduleCount);
    // Use the CPU's identity (slot 0) as the device's PLC identity rather than
    // the ListIdentity result, which may belong to the Ethernet bridge (e.g. an
    // older 1756-ENBT/A answering the discovery instead of the CPU).
    dev.vendor = info.vendorId;
    strncpy(dev.productName, info.productName.c_str(), sizeof(dev.productName) - 1);
    dev.productName[sizeof(dev.productName) - 1] = '\0';
    snprintf(dev.firmware, sizeof(dev.firmware), "%u.%u", info.cpuMajorRevision, info.cpuMinorRevision);
    // Serial and state are also sourced from the CPU read now; keep the
    // ListIdentity-derived values if the CPU did not report them (0 / 0xFF).
    if (info.serialNumber != 0) {
      snprintf(dev.serial, sizeof(dev.serial), "%lu", (unsigned long)info.serialNumber);
    }
    if (info.state != 0xFF) {
      dev.state = info.state;
    }
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
  return ok;
}

// Return a module's isVulnerable string by slot, or "N/A" if not found.
static const char* moduleVulnerability(const DeviceModule* modules, uint8_t count, uint8_t slot) {
  for (uint8_t i = 0; i < count; i++) {
    if (modules[i].slot == slot) return modules[i].isVulnerable;
  }
  return "N/A";
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

  // Compute vulnerability status for the fresh modules (so firmware-change
  // emails can show it, and so it's available for the sync below).
  setModuleVulnerability(freshModules, freshCount);

  // Firmware change
  if (freshFirmware[0] != '\0' && dev.firmware[0] != '\0' &&
      strcmp(freshFirmware, dev.firmware) != 0) {
    char buf[128];
    snprintf(buf, sizeof(buf), "PLC firmware change: %d.%d.%d.%d %s -> %s",
             dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3], dev.firmware, freshFirmware);
    logger->safePrintln(buf);
    String cpuUrl = advisoryURL(advisorySearchTerm(0x0E, info.productName));
    logger->sendDeviceFirmwareChangeTrap(dev.ip, dev.mac, dev.productName,
                                         dev.firmware, freshFirmware,
                                         cpuUrl.c_str(),
                                         moduleVulnerability(freshModules, freshCount, 0));
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
    String url = advisoryURL(advisorySearchTerm(m.deviceType, m.productName));

    char buf[128];
    snprintf(buf, sizeof(buf), "PLC Ethernet module (slot %u) firmware change: %s -> %s",
             (unsigned)m.slot, prevFw, newFw);
    logger->safePrintln(buf);

    logger->sendEthernetModuleFirmwareChangeTrap(dev.ip, dev.mac, m.slot,
                                                 m.productName.c_str(), prevFw, newFw,
                                                 url.c_str(),
                                                 moduleVulnerability(freshModules, freshCount, m.slot));
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

  // Refresh vulnerability status on the persistent modules (handles the
  // no-change case; the change case already copied freshModules above).
  for (uint8_t i = 0; i < dev.moduleCount; i++) {
    strncpy(dev.modules[i].isVulnerable, freshModules[i].isVulnerable,
            sizeof(dev.modules[i].isVulnerable) - 1);
    dev.modules[i].isVulnerable[sizeof(dev.modules[i].isVulnerable) - 1] = '\0';
  }

  dev.lastStatusCheck = esp_timer_get_time();
}

// Set each module's isVulnerable field ("YES"/"NO"/"N/A") from the current DNS
// availability and a firmware vulnerability lookup.
void LanScanner::setModuleVulnerability(DeviceModule* modules, uint8_t count) {
  for (uint8_t i = 0; i < count; i++) {
    const char* result;
    if (isDNSAvailable) {
      result = isModuleVulnerable(modules[i].deviceType, String(modules[i].productName),
                                  modules[i].majorRevision,
                                  modules[i].minorRevision) ? "YES" : "NO";
    } else {
      result = "N/A";
    }
    strncpy(modules[i].isVulnerable, result, sizeof(modules[i].isVulnerable) - 1);
    modules[i].isVulnerable[sizeof(modules[i].isVulnerable) - 1] = '\0';
  }
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

