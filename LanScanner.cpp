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

// Ping timeout per host (ms)
#define PING_TIMEOUT_MS 100
// TCP connect deadline for the 44818 probe (ms)
#define CONNECT_TIMEOUT_MS 100
// Session/message timeouts (ms)
#define SESSION_TIMEOUT_MS 1000
#define MESSAGE_TIMEOUT_MS 1000

// Advance an IPv4 address to the next host address
static bool nextHost(IPAddress &ip) {
  for (int i = 3; i >= 0; --i) {
    if (ip[i] < 255) { ++ip[i]; return true; }
    ip[i] = 0;
  }
  return false;
}

LanScanner::LanScanner(HoneypotLogging* logger, IPAddress localIP, IPAddress gateway, IPAddress subnetMask)
    : logger(logger), localIP(localIP), gateway(gateway), subnetMask(subnetMask) {
  deviceCount = 0;
  scanCount = 0;
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
  }
}

void LanScanner::runScan() {
  scanCount++;
  uint32_t scanStart = millis();
  bool doStatusCheck = (scanCount % LAN_STATUS_CHECK_MULTIPLIER == 0);

  if (DEBUG) {
    char buf[32];
    snprintf(buf, sizeof(buf), "LAN scan #%lu started", (unsigned long)scanCount);
    logger->safePrintln(buf);
  }

  // Sweep the LAN range
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
        dev.lastSeen = millis();
        dev.lastStatusCheck = 0;
        if (probePlc(ip, dev)) {
          dev.isPlc = true;
          dev.hasStatus = true;
          dev.lastStatusCheck = millis();
          logger->sendNewDeviceTrap(ip, dev.mac, true, dev.vendor, dev.productName,
                                    dev.firmware, dev.serial, dev.state, dev.mode);
        } else {
          logger->sendNewDeviceTrap(ip, dev.mac, false, 0, "", "", "", 0, 0);
        }
        addDevice(dev);
        {
          char buf[160];
          if (dev.isPlc) {
            snprintf(buf, sizeof(buf),
                     "New device: %d.%d.%d.%d (MAC %02X:%02X:%02X:%02X:%02X:%02X) - PLC %s fw %s",
                     dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3],
                     (unsigned)dev.mac[0], (unsigned)dev.mac[1], (unsigned)dev.mac[2],
                     (unsigned)dev.mac[3], (unsigned)dev.mac[4], (unsigned)dev.mac[5],
                     dev.productName, dev.firmware);
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
        devices[idx].lastSeen = millis();
        if (hasMac) {
          memcpy(devices[idx].mac, mac, 6);
          devices[idx].hasMac = true;
        }
      }
    }
    // Quiet time between ARP discovery requests (network-impact throttle)
    delay(LAN_SCAN_ARP_THROTTLE_MS);

    nextHost(ip);
  }

  // Check for disappeared devices
  for (int i = deviceCount - 1; i >= 0; i--) {
    if (devices[i].lastSeen < scanStart) {
      char buf[48];
      snprintf(buf, sizeof(buf), "Device disappeared: %d.%d.%d.%d",
               devices[i].ip[0], devices[i].ip[1], devices[i].ip[2], devices[i].ip[3]);
      logger->safePrintln(buf);
      logger->sendDeviceGoneTrap(devices[i].ip, devices[i].mac);
      logger->removeIPFromHoldoff(devices[i].ip);
      removeDevice(i);
    }
  }

  // Status check (every Nth scan)
  if (doStatusCheck) {
    for (int i = 0; i < deviceCount; i++) {
      if (devices[i].isPlc) {
        checkStatus(devices[i]);
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

// Query a single CIP Identity Object attribute (class 1, instance 1)
bool LanScanner::queryIdentityAttr(uint8_t attr, uint8_t* out, size_t* outLen) {
  uint8_t path[4];
  size_t pl = 0;
  pl += clx::appendClass(path + pl, 1);      // class = Identity (1)
  pl += clx::appendInstance(path + pl, 1);   // instance = 1
  uint8_t data[2];
  clx::appendAttribute(data, attr);

  clx::Status st = msg.send(tcp, session.handle(),
                            (uint8_t)clx::Service::GetAttributeSingle,
                            path, pl, data, sizeof(data), MESSAGE_TIMEOUT_MS);
  if (st != clx::Status::Ok && st != clx::Status::Pending) return false;

  uint32_t start = millis();
  while ((st = msg.poll()) == clx::Status::Pending) {
    if (millis() - start > MESSAGE_TIMEOUT_MS + 500) return false;
    delay(10);
  }
  if (st != clx::Status::Ok || msg.resultCode() != 0) return false;

  *outLen = msg.dataLength();
  if (*outLen > 0) memcpy(out, msg.data(), *outLen);
  return true;
}

// Query the run-switch mode via the symbolic tag ControllerInfo.Mode
bool LanScanner::queryMode(int32_t& mode) {
  clx::Status st = tag.read(msg, tcp, session.handle(), "ControllerInfo.Mode", 1, MESSAGE_TIMEOUT_MS);
  if (st != clx::Status::Ok && st != clx::Status::Pending) return false;

  uint32_t start = millis();
  while ((st = tag.poll(msg)) == clx::Status::Pending) {
    if (millis() - start > MESSAGE_TIMEOUT_MS + 500) return false;
    delay(10);
  }
  if (st != clx::Status::Ok || tag.resultCode() != 0) return false;

  mode = tag.getInt32(0);
  return true;
}

// Probe a host for a ControlLogix PLC: connect, query identity + mode, close.
// Returns true if the host is a ControlLogix device (identity query succeeded).
bool LanScanner::probePlc(IPAddress ip, DeviceEntry& dev) {
  // TCP connect to 44818
  tcp.connect(ip, 44818, CONNECT_TIMEOUT_MS);
  uint32_t start = millis();
  clx::Status st;
  while ((st = tcp.poll()) == clx::Status::Pending) {
    if (millis() - start > CONNECT_TIMEOUT_MS + 500) { tcp.close(); return false; }
    delay(10);
  }
  if (st != clx::Status::Ok) { tcp.close(); return false; }

  // Open EtherNet/IP session
  session.open(tcp, SESSION_TIMEOUT_MS);
  start = millis();
  while ((st = session.poll()) == clx::Status::Pending) {
    if (millis() - start > SESSION_TIMEOUT_MS + 500) { session.abort(); tcp.close(); return false; }
    delay(10);
  }
  if (st != clx::Status::Ok) { session.abort(); tcp.close(); return false; }

  uint8_t buf[64];
  size_t len;

  // vendor (2 bytes)
  dev.vendor = 0;
  if (queryIdentityAttr(clx::kIdentityVendorId, buf, &len) && len >= 2) {
    dev.vendor = (uint16_t)(buf[0] | (buf[1] << 8));
  }

  // product name (string)
  dev.productName[0] = '\0';
  if (queryIdentityAttr(clx::kIdentityProductName, buf, &len) && len > 0) {
    size_t n = (len < 63) ? len : 63;
    memcpy(dev.productName, buf, n);
    dev.productName[n] = '\0';
  }

  // revision (firmware, 2 bytes: major.minor)
  dev.firmware[0] = '\0';
  if (queryIdentityAttr(clx::kIdentityRevision, buf, &len) && len >= 2) {
    snprintf(dev.firmware, sizeof(dev.firmware), "%u.%u", buf[0], buf[1]);
  }

  // serial number (4 bytes)
  dev.serial[0] = '\0';
  if (queryIdentityAttr(clx::kIdentitySerialNumber, buf, &len) && len >= 4) {
    uint32_t serial = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
                      ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    snprintf(dev.serial, sizeof(dev.serial), "%lu", (unsigned long)serial);
  }

  // state (1 byte)
  dev.state = 0;
  if (queryIdentityAttr(clx::kIdentityState, buf, &len) && len >= 1) {
    dev.state = buf[0];
  }

  // mode (run switch, via symbolic tag; optional for non-Logix devices)
  dev.mode = -1;
  queryMode(dev.mode);

  // Close session and connection
  session.close();
  tcp.close();
  return true;
}

// Re-query a PLC's firmware and mode, emitting traps on change
void LanScanner::checkStatus(DeviceEntry& dev) {
  DeviceEntry fresh;
  fresh.ip = dev.ip;
  memcpy(fresh.mac, dev.mac, 6);
  fresh.hasMac = dev.hasMac;
  fresh.isPlc = false;
  fresh.hasStatus = false;

  if (!probePlc(dev.ip, fresh)) {
    return;  // unreachable or query failed
  }

  // Firmware change
  if (fresh.firmware[0] != '\0' && dev.firmware[0] != '\0' &&
      strcmp(fresh.firmware, dev.firmware) != 0) {
    char buf[128];
    snprintf(buf, sizeof(buf), "PLC firmware change: %d.%d.%d.%d %s -> %s",
             dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3], dev.firmware, fresh.firmware);
    logger->safePrintln(buf);
    logger->sendDeviceFirmwareChangeTrap(dev.ip, dev.mac, dev.firmware, fresh.firmware, 2 /* unknown */);
    strncpy(dev.prevFirmware, dev.firmware, sizeof(dev.prevFirmware) - 1);
    dev.prevFirmware[sizeof(dev.prevFirmware) - 1] = '\0';
    strncpy(dev.firmware, fresh.firmware, sizeof(dev.firmware) - 1);
    dev.firmware[sizeof(dev.firmware) - 1] = '\0';
  }

  // Run-switch mode change
  if (fresh.mode >= 0 && dev.mode >= 0 && fresh.mode != dev.mode) {
    char buf[128];
    snprintf(buf, sizeof(buf), "PLC mode change: %d.%d.%d.%d %ld -> %ld",
             dev.ip[0], dev.ip[1], dev.ip[2], dev.ip[3], (long)dev.mode, (long)fresh.mode);
    logger->safePrintln(buf);
    logger->sendDeviceModeChangeTrap(dev.ip, dev.mac, dev.mode, fresh.mode);
    dev.prevMode = dev.mode;
    dev.mode = fresh.mode;
  }

  dev.lastStatusCheck = millis();
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
