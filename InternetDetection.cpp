/*
 * InternetDetection.cpp
 * 
 * Internet access detection for SCADASentry.
 * Probes for a DHCP server on the local LAN (which should not exist on a
 * PLC LAN) and verifies Internet reachability through the gateway, then
 * reports the finding via an SNMP trap through HoneypotLogging.
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#include "InternetDetection.h"
#include <ETH.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <esp_system.h>
#include <lwip/netif.h>
#include <lwip/ip4_addr.h>
#include <lwip/ip_addr.h>

// DHCP / BOOTP constants
#define DHCP_CLIENT_PORT        68
#define DHCP_SERVER_PORT        67
#define DHCP_MAGIC_COOKIE_OFF   236
#define DHCP_OPTIONS_OFF        240
#define DHCP_OPT_MSG_TYPE       53
#define DHCP_OPT_SERVER_ID      54
#define DHCP_OPT_ROUTER         3
#define DHCP_OPT_END            255
#define DHCP_MSG_DISCOVER       1
#define DHCP_MSG_OFFER          2

// DNS constants
#define DNS_PORT                53
#define DNS_QTYPE_A             1
#define DNS_QCLASS_IN           1

// Human-readable name for an Internet detection method.
static const char* methodName(InternetDetectionMethod m) {
  switch (m) {
    case INTERNET_METHOD_TCP: return "TCP connect";
    case INTERNET_METHOD_DNS: return "DNS query";
    default:                  return "none";
  }
}

InternetDetection::InternetDetection(HoneypotLogging* logger, IPAddress gateway)
    : logger(logger), gateway(gateway) {
}

// Send a DHCPDISCOVER and wait for a DHCPOFFER. On success, fills serverIp
// with the DHCP server identifier (option 54) and gatewayIp with the router
// option (option 3), and returns true.
//
// NOTE: Only a DHCPDISCOVER (message type 1) is sent; no DHCPREQUEST is ever
// issued, so the DORA handshake is never completed and the device never
// obtains or reserves an IP address from the DHCP server. The device keeps
// its statically-configured IP address.
bool InternetDetection::probeDhcp(IPAddress& serverIp, IPAddress& gatewayIp) {
  WiFiUDP udp;
  if (!udp.begin(DHCP_CLIENT_PORT)) {
    if (DEBUG) logger->safePrintln("[DEBUG] Internet: failed to bind DHCP client port");
    return false;
  }

  uint32_t xid = (uint32_t)esp_random();
  uint8_t xid0 = (xid >> 24) & 0xFF;
  uint8_t xid1 = (xid >> 16) & 0xFF;
  uint8_t xid2 = (xid >> 8) & 0xFF;
  uint8_t xid3 = xid & 0xFF;

  // Build a DHCPDISCOVER packet.
  uint8_t packet[300];
  memset(packet, 0, sizeof(packet));

  packet[0] = 1;                       // op = BOOTREQUEST
  packet[1] = 1;                       // htype = Ethernet
  packet[2] = 6;                       // hlen = 6
  packet[3] = 0;                       // hops
  packet[4] = xid0;                    // transaction ID
  packet[5] = xid1;
  packet[6] = xid2;
  packet[7] = xid3;
  packet[10] = 0x80;                   // flags = broadcast (0x8000)

  uint8_t mac[6];
  ETH.macAddress(mac);
  memcpy(packet + 28, mac, 6);         // chaddr (client hardware address)

  packet[DHCP_MAGIC_COOKIE_OFF]     = 0x63;  // magic cookie 0x63825363
  packet[DHCP_MAGIC_COOKIE_OFF + 1] = 0x82;
  packet[DHCP_MAGIC_COOKIE_OFF + 2] = 0x53;
  packet[DHCP_MAGIC_COOKIE_OFF + 3] = 0x63;

  // Option 53: message type = DISCOVER (not REQUEST). This only solicits a
  // DHCPOFFER; we never send DHCPREQUEST, so no lease is taken or reserved.
  packet[DHCP_OPTIONS_OFF]     = DHCP_OPT_MSG_TYPE;
  packet[DHCP_OPTIONS_OFF + 1] = 1;
  packet[DHCP_OPTIONS_OFF + 2] = DHCP_MSG_DISCOVER;
  // Option 55: parameter request list (subnet mask, router, DNS, domain name)
  packet[DHCP_OPTIONS_OFF + 3] = 55;
  packet[DHCP_OPTIONS_OFF + 4] = 4;
  packet[DHCP_OPTIONS_OFF + 5] = 1;
  packet[DHCP_OPTIONS_OFF + 6] = 3;
  packet[DHCP_OPTIONS_OFF + 7] = 6;
  packet[DHCP_OPTIONS_OFF + 8] = 15;
  // Option 255: end
  packet[DHCP_OPTIONS_OFF + 9] = DHCP_OPT_END;

  uint16_t packetLen = DHCP_OPTIONS_OFF + 10;

  udp.beginPacket(IPAddress(255, 255, 255, 255), DHCP_SERVER_PORT);
  udp.write(packet, packetLen);
  udp.endPacket();

  // Wait for a DHCPOFFER.
  uint32_t start = millis();
  while (millis() - start < INTERNET_DHCP_TIMEOUT_MS) {
    int size = udp.parsePacket();
    if (size > 0) {
      uint8_t resp[300];
      int n = udp.read(resp, sizeof(resp));
      if (n >= DHCP_OPTIONS_OFF + 2 &&
          resp[0] == DHCP_MSG_OFFER &&
          resp[4] == xid0 && resp[5] == xid1 && resp[6] == xid2 && resp[7] == xid3 &&
          resp[DHCP_MAGIC_COOKIE_OFF] == 0x63 &&
          resp[DHCP_MAGIC_COOKIE_OFF + 1] == 0x82 &&
          resp[DHCP_MAGIC_COOKIE_OFF + 2] == 0x53 &&
          resp[DHCP_MAGIC_COOKIE_OFF + 3] == 0x63) {
        // Parse options for the server identifier (54) and router (3).
        bool foundServer = false;
        int i = DHCP_OPTIONS_OFF;
        while (i + 1 < n) {
          uint8_t opt = resp[i];
          if (opt == DHCP_OPT_END) break;
          if (opt == 0) { i++; continue; }   // padding
          uint8_t len = resp[i + 1];
          if (i + 2 + len > n) break;
          if (opt == DHCP_OPT_SERVER_ID && len == 4) {
            serverIp = IPAddress(resp[i + 2], resp[i + 3], resp[i + 4], resp[i + 5]);
            foundServer = true;
          } else if (opt == DHCP_OPT_ROUTER && len >= 4) {
            // Router option: a list of 4-byte IPs; take the first.
            gatewayIp = IPAddress(resp[i + 2], resp[i + 3], resp[i + 4], resp[i + 5]);
          }
          i += 2 + len;
        }
        if (foundServer) {
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

// Open a TCP connection to ip:port and close it; true on success.
bool InternetDetection::tcpConnectTest(IPAddress ip, uint16_t port, uint32_t timeoutMs) {
  WiFiClient client;
  if (client.connect(ip, port, (int32_t)timeoutMs)) {
    client.stop();
    return true;
  }
  return false;
}

// Resolve hostname via dnsServer and require a non-empty answer.
bool InternetDetection::dnsQueryTest(const char* hostname, IPAddress dnsServer, uint32_t timeoutMs) {
  WiFiUDP udp;
  if (!udp.begin(0)) {   // ephemeral source port
    return false;
  }

  // Build a DNS A-record query.
  uint8_t query[64];
  memset(query, 0, sizeof(query));
  uint16_t id = (uint16_t)(esp_random() & 0xFFFF);
  query[0] = (id >> 8) & 0xFF;
  query[1] = id & 0xFF;
  query[2] = 0x01;   // flags: RD (recursion desired)
  query[3] = 0x00;
  query[4] = 0x00; query[5] = 0x01;   // QDCOUNT = 1

  // QNAME: encode the hostname as length-prefixed labels.
  int pos = 12;
  const char* p = hostname;
  while (*p) {
    const char* dot = strchr(p, '.');
    int len = dot ? (int)(dot - p) : (int)strlen(p);
    if (pos + 1 + len >= (int)sizeof(query)) { udp.stop(); return false; }
    query[pos++] = (uint8_t)len;
    memcpy(query + pos, p, len);
    pos += len;
    if (dot) p = dot + 1; else break;
  }
  query[pos++] = 0;                              // terminating zero-length label
  query[pos++] = 0x00; query[pos++] = DNS_QTYPE_A;    // QTYPE = A
  query[pos++] = 0x00; query[pos++] = DNS_QCLASS_IN;  // QCLASS = IN

  udp.beginPacket(dnsServer, DNS_PORT);
  udp.write(query, pos);
  udp.endPacket();

  // Wait for a valid response.
  uint32_t start = millis();
  while (millis() - start < timeoutMs) {
    int size = udp.parsePacket();
    if (size >= 12) {
      uint8_t resp[512];
      int n = udp.read(resp, sizeof(resp));
      if (n >= 12 && resp[0] == query[0] && resp[1] == query[1]) {
        uint16_t flags = ((uint16_t)resp[2] << 8) | resp[3];
        uint16_t ancount = ((uint16_t)resp[6] << 8) | resp[7];
        // QR bit set (response), RCODE == 0 (no error), and >= 1 answer.
        if ((flags & 0x8000) && ((flags & 0x000F) == 0) && ancount > 0) {
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

// Test Internet reachability through the current default route. On success,
// fills method with the method that succeeded and returns true.
bool InternetDetection::testInternet(InternetDetectionMethod& method) {
  bool accessible = false;
  method = INTERNET_METHOD_NONE;

  for (uint16_t i = 0; i < internetTcpProbeHostCount && !accessible; i++) {
    if (tcpConnectTest(internetTcpProbeHosts[i], 443, INTERNET_CONNECT_TIMEOUT_MS)) {
      accessible = true;
      method = INTERNET_METHOD_TCP;
    }
  }

  if (!accessible &&
      dnsQueryTest(internetDnsProbeHost, internetDnsServer, INTERNET_CONNECT_TIMEOUT_MS)) {
    accessible = true;
    method = INTERNET_METHOD_DNS;
  }

  return accessible;
}

// Test Internet reachability through a specific gateway by temporarily
// changing the default route, then restoring it.
bool InternetDetection::testInternetThroughGateway(IPAddress gw, InternetDetectionMethod& method) {
  if (netif_default == NULL) {
    return false;
  }

  // Hold the gateway-change lock so concurrent SNMP/SMTP sends defer until the
  // default gateway is restored below.
  logger->beginGatewayChange();

  ip_addr_t savedGw = netif_default->gw;
  ip4_addr_t testGw;
  IP4_ADDR(&testGw, gw[0], gw[1], gw[2], gw[3]);
  netif_set_gw(netif_default, &testGw);

  bool accessible = testInternet(method);

  netif_set_gw(netif_default, ip_2_ip4(&savedGw));
  logger->endGatewayChange();
  return accessible;
}

// Run one Internet detection cycle and report via SNMP trap when detected.
bool InternetDetection::runDetection() {
  // 1. Probe for a DHCP server and its advertised gateway.
  IPAddress dhcpServer;
  IPAddress dhcpGateway;
  bool dhcpDetected = probeDhcp(dhcpServer, dhcpGateway);

  if (DEBUG) {
    if (dhcpDetected) {
      char buf[96];
      snprintf(buf, sizeof(buf), "[DEBUG] Internet: DHCP server %d.%d.%d.%d gateway %d.%d.%d.%d",
               dhcpServer[0], dhcpServer[1], dhcpServer[2], dhcpServer[3],
               dhcpGateway[0], dhcpGateway[1], dhcpGateway[2], dhcpGateway[3]);
      logger->safePrintln(buf);
    } else {
      logger->safePrintln("[DEBUG] Internet: no DHCP server detected");
    }
  }

  // 2. Test Internet reachability. Prefer the DHCP-advertised gateway (if it
  //    differs from the configured gateway), then fall back to the configured
  //    gateway.
  bool internetAccessible = false;
  InternetDetectionMethod method = INTERNET_METHOD_NONE;
  IPAddress testedGateway = gateway;

  if (dhcpDetected && dhcpGateway != IPAddress(0, 0, 0, 0) && dhcpGateway != gateway) {
    if (DEBUG) {
      char buf[96];
      snprintf(buf, sizeof(buf), "[DEBUG] Internet: testing via DHCP gateway %d.%d.%d.%d",
               dhcpGateway[0], dhcpGateway[1], dhcpGateway[2], dhcpGateway[3]);
      logger->safePrintln(buf);
    }
    if (testInternetThroughGateway(dhcpGateway, method)) {
      internetAccessible = true;
      testedGateway = dhcpGateway;
    } else if (DEBUG) {
      char buf[96];
      snprintf(buf, sizeof(buf), "[DEBUG] Internet: DHCP gateway %d.%d.%d.%d not accessible",
               dhcpGateway[0], dhcpGateway[1], dhcpGateway[2], dhcpGateway[3]);
      logger->safePrintln(buf);
    }
  }

  if (!internetAccessible) {
    if (DEBUG) {
      char buf[96];
      snprintf(buf, sizeof(buf), "[DEBUG] Internet: testing via configured gateway %d.%d.%d.%d",
               gateway[0], gateway[1], gateway[2], gateway[3]);
      logger->safePrintln(buf);
    }
    if (testInternet(method)) {
      internetAccessible = true;
      testedGateway = gateway;
    } else if (DEBUG) {
      char buf[96];
      snprintf(buf, sizeof(buf), "[DEBUG] Internet: configured gateway %d.%d.%d.%d not accessible",
               gateway[0], gateway[1], gateway[2], gateway[3]);
      logger->safePrintln(buf);
    }
  }

  if (DEBUG) {
    if (internetAccessible) {
      char buf[128];
      snprintf(buf, sizeof(buf), "[DEBUG] Internet: Internet accessible via gateway %d.%d.%d.%d (%s)",
               testedGateway[0], testedGateway[1], testedGateway[2], testedGateway[3], methodName(method));
      logger->safePrintln(buf);
    } else {
      logger->safePrintln("[DEBUG] Internet: Internet NOT accessible (all methods failed)");
    }
  }

  if (!internetAccessible) {
    return false;
  }

  // 3. Internet access detected. Report the gateway that provided it and the
  //    DHCP server (0.0.0.0 if none was found).
  IPAddress noDhcp(0, 0, 0, 0);
  logger->sendInternetDetectedTrap(testedGateway, dhcpDetected ? dhcpServer : noDhcp,
                                   internetAccessible, (int32_t)method);
  return true;
}
