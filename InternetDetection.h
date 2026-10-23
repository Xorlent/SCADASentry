/*
 * InternetDetection.h
 * 
 * Internet access detection for SCADASentry.
 * Probes for a DHCP server on the local LAN, classifies a server that
 * advertises a gateway different from the configured gateway as rogue, and
 * verifies Internet reachability through the configured gateway. Reports
 * findings via SNMP traps through HoneypotLogging.
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#ifndef INTERNET_DETECTION_H
#define INTERNET_DETECTION_H

#include <Arduino.h>
#include <IPAddress.h>
#include "Config.h"
#include "HoneypotLogging.h"

// How Internet reachability was verified (internetDetectionMethod varbind enum).
enum InternetDetectionMethod {
  INTERNET_METHOD_NONE = 0,
  INTERNET_METHOD_TCP  = 1,   // TCP connect to a public anycast IP on port 443
  INTERNET_METHOD_DNS  = 2    // DNS query to a public resolver
};

class InternetDetection {
public:
  InternetDetection(HoneypotLogging* logger, IPAddress gateway);

  // Run one Internet detection cycle: probe for a DHCP server and classify a
  // server that advertises a gateway different from the configured gateway as
  // rogue. Internet reachability is verified only through the configured
  // gateway (TCP connect, falling back to a DNS query). Sends an
  // internetDetectedTrap when Internet access is detected.
  bool runDetection();

private:
  HoneypotLogging* logger;
  IPAddress gateway;

  // Send a DHCPDISCOVER and wait for a DHCPOFFER. On success, fills serverIp
  // with the DHCP server identifier (option 54) and gatewayIp with the router
  // option (option 3), and returns true.
  bool probeDhcp(IPAddress& serverIp, IPAddress& gatewayIp);

  // Open a TCP connection to ip:port and close it; true on success.
  bool tcpConnectTest(IPAddress ip, uint16_t port, uint32_t timeoutMs);

  // Resolve hostname via dnsServer and require a non-empty answer.
  bool dnsQueryTest(const char* hostname, IPAddress dnsServer, uint32_t timeoutMs);

  // Test Internet reachability through the current default route. On success,
  // fills method with the method that succeeded and returns true.
  bool testInternet(InternetDetectionMethod& method);
};

#endif // INTERNET_DETECTION_H
