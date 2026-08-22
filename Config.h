/*
 * Config.h
 * 
 * Configuration settings for SCADASentry
 * Edit the values in this file to customize your honeypot deployment
 * 
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <IPAddress.h>

// Port and service name structure for TCP/UDP monitoring
struct HoneypotPort {
  uint16_t port;
  const char* service;
};

// ICMP type and name structure for monitoring
struct HoneypotICMPType {
  uint8_t type;
  const char* name;
};

////////------------------------------------------- CONFIGURATION SETTINGS AREA --------------------------------------------////////

// Device Identification
const uint8_t hostName[] = "SCADASentry"; // Set hostname, no spaces, no domain name per RFC 3164

// Debug mode - enables verbose serial output showing events and SNMP trap messages
const bool DEBUG = true;

////////// Network Configuration //////////

    // Ethernet configuration:
    const IPAddress ip(192, 168, 1, 50);        // Set device IP address.
    const IPAddress gateway(192, 168, 1, 1);    // Set default gateway IP address.
    const IPAddress subnet(255, 255, 255, 0);    // Set network subnet mask.
    const IPAddress dns1(9, 9, 9, 9);            // Primary DNS
    const IPAddress dns2(149, 112, 112, 112);    // Secondary DNS

    // Logging method configuration:
    // Choose logging method: true = SMTP relay, false = SNMP trap
    const bool USE_SMTP = false;

    // SNMP trap configuration (used when USE_SMTP = false):
    const IPAddress snmpTrapSvr(192, 168, 1, 2); // Set SNMP trap receiver (NMS) IP address.
    const uint16_t snmpTrapPort = 162;      // Set SNMP trap receiver UDP port.
    const char* const snmpCommunity = "public"; // SNMPv2c community string.

    // SMTP relay configuration (used when USE_SMTP = true):
    const IPAddress smtpServer(192, 168, 1, 25); // SMTP relay server IP address
    const uint16_t smtpPort = 25;          // SMTP relay port (usually 25)
    const char* const smtpFromAddr = "honeypot@example.com";  // From email address
    const char* const smtpToAddr = "security@example.com";    // To email address

    // NTP server configuration:
    // Select your NTP server info by configuring and uncommenting ONLY ONE line below:
    const IPAddress ntpSvr(192, 168, 1, 2);    // Set internal NTP server IP address.
    //const char* const ntpSvr = "pool.ntp.org";   // Or set a NTP DNS server hostname.

////////// Monitoring Configuration //////////

////////// TCP Port Monitoring //////////

    // Choose your honeypot personality by uncommenting ONE of the following arrays:
    // Maximum service name: 64 characters

    // Common enterprise TCP ports:
/*
    const HoneypotPort honeypotTCPPorts[] = {
        {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {80, "http"}, 
        {135, "epmap"}, {139, "netbios-ssn"}, {389, "ldap"}, {443, "https"}, 
        {445, "microsoft-ds"}, {636, "ldaps"}, {1433, "ms-sql-s"}, {1521, "oracle"}, 
        {3268, "msft-gc"}, {3306, "mysql"}, {3389, "rdp"}, {5432, "postgres"}, 
        {5555, "personal-agent"}, {5900, "vnc"}, {5985, "winrm-http"}, {5986, "winrm-https"}, 
        {8080, "http-alt"}, {8443, "https-alt"}
    }; 
*/
    // Common OT/SCADA TCP ports:
    const HoneypotPort honeypotTCPPorts[] = {
        {22, "ssh"}, {23, "telnet"}, {80, "http"}, {102, "siemens-s7"}, 
        {502, "modbus"}, {2222, "rockwell-csp2"}, {3389, "rdp"}, {4840, "opcua"}, {20000, "dnp3"}, 
        {44818, "rockwell-encap"}, {47808, "bacnet"}, {18245, "ge-srtp"}, {18246, "ge-srtp"}, 
        {34962, "profinet"}, {34964, "profinet"}, {34980, "profinet"}, {28784, "automationdirect"}
    };

    // Custom TCP ports (edit as needed):
    //const HoneypotPort honeypotTCPPorts[] = {
    //    {22, "ssh"}, {80, "http"}, {443, "https"}, {3389, "rdp"}, {8080, "http-alt"}
    //};

////////// UDP Port Monitoring //////////

    // Enable UDP monitoring
    const bool MONITOR_UDP = true;

    // UDP ports to monitor
    // Choose your profile by uncommenting ONE of the following arrays:

    // Common enterprise UDP ports:
/*
    const HoneypotPort honeypotUDPPorts[] = {
        {53, "dns"}, {69, "tftp"}, {88, "kerberos"}, {123, "ntp"}, 
        {138, "netbios-dgm"}, {161, "snmp"}, {500, "isakmp"}, {1900, "ssdp"}
    };
*/
    // Common OT/SCADA UDP ports:
    const HoneypotPort honeypotUDPPorts[] = {
        {502, "modbus"}, {2222, "rockwell-browse"}, {4840, "opcua"}, {20000, "dnp3"}, {44818, "rslogix-browse"}
    };

    // Custom UDP ports (edit as needed):
    //const HoneypotPort honeypotUDPPorts[] = {
    //    {53, "dns"}, {123, "ntp"}, {161, "snmp"}
    //};

////////// ICMP Monitoring //////////

    // Enable ICMP monitoring
    // Note: Enabling ICMP prevents device from responding to ICMP packets
    const bool MONITOR_ICMP = false;

    // ICMP types to monitor
    // Echo request types (8 = Echo Request, 42 = Extended Echo Request)
    const HoneypotICMPType honeypotICMPTypes[] = {
        {8, "echo-request"}, 
        {42, "extended-echo-request"}
    };

////////// Holdoff Configuration //////////

    // Prevents flooding the trap receiver with repeated events from the same IP

    // Maximum unique IPs to track per protocol
    #define MAX_TRACKED_IPS 50

    // Holdoff time in seconds for each protocol (0 = disabled)
    const uint16_t TCP_HOLDOFF_SECONDS = 3600;
    const uint16_t UDP_HOLDOFF_SECONDS = 3600;
    const uint16_t ICMP_HOLDOFF_SECONDS = 3600;

////////// LAN Scan Configuration //////////

    // Scans the local LAN for devices and reports them via SNMP traps.
    // See README.md "SNMP Trap Reference" for the trap OIDs.

    // Maximum number of LAN devices to track
    #define MAX_DEVICES 252

    // Interval between LAN scans, in seconds
    const uint32_t LAN_SCAN_INTERVAL_SECONDS = 240;

    // Run-switch/firmware status is re-queried every N scans
    // (LAN_SCAN_INTERVAL_SECONDS * LAN_STATUS_CHECK_MULTIPLIER seconds)
    const uint16_t LAN_STATUS_CHECK_MULTIPLIER = 15;

    // Quiet time (ms) between each ARP discovery request during a scan.
    // Throttles the scan's impact on the network segment; increase to reduce
    // load, decrease for faster scans. 0 disables the throttle.
    const uint16_t LAN_SCAN_ARP_THROTTLE_MS = 100;

    // IP addresses to exclude from the LAN scan (in addition to this device's
    // network address, broadcast address, and default gateway, which are
    // always skipped).
    const IPAddress excludedHosts[] = {
        // IPAddress(192, 168, 1, 10),  // example: exclude a specific host
    };

////////--------------------------------------- END OF CONFIGURATION SETTINGS ---------------------------------------////////

////////// Calculated Array Sizes (Do Not Edit) //////////

    // Calculate array sizes for validation and iteration
    const uint16_t honeypotNumPorts = sizeof(honeypotTCPPorts)/sizeof(honeypotTCPPorts[0]);
    const uint16_t honeypotNumUDPPorts = sizeof(honeypotUDPPorts)/sizeof(honeypotUDPPorts[0]);
    const uint16_t honeypotNumICMPTypes = sizeof(honeypotICMPTypes)/sizeof(honeypotICMPTypes[0]);
    const uint16_t excludedHostsCount = sizeof(excludedHosts)/sizeof(excludedHosts[0]);

#endif // CONFIG_H
