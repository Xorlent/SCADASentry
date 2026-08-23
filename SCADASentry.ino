/*
 * SCADASentry.ino
 * 
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 * 
 * Raw Socket Implementation - Now monitors unlimited ports and ICMP types
 * Designed for M5Stack Unit-PoE-P4 or other device with sufficient resources
 * 
 * CONFIGURATION: All user-configurable settings are in Config.h
 * Edit Config.h to customize your honeypot deployment.
 */

#include "Config.h"

////////--------------------------------------- DO NOT EDIT ANYTHING BELOW THIS LINE ---------------------------------------////////

#include <ETH.h>
#include <WiFiUdp.h>
#include <NTP.h>
#include <lwip/ip.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/icmp.h>
#include <lwip/raw.h>
#include <lwip/prot/tcp.h>
#include "HoneypotLogging.h"
#include "LanScanner.h"
#include "InternetDetection.h"
#include "ConfigValidation.h"

// Define TCP structures and flags if not already available
#ifndef TCPH_FLAGS
#define TCPH_FLAGS(phdr) (lwip_ntohs((phdr)->_hdrlen_rsvd_flags) & 0xFF)
#endif

#ifndef TCP_SYN
#define TCP_SYN   0x02U
#endif

#ifndef TCP_ACK
#define TCP_ACK   0x10U
#endif

#define ETH_ADDR        1
#define ETH_POWER_PIN   51
#define ETH_TYPE        ETH_PHY_TLK110
#define ETH_PHY_MDC     31
#define ETH_PHY_MDIO    52
#define ETH_CLK_MODE    EMAC_CLK_EXT_IN

// Reset button (GPIO 45, active-high: grounded when idle, 3.3V when pressed)
#define RESET_BUTTON_PIN            45
#define RESET_BUTTON_DEBOUNCE_MS    50
#define RESET_BUTTON_HOLD_MS        1000   // button must be held this long to reset

// Reset button debounce state
static int resetButtonState = LOW;          // stable (debounced) state
static int resetButtonLastReading = LOW;    // last raw reading
static unsigned long resetButtonLastDebounce = 0;
static unsigned long resetButtonPressedAt = 0;   // millis() when the button was first pressed
static bool resetButtonTriggered = false;         // true once the reset has fired for this press
static bool resetButtonArmed = false;             // false until the pin settles to idle after boot

////////---------------------------------------        Create runtime objects        ---------------------------------------////////

// Compile-time array size validation
static_assert(honeypotNumPorts <= 65535, "TCP port array exceeds maximum size");
static_assert(honeypotNumUDPPorts <= 65535, "UDP port array exceeds maximum size");
static_assert(honeypotNumICMPTypes <= 255, "ICMP type array exceeds maximum size");

// Port bitmaps for O(1) lookups (65536 ports = 8192 bytes each)
// Bit N set = port N is monitored
uint8_t tcpPortBitmap[8192];
uint8_t udpPortBitmap[8192];

// Set bit in bitmap (mark port as monitored)
inline void setBitInBitmap(uint8_t* bitmap, uint16_t port) {
  bitmap[port >> 3] |= (1 << (port & 0x07));
}

// Check if bit set in bitmap (is port monitored?)
inline bool isBitSetInBitmap(const uint8_t* bitmap, uint16_t port) {
  return (bitmap[port >> 3] & (1 << (port & 0x07))) != 0;
}

// SNMP trap and NTP clients
WiFiUDP snmpUdp;
NTP ntp(snmpUdp);

// Logging system
HoneypotLogging logger(hostName, ip, snmpTrapSvr, snmpTrapPort, snmpCommunity, DEBUG, 
                       TCP_HOLDOFF_SECONDS, UDP_HOLDOFF_SECONDS, ICMP_HOLDOFF_SECONDS,
                       &snmpUdp, &ntp,
                       USE_SMTP, smtpServer, smtpPort, smtpFromAddr, smtpToAddr);

// LAN scanner
LanScanner scanner(&logger, ip, gateway, subnet);
TaskHandle_t scannerTaskHandle = NULL;

// Internet access detection
InternetDetection internetDetector(&logger, gateway);
TaskHandle_t internetDetectionTaskHandle = NULL;

// LAN scanner task: periodically scans the local subnet for devices
void scannerTask(void* parameter) {
  // Wait briefly after boot for NTP sync and network settling
  vTaskDelay(5000 / portTICK_PERIOD_MS);
  while (1) {
    scanner.runScan();
    // Wait for the scan interval, or wake immediately on a reset notification.
    ulTaskNotifyTake(pdTRUE, (LAN_SCAN_INTERVAL_SECONDS * 1000) / portTICK_PERIOD_MS);
  }
}

// Internet detection task: periodically probes for a DHCP server and verifies
// Internet reachability to detect Internet access.
void internetDetectionTask(void* parameter) {
  // Wait after boot for NTP sync and network settling.
  vTaskDelay(10000 / portTICK_PERIOD_MS);
  while (1) {
    internetDetector.runDetection();
    vTaskDelay((INTERNET_DETECTION_INTERVAL_SECONDS * 1000) / portTICK_PERIOD_MS);
  }
}

// Raw sockets for packet capture (one per protocol)
struct raw_pcb *tcp_raw_socket;
struct raw_pcb *udp_raw_socket;
struct raw_pcb *icmp_raw_socket;

// NTP update tracking
unsigned long lastNTP = 0;

// Ethernet link state tracking (for linkUp notifications)
bool linkWasUp = false;

// Static string constants for suspicious traffic logging
static const char* const SUSPICIOUS_TCP_FRAGMENT = "TCP-fragment";
static const char* const SUSPICIOUS_UDP_FRAGMENT = "UDP-fragment";
static const char* const SUSPICIOUS_ICMP_FRAGMENT = "ICMP-fragment";
static const char* const SUSPICIOUS_UNKNOWN_FRAGMENT = "unknown-fragment";
static const char* const SUSPICIOUS_TCP_IP_OPTIONS = "TCP-ip-options";
static const char* const SUSPICIOUS_UDP_IP_OPTIONS = "UDP-ip-options";
static const char* const SUSPICIOUS_ICMP_IP_OPTIONS = "ICMP-ip-options";
static const char* const SUSPICIOUS_UNKNOWN_IP_OPTIONS = "unknown-ip-options";

// EtherNet/IP (Rockwell Automation) browse filtering
// On these UDP ports, only report ListIdentity (browse) traffic; ignore implicit I/O.
#define ENIP_LIST_IDENTITY_CMD 0x0063  // EtherNet/IP encapsulation command for ListIdentity (browse)
#define ENIP_PORT_44818 44818          // EtherNet/IP I/O + browse port
#define ENIP_PORT_2222 2222            // Legacy EtherNet/IP port (1756-ENET era)

////////---------------------------------------     End create runtime objects     ---------------------------------------////////

// Check if TCP port is monitored (O(1) bitmap lookup)
bool isHoneypotTCPPort(uint16_t port) {
  return isBitSetInBitmap(tcpPortBitmap, port);
}

// Get service name for TCP port
const char* getTCPServiceName(uint16_t port) {
  for(int i = 0; i < honeypotNumPorts; i++) {
    if(honeypotTCPPorts[i].port == port) {
      return (honeypotTCPPorts[i].service != NULL) ? honeypotTCPPorts[i].service : "unknown";
    }
  }
  return "unknown";
}

// Check if UDP port is monitored (O(1) bitmap lookup)
bool isHoneypotUDPPort(uint16_t port) {
  if (!MONITOR_UDP) return false;
  return isBitSetInBitmap(udpPortBitmap, port);
}

// Get service name for UDP port
const char* getUDPServiceName(uint16_t port) {
  if (!MONITOR_UDP) return "unknown";
  for(int i = 0; i < honeypotNumUDPPorts; i++) {
    if(honeypotUDPPorts[i].port == port) {
      return (honeypotUDPPorts[i].service != NULL) ? honeypotUDPPorts[i].service : "unknown";
    }
  }
  return "unknown";
}

// Check if ICMP type is monitored
bool isHoneypotICMPType(uint8_t type) {
  if (!MONITOR_ICMP) return false;
  for(int i = 0; i < honeypotNumICMPTypes; i++) {
    if(honeypotICMPTypes[i].type == type) {
      return true;
    }
  }
  return false;
}

// Get name for ICMP type
const char* getICMPTypeName(uint8_t type) {
  if (!MONITOR_ICMP) return "unknown";
  for(int i = 0; i < honeypotNumICMPTypes; i++) {
    if(honeypotICMPTypes[i].type == type) {
      return (honeypotICMPTypes[i].name != NULL) ? honeypotICMPTypes[i].name : "unknown";
    }
  }
  return "unknown";
}

// Get fragment description string for protocol
static const char* getFragmentDescription(u8_t protocol) {
  switch(protocol) {
    case IP_PROTO_TCP:  return SUSPICIOUS_TCP_FRAGMENT;
    case IP_PROTO_UDP:  return SUSPICIOUS_UDP_FRAGMENT;
    case IP_PROTO_ICMP: return SUSPICIOUS_ICMP_FRAGMENT;
    default:            return SUSPICIOUS_UNKNOWN_FRAGMENT;
  }
}

// Get IP options description string for protocol
static const char* getIPOptionsDescription(u8_t protocol) {
  switch(protocol) {
    case IP_PROTO_TCP:  return SUSPICIOUS_TCP_IP_OPTIONS;
    case IP_PROTO_UDP:  return SUSPICIOUS_UDP_IP_OPTIONS;
    case IP_PROTO_ICMP: return SUSPICIOUS_ICMP_IP_OPTIONS;
    default:            return SUSPICIOUS_UNKNOWN_IP_OPTIONS;
  }
}

// Update NTP if 10 minutes elapsed
void updateNTPIfNeeded() {
  unsigned long currentMillis = millis();
  if(currentMillis - lastNTP >= 600000) {
    if(ntp.update()) {
      lastNTP = currentMillis;
    }
  }
}

// Validate IP header, return IP header length or 0 if invalid
static u8_t validateIPHeader(struct pbuf *p, struct ip_hdr **iphdr_out) {
  // Validate packet size
  if (p == NULL || p->tot_len < sizeof(struct ip_hdr)) {
    return 0;
  }
  
  // Ensure header in first pbuf (prevents buffer overrun)
  if (p->len < sizeof(struct ip_hdr)) {
    return 0;
  }
  
  struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
  
  // Validate header length (20-60 bytes)
  u8_t ip_header_len = IPH_HL(iphdr) * 4;
  if (ip_header_len < 20 || ip_header_len > 60 || p->tot_len < ip_header_len) {
    return 0;
  }
  
  // Ensure entire header (with options) in first pbuf
  if (p->len < ip_header_len) {
    return 0;
  }
  
  *iphdr_out = iphdr;
  return ip_header_len;
}

// Raw packet receive callback (all protocols)
static u8_t raw_recv_callback(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
  // Validate packet
  struct ip_hdr *iphdr;
  u8_t ip_header_len = validateIPHeader(p, &iphdr);
  
  if (ip_header_len == 0) {
    if (p != NULL) pbuf_free(p);
    return 1;
  }
  
  // Detect IP fragmentation (suspicious)
  // Offset in 8-byte units, non-zero = fragmented
  u16_t fragment_offset = (lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK) * 8;
  u16_t ip_flags = lwip_ntohs(IPH_OFFSET(iphdr)) & 0xE000;
  bool more_fragments = (ip_flags & IP_MF) != 0;
  bool is_fragment = (fragment_offset > 0) || more_fragments;
  
  if (is_fragment) {
    // Log fragmented packet (suspicious)
    uint32_t sourceIPAddr = ip4_addr_get_u32(&iphdr->src);
    u8_t protocol = IPH_PROTO(iphdr);
    
    const char* fragDesc = getFragmentDescription(protocol);
    
    logger.enqueueLogEvent(EVT_FRAGMENT, 0, sourceIPAddr, PROTO_TCP, protocol, fragDesc);
    
    // Drop fragmented packets
    pbuf_free(p);
    return 1;
  }
  
  // Detect IP options (suspicious)
  // Options rarely used; often indicates attacks or manipulation
  if (ip_header_len > 20) {
    // Log IP options (suspicious)
    uint32_t sourceIPAddr = ip4_addr_get_u32(&iphdr->src);
    u8_t protocol = IPH_PROTO(iphdr);
    
    const char* optDesc = getIPOptionsDescription(protocol);
    
    logger.enqueueLogEvent(EVT_IP_OPTIONS, 0, sourceIPAddr, PROTO_TCP, protocol, optDesc);
    
    // Drop packets with IP options
    pbuf_free(p);
    return 1;
  }
  
  u8_t protocol = IPH_PROTO(iphdr);
  
  // Handle TCP
  if (protocol == IP_PROTO_TCP) {
    // Validate TCP header size
    if (p->tot_len < ip_header_len + sizeof(struct tcp_hdr)) {
      pbuf_free(p);
      return 1;
    }
    
    // Ensure TCP header in first pbuf (not fragmented across pbufs)
    if (p->len < ip_header_len + sizeof(struct tcp_hdr)) {
      pbuf_free(p);
      return 1;
    }
    
    // Get TCP header
    struct tcp_hdr *tcphdr = (struct tcp_hdr *)((u8_t *)p->payload + ip_header_len);
    
    // Extract destination port
    uint16_t dest_port = ntohs(tcphdr->dest);
    
    // Check for SYN without ACK (new connection)
    u8_t flags = TCPH_FLAGS(tcphdr);
    bool is_syn = (flags & TCP_SYN) != 0;
    bool is_ack = (flags & TCP_ACK) != 0;
    
    if (is_syn && !is_ack) {
      // Check if port is monitored
      if (isHoneypotTCPPort(dest_port)) {
        // Extract source IP
        uint32_t sourceIPAddr = ip4_addr_get_u32(&iphdr->src);
        
        // Enqueue event for main loop processing
        // Filtering (broadcast/multicast/holdoff) happens in main loop
        logger.enqueueLogEvent(EVT_TCP_CONN, dest_port, sourceIPAddr, PROTO_TCP, IP_PROTO_TCP, getTCPServiceName(dest_port));
      }
      // Consume the SYN so the honeypot does not answer the connection attempt
      pbuf_free(p);
      return 1;
    }
    // Not a pure SYN (SYN-ACK, ACK, data, FIN, RST, ...) - let the normal TCP
    // stack handle it so outgoing connections (e.g. EtherNet/IP to a PLC) work.
    return 0;
  }
  
  // Handle UDP
  else if (protocol == IP_PROTO_UDP && MONITOR_UDP) {
    // Validate UDP header size
    if (p->tot_len < ip_header_len + sizeof(struct udp_hdr)) {
      pbuf_free(p);
      return 1;
    }
    
    // Ensure UDP header in first pbuf (not fragmented)
    if (p->len < ip_header_len + sizeof(struct udp_hdr)) {
      pbuf_free(p);
      return 1;
    }
    
    // Get UDP header
    struct udp_hdr *udphdr = (struct udp_hdr *)((u8_t *)p->payload + ip_header_len);
    
    // Extract destination port
    uint16_t dest_port = ntohs(udphdr->dest);
    
    // Check if port is monitored
    if (isHoneypotUDPPort(dest_port)) {
      // For EtherNet/IP ports, only report ListIdentity (browse) traffic;
      // ignore implicit I/O data (which lacks the 0x0063 command).
      if (dest_port == ENIP_PORT_44818 || dest_port == ENIP_PORT_2222) {
        // Ensure at least 4 bytes of UDP payload are in the first pbuf
        // (encapsulation Command + Length fields)
        if (p->len < ip_header_len + sizeof(struct udp_hdr) + 4) {
          pbuf_free(p);
          return 1;
        }
        // Read the EtherNet/IP encapsulation Command field (first 2 bytes, little-endian).
        // NOTE: ControlLogixDiscovery.cpp reads/writes this header little-endian and
        // works against real PLCs, so the on-wire order is little-endian here too.
        const u8_t* payload = (const u8_t*)p->payload + ip_header_len + sizeof(struct udp_hdr);
        uint16_t command = payload[0] | (payload[1] << 8);
        if (command != ENIP_LIST_IDENTITY_CMD) {
          pbuf_free(p);
          return 1;  // Not a browse request; ignore I/O traffic
        }
        // A ListIdentity RESPONSE (Length > 0) answers our own discovery
        // broadcast; pass it through to the normal UDP stack so the
        // ControlLogixDiscovery client can receive it. A ListIdentity
        // REQUEST (Length == 0) is browse traffic from another device,
        // which we log and consume below.
        uint16_t encapLength = payload[2] | (payload[3] << 8);
        if (encapLength > 0) {
          return 0;  // pass through (do NOT free the pbuf)
        }
      }
      
      // Extract source IP
      uint32_t sourceIPAddr = ip4_addr_get_u32(&iphdr->src);
      
      // Enqueue event for main loop processing
      // Filtering (broadcast/multicast/holdoff) happens in main loop
      logger.enqueueLogEvent(EVT_UDP_CONN, dest_port, sourceIPAddr, PROTO_UDP, IP_PROTO_UDP, getUDPServiceName(dest_port));
      
      // Consume the monitored-port packet
      pbuf_free(p);
      return 1;
    }
    
    // Not a monitored port: pass through so legitimate UDP traffic
    // (e.g. NTP responses on the NTP client's ephemeral port) reaches the
    // normal UDP stack.
    return 0;
  }
  
  // Handle ICMP
  else if (protocol == IP_PROTO_ICMP && MONITOR_ICMP) {
    // Validate ICMP header size
    if (p->tot_len < ip_header_len + sizeof(struct icmp_echo_hdr)) {
      pbuf_free(p);
      return 1;
    }
    
    // Ensure ICMP header in first pbuf (not fragmented)
    if (p->len < ip_header_len + sizeof(struct icmp_echo_hdr)) {
      pbuf_free(p);
      return 1;
    }
    
    // Extract ICMP type
    struct icmp_echo_hdr *icmphdr = (struct icmp_echo_hdr *)((u8_t *)p->payload + ip_header_len);
    u8_t icmp_type = ICMPH_TYPE(icmphdr);
    
    // Check if ICMP type is monitored
    if (isHoneypotICMPType(icmp_type)) {
      // Extract source IP
      uint32_t sourceIPAddr = ip4_addr_get_u32(&iphdr->src);
      
      // Enqueue event for main loop processing
      // Filtering (broadcast/multicast/holdoff) happens in main loop
      logger.enqueueLogEvent(EVT_ICMP_REQ, icmp_type, sourceIPAddr, PROTO_ICMP, IP_PROTO_ICMP, getICMPTypeName(icmp_type));
    }
  }
  
  pbuf_free(p);
  
  // Return 1 = packet consumed and freed
  return 1;
}

void setup() {
  Serial.begin(115200);
  while (!Serial) {
      delay(100);
  }
  
  Serial.println("Starting...");

  // Configure the reset button (active-high: grounded when idle, 3.3V when pressed)
  pinMode(RESET_BUTTON_PIN, INPUT);

  // Validate configuration before proceeding - halt on critical errors
  if (!validateConfiguration()) {
    Serial.println("HALTED: Fix configuration errors in Config.h, recompile and reflash");
    while(1) {
      delay(1000);
    }
  }

  Serial.print("Monitoring ");
  Serial.print(honeypotNumPorts);
  Serial.print(" TCP ports");
  if (MONITOR_UDP) {
    Serial.print(", ");
    Serial.print(honeypotNumUDPPorts);
    Serial.print(" UDP ports");
  }
  if (MONITOR_ICMP) {
    Serial.print(", ");
    Serial.print(honeypotNumICMPTypes);
    Serial.print(" ICMP types");
  }
  Serial.println();

  // Initialize port bitmaps
  Serial.println("Initializing port bitmaps...");
  
  // Clear bitmaps
  memset(tcpPortBitmap, 0, sizeof(tcpPortBitmap));
  memset(udpPortBitmap, 0, sizeof(udpPortBitmap));
  
  // Populate TCP bitmap
  for(int i = 0; i < honeypotNumPorts; i++) {
    setBitInBitmap(tcpPortBitmap, honeypotTCPPorts[i].port);
  }
  Serial.print("  TCP bitmap: ");
  Serial.print(honeypotNumPorts);
  Serial.println(" ports indexed");
  
  // Populate UDP bitmap
  if (MONITOR_UDP) {
    for(int i = 0; i < honeypotNumUDPPorts; i++) {
      setBitInBitmap(udpPortBitmap, honeypotUDPPorts[i].port);
    }
    Serial.print("  UDP bitmap: ");
    Serial.print(honeypotNumUDPPorts);
    Serial.println(" ports indexed");
  }

  // Initialize Ethernet
  ETH.begin(ETH_TYPE, ETH_ADDR, ETH_PHY_MDC, ETH_PHY_MDIO, ETH_POWER_PIN, ETH_CLK_MODE);
  ETH.config(ip, gateway, subnet, dns1, dns2);
  while(!ETH.linkUp()) {
    delay(1000);
    Serial.println("Waiting for Ethernet...");
  }
  linkWasUp = true;  // Record initial link state
  
  Serial.println("Ethernet connected.");
  Serial.print("IP Address: ");
  Serial.println(ETH.localIP());

  // Start NTP
  ntp.begin(ntpSvr);
  ntp.updateInterval(3600000);
  /*
  // Wait for initial NTP sync
  Serial.println("Waiting for NTP sync...");
  while(!ntp.update())
  {
    Serial.println("NTP retry...");
    delay(500);
  };
*/
  lastNTP = millis();
  Serial.print("NTP synchronized: ");
  Serial.print(ntp.formattedTime("%b %d %T "));
  Serial.println("UTC");
  
  // Initialize logging (all Serial output must be thread-safe after this)
  logger.begin();

  // Notify that the device has come online (power on / boot)
  logger.sendDeviceOnlineTrap(ONLINE_REASON_POWER);

  // Initialize and start the LAN scanner
  scanner.begin();
  xTaskCreate(scannerTask, "lanScanner", 8192, NULL, 1, &scannerTaskHandle);

  // Initialize and start Internet detection
  if (DETECT_INTERNET) {
    xTaskCreate(internetDetectionTask, "internetDetection", 8192, NULL, 1, &internetDetectionTaskHandle);
  }
  
  // Create raw sockets (lwIP requires separate sockets per protocol)
  
  // Create TCP raw socket
  tcp_raw_socket = raw_new(IP_PROTO_TCP);
  if (tcp_raw_socket != NULL) {
    raw_bind(tcp_raw_socket, IP_ADDR_ANY);
    raw_recv(tcp_raw_socket, raw_recv_callback, NULL);
    if (DEBUG) {
      logger.safePrintln("[DEBUG] TCP raw socket created");
    }
  } else {
    logger.safePrintln("ERROR: Could not create TCP raw socket!");
  }
  
  // UDP socket (if enabled)
  if (MONITOR_UDP) {
    udp_raw_socket = raw_new(IP_PROTO_UDP);
    if (udp_raw_socket != NULL) {
      raw_bind(udp_raw_socket, IP_ADDR_ANY);
      raw_recv(udp_raw_socket, raw_recv_callback, NULL);
      if (DEBUG) {
        logger.safePrintln("[DEBUG] UDP raw socket created");
      }
    } else {
      logger.safePrintln("ERROR: Could not create UDP raw socket!");
    }
  }
  
  // ICMP socket (if enabled)
  if (MONITOR_ICMP) {
    icmp_raw_socket = raw_new(IP_PROTO_ICMP);
    if (icmp_raw_socket != NULL) {
      raw_bind(icmp_raw_socket, IP_ADDR_ANY);
      raw_recv(icmp_raw_socket, raw_recv_callback, NULL);
      if (DEBUG) {
        logger.safePrintln("[DEBUG] ICMP raw socket created");
      }
    } else {
      logger.safePrintln("ERROR: Could not create ICMP raw socket!");
    }
  }
  
  // Print summary
  if (tcp_raw_socket != NULL || udp_raw_socket != NULL || icmp_raw_socket != NULL) {
    logger.safePrintln("Configured protocols and ports:");
    
    // Print monitored TCP ports
    if (tcp_raw_socket != NULL) {
      char portList[512] = "  TCP ports: ";
      int offset = strlen(portList);
      for(int i = 0; i < honeypotNumPorts; i++) {
        int ret = snprintf(portList + offset, sizeof(portList) - offset, "%d", honeypotTCPPorts[i].port);
        // Check for truncation or error
        if (ret < 0 || ret >= (int)(sizeof(portList) - offset)) {
          // Buffer full, indicate truncation
          snprintf(portList + offset, sizeof(portList) - offset, "...");
          break;
        }
        offset += ret;
        
        // Add separator if not last item
        if(i < honeypotNumPorts - 1) {
          ret = snprintf(portList + offset, sizeof(portList) - offset, ", ");
          if (ret < 0 || ret >= (int)(sizeof(portList) - offset)) {
            // Buffer full, indicate truncation
            snprintf(portList + offset, sizeof(portList) - offset, "...");
            break;
          }
          offset += ret;
        }
      }
      logger.safePrintln(portList);
    }
    
    // Print monitored UDP ports if enabled
    if (udp_raw_socket != NULL && MONITOR_UDP) {
      char portList[512] = "  UDP ports: ";
      int offset = strlen(portList);
      for(int i = 0; i < honeypotNumUDPPorts; i++) {
        int ret = snprintf(portList + offset, sizeof(portList) - offset, "%d", honeypotUDPPorts[i].port);
        // Check for truncation or error
        if (ret < 0 || ret >= (int)(sizeof(portList) - offset)) {
          // Buffer full, indicate truncation
          snprintf(portList + offset, sizeof(portList) - offset, "...");
          break;
        }
        offset += ret;
        
        // Add separator if not last item
        if(i < honeypotNumUDPPorts - 1) {
          ret = snprintf(portList + offset, sizeof(portList) - offset, ", ");
          if (ret < 0 || ret >= (int)(sizeof(portList) - offset)) {
            // Buffer full, indicate truncation
            snprintf(portList + offset, sizeof(portList) - offset, "...");
            break;
          }
          offset += ret;
        }
      }
      logger.safePrintln(portList);
    }
    
    // Print monitored ICMP types if enabled
    if (icmp_raw_socket != NULL && MONITOR_ICMP) {
      char typeList[512] = "  ICMP types: ";
      int offset = strlen(typeList);
      for(int i = 0; i < honeypotNumICMPTypes; i++) {
        int ret = snprintf(typeList + offset, sizeof(typeList) - offset, "%d", honeypotICMPTypes[i].type);
        // Check for truncation or error
        if (ret < 0 || ret >= (int)(sizeof(typeList) - offset)) {
          // Buffer full, indicate truncation
          snprintf(typeList + offset, sizeof(typeList) - offset, "...");
          break;
        }
        offset += ret;
        
        // Add separator if not last item
        if(i < honeypotNumICMPTypes - 1) {
          ret = snprintf(typeList + offset, sizeof(typeList) - offset, ", ");
          if (ret < 0 || ret >= (int)(sizeof(typeList) - offset)) {
            // Buffer full, indicate truncation
            snprintf(typeList + offset, sizeof(typeList) - offset, "...");
            break;
          }
          offset += ret;
        }
      }
      logger.safePrintln(typeList);
    }
  } else {
    logger.safePrintln("ERROR: Could not create any raw sockets");
    logger.safePrintln("Please check ESP-IDF configuration for raw socket support");
  }
  
  logger.safePrintln("Listening...");
}

// Reset button handling (GPIO 45, active-high: grounded when idle, 3.3V when pressed)
void checkResetButton() {
  int reading = digitalRead(RESET_BUTTON_PIN);

  // After boot, the boot circuitry holds the pin HIGH for a while (which would
  // look like a press). Wait for the pin to settle to its idle (LOW) state
  // before arming button detection.
  if (!resetButtonArmed) {
    if (reading == LOW) {
      resetButtonArmed = true;
      resetButtonState = LOW;
      resetButtonLastReading = LOW;
      resetButtonPressedAt = 0;
      resetButtonTriggered = false;
    }
    return;
  }

  if (reading != resetButtonLastReading) {
    resetButtonLastDebounce = millis();
  }
  if ((millis() - resetButtonLastDebounce) > RESET_BUTTON_DEBOUNCE_MS) {
    if (reading != resetButtonState) {
      resetButtonState = reading;
      if (resetButtonState == HIGH) {  // just pressed (active-high)
        resetButtonPressedAt = millis();   // start the hold timer
        resetButtonTriggered = false;
      }
    }
  }
  resetButtonLastReading = reading;

  // Require the button to be held for RESET_BUTTON_HOLD_MS before resetting.
  if (resetButtonState == HIGH && !resetButtonTriggered &&
      (millis() - resetButtonPressedAt) >= RESET_BUTTON_HOLD_MS) {
    resetButtonTriggered = true;
    if (DEBUG) {
      logger.safePrintln("[DEBUG] Reset button held - clearing state");
    }
    logger.resetHoldoff();
    scanner.requestReset();
    if (scannerTaskHandle != NULL) {
      xTaskNotifyGive(scannerTaskHandle);  // wake the scanner task immediately
    }
  }
}

void loop() {
  // Check the reset button
  checkResetButton();

  // Process queued log events from lwIP task
  logger.processLogQueue(ip, subnet);
  
  // Update NTP if needed
  updateNTPIfNeeded();
  
  // Monitor Ethernet link for linkUp events
  bool linkUp = ETH.linkUp();
  if (linkUp && !linkWasUp) {
    // Link just recovered after being down
    logger.sendDeviceOnlineTrap(ONLINE_REASON_LINK);
  }
  linkWasUp = linkUp;
  
  delay(1);
}