/*
 * HoneypotLogging.h
 * 
 * Logging and SNMP trap functionality for SCADASentry
 * Handles event queuing, holdoff tracking, and SNMP trap formatting
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#ifndef HONEYPOT_LOGGING_H
#define HONEYPOT_LOGGING_H

#include <Arduino.h>
#include "Config.h"

// Compile-time validation of MAX_TRACKED_IPS
static_assert(MAX_TRACKED_IPS > 0, "MAX_TRACKED_IPS must be greater than 0");
static_assert(MAX_TRACKED_IPS <= 255, "MAX_TRACKED_IPS must not exceed 255");
#include <WiFiUdp.h>
#include <WiFiClient.h>
#include <NTP.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include "SNMPTrap.h"

// Protocol types for holdoff tracking
enum ProtocolType {
  PROTO_TCP,
  PROTO_UDP,
  PROTO_ICMP
};

// Event types for unified logging (maps to SNMP trap OIDs)
enum EventType {
  EVT_TCP_CONN,
  EVT_UDP_CONN,
  EVT_ICMP_REQ,
  EVT_FRAGMENT,
  EVT_IP_OPTIONS
};

// Device online / reconnect reason codes (honeypotStartReason varbind)
enum DeviceOnlineReason {
  ONLINE_REASON_POWER = 1,  // Boot / power recovery
  ONLINE_REASON_LINK  = 2   // Ethernet link recovery (no reboot)
};

// Event queue entry structure for deferred logging
struct LogQueueEntry {
  EventType eventType;
  uint16_t portOrType;
  uint32_t sourceIP;
  ProtocolType protocol;
  uint8_t ianaProtocol;
  const char* serviceName;
  bool valid;
};

// IP tracking structure for holdoff functionality
struct IPLogEntry {
  uint32_t ip;
  unsigned long lastLogTime;
};

// Email queue entry structure for async SMTP processing
struct EmailQueueEntry {
  char subject[80];
  char body[512];
};

// SNMP trap OID constants are defined in HoneypotLogging.cpp

// Log queue configuration
#define LOG_QUEUE_SIZE 16

// Class for managing honeypot logging functionality
class HoneypotLogging {
private:
  // Queue for deferred event processing
  LogQueueEntry logQueue[LOG_QUEUE_SIZE];
  volatile uint8_t logQueueHead;
  volatile uint8_t logQueueTail;
  
  // SECURITY: Spinlock for queue access (protects against race conditions)
  #ifdef ESP32
    portMUX_TYPE queueMux = portMUX_INITIALIZER_UNLOCKED;
  #endif
  
  // FreeRTOS mutex for inter-core Serial synchronization
  SemaphoreHandle_t serialMutex;

  // FreeRTOS mutex for serializing SNMP trap sends (shared with the LAN scanner task)
  SemaphoreHandle_t trapMutex;

  // FreeRTOS mutex held while the default gateway is temporarily changed for
  // Internet detection. SNMP/SMTP sends block on this mutex so they are
  // deferred (not misrouted or lost) until the gateway is restored.
  SemaphoreHandle_t gatewayMutex;

  // FreeRTOS mutex guarding the holdoff tracking arrays (tcpIPLog/udpIPLog/
  // icmpIPLog), which are accessed from both the main loop and the scanner task.
  SemaphoreHandle_t holdoffMutex;

  IPLogEntry tcpIPLog[MAX_TRACKED_IPS];
  IPLogEntry udpIPLog[MAX_TRACKED_IPS];
  IPLogEntry icmpIPLog[MAX_TRACKED_IPS];
  uint8_t tcpIPLogIndex;
  uint8_t udpIPLogIndex;
  uint8_t icmpIPLogIndex;
  
  // Configuration
  const uint8_t* hostname;
  IPAddress honeypotIP;
  IPAddress snmpTrapServer;
  uint16_t snmpTrapPort;
  const char* snmpCommunity;
  bool debugMode;
  uint16_t tcpHoldoffSeconds;
  uint16_t udpHoldoffSeconds;
  uint16_t icmpHoldoffSeconds;
  
  // SMTP configuration
  bool useSMTP;
  IPAddress smtpServer;
  uint16_t smtpPort;
  const char* smtpFrom;
  const char* smtpTo;
  
  // External dependencies
  WiFiUDP* snmpUdp;
  NTP* ntpClient;
  WiFiClient smtpClient;
  
  // SMTP async task support
  QueueHandle_t emailQueue;
  TaskHandle_t smtpTaskHandle;
  static void smtpTask(void* parameter);
  
  // Helper methods
  bool isBroadcastOrMulticast(uint32_t source_ip, IPAddress localIP, IPAddress subnetMask);
  bool shouldLogEvent(uint32_t ip, ProtocolType protocol);
  bool sendSMTPEmail(const char* subject, const char* body);
  void sendTrap(const uint32_t* trapOid, size_t trapOidLen, const SnmpVarbind* varbinds, size_t varbindCount);
  
public:
  // Constructor
  HoneypotLogging(const uint8_t* hostName, IPAddress localIP, IPAddress snmpTrapSvr, uint16_t snmpTrapPt,
                  const char* snmpCommunityStr,
                  bool debug, uint16_t tcpHoldoff, uint16_t udpHoldoff, uint16_t icmpHoldoff,
                  WiFiUDP* snmpUdp, NTP* ntp,
                  bool useSMTPRelay = false, IPAddress smtpSvr = IPAddress(0,0,0,0), 
                  uint16_t smtpPt = 25, const char* smtpFromAddr = "", const char* smtpToAddr = "");
  
  // Destructor - cleanup FreeRTOS resources
  ~HoneypotLogging();
  
  // Initialization
  void begin();
  
  // Thread-safe Serial printing
  void safePrint(const char* msg);
  void safePrintln(const char* msg);
  void safePrint(unsigned long val);
  void safePrintln(unsigned long val);
  
  // SMTP async methods
  void beginSMTPTask();
  bool queueEmail(const char* subject, const char* body);
  
  // Event queuing (lwIP task context, uses critical sections)
  bool enqueueLogEvent(EventType eventType, uint16_t portOrType, uint32_t sourceIP, ProtocolType protocol, uint8_t ianaProtocol, const char* serviceName = "unknown");
  
  // Event processing (main loop)
  void processLogQueue(IPAddress localIP, IPAddress subnetMask);
  
  // Logging
  void logEvent(EventType eventType, uint16_t portOrType, IPAddress sourceIP, uint8_t ianaProtocol, const char* serviceName = "unknown");

  // Device lifecycle notification (boot / power recovery or link recovery)
  void sendDeviceOnlineTrap(DeviceOnlineReason reason);

  // LAN-discovered device notifications (called from the LAN scanner task)
  void sendNewDeviceTrap(IPAddress deviceIp, const uint8_t mac[6], bool isPlc,
                         uint16_t vendor, const char* productName, const char* firmware,
                         const char* serial, uint8_t state, int32_t mode);
  void sendDeviceGoneTrap(IPAddress deviceIp, const uint8_t mac[6]);
  void sendDeviceModeChangeTrap(IPAddress deviceIp, const uint8_t mac[6], int32_t prevMode, int32_t mode);
  void sendDeviceFirmwareChangeTrap(IPAddress deviceIp, const uint8_t mac[6],
                                    const char* prevFirmware, const char* firmware, int32_t vulnerable);

  // Internet detection notification (called from the Internet detection task)
  void sendInternetDetectedTrap(IPAddress gatewayIp, IPAddress dhcpServerIp,
                                bool internetAccessible, int32_t detectionMethod);

  // Acquire/release the gateway-change lock. While held, SNMP/SMTP sends block
  // (defer) until the temporary default-gateway change is complete. Called by
  // the Internet detection task around its temporary gateway swap.
  void beginGatewayChange();
  void endGatewayChange();

  // Remove an IP from the holdoff tracking arrays (called when a device disappears)
  void removeIPFromHoldoff(IPAddress ip);

  // Clear all holdoff tracking arrays (called on a user-requested state reset)
  void resetHoldoff();
  
  // IP filtering
  bool shouldLogIP(uint32_t sourceIP, ProtocolType protocol, IPAddress localIP, IPAddress subnetMask);
};

#endif // HONEYPOT_LOGGING_H
