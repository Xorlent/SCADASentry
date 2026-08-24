/*
 * HoneypotLogging.cpp
 * 
 * Implementation of logging and SNMP trap functionality for SCADASentry
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#include "HoneypotLogging.h"
#include "SNMPTrap.h"

// SNMP trap OID constants (enterprise root 1.3.6.1.4.1.99999)
static const uint32_t OID_HONEYPOT_SOURCE_IP[]    = {1,3,6,1,4,1,99999,1,1,0};
static const uint32_t OID_HONEYPOT_PROTOCOL[]     = {1,3,6,1,4,1,99999,1,2,0};
static const uint32_t OID_HONEYPOT_DEST_PORT[]    = {1,3,6,1,4,1,99999,1,3,0};
static const uint32_t OID_HONEYPOT_SERVICE_NAME[] = {1,3,6,1,4,1,99999,1,4,0};
static const uint32_t OID_HONEYPOT_ICMP_TYPE[]    = {1,3,6,1,4,1,99999,1,5,0};
static const uint32_t OID_HONEYPOT_EVENT_TIME[]   = {1,3,6,1,4,1,99999,1,19,0};
static const uint32_t OID_HONEYPOT_START_REASON[] = {1,3,6,1,4,1,99999,1,20,0};

// LAN-discovered device object OIDs
static const uint32_t OID_DEVICE_IP[]              = {1,3,6,1,4,1,99999,1,6,0};
static const uint32_t OID_DEVICE_MAC[]              = {1,3,6,1,4,1,99999,1,7,0};
static const uint32_t OID_DEVICE_VENDOR[]           = {1,3,6,1,4,1,99999,1,8,0};
static const uint32_t OID_DEVICE_PRODUCT_NAME[]     = {1,3,6,1,4,1,99999,1,9,0};
static const uint32_t OID_DEVICE_FIRMWARE[]         = {1,3,6,1,4,1,99999,1,10,0};
static const uint32_t OID_DEVICE_SERIAL[]           = {1,3,6,1,4,1,99999,1,11,0};
static const uint32_t OID_DEVICE_STATE[]            = {1,3,6,1,4,1,99999,1,12,0};
static const uint32_t OID_DEVICE_MODE[]             = {1,3,6,1,4,1,99999,1,13,0};
static const uint32_t OID_DEVICE_PREV_FIRMWARE[]    = {1,3,6,1,4,1,99999,1,14,0};
static const uint32_t OID_DEVICE_PREV_MODE[]        = {1,3,6,1,4,1,99999,1,15,0};
static const uint32_t OID_DEVICE_FIRMWARE_VULN[]    = {1,3,6,1,4,1,99999,1,16,0};

// Internet detection object OIDs
static const uint32_t OID_INTERNET_DHCP_SERVER[]        = {1,3,6,1,4,1,99999,1,21,0};
static const uint32_t OID_INTERNET_ACCESS[]    = {1,3,6,1,4,1,99999,1,22,0};
static const uint32_t OID_INTERNET_DETECTION_METHOD[]   = {1,3,6,1,4,1,99999,1,23,0};
static const uint32_t OID_INTERNET_GATEWAY[]            = {1,3,6,1,4,1,99999,1,24,0};

static const uint32_t OID_TRAP_TCP_CONN[]   = {1,3,6,1,4,1,99999,0,1};
static const uint32_t OID_TRAP_UDP_CONN[]   = {1,3,6,1,4,1,99999,0,2};
static const uint32_t OID_TRAP_ICMP_REQ[]   = {1,3,6,1,4,1,99999,0,3};
static const uint32_t OID_TRAP_FRAGMENT[]   = {1,3,6,1,4,1,99999,0,4};
static const uint32_t OID_TRAP_IP_OPTIONS[] = {1,3,6,1,4,1,99999,0,5};
static const uint32_t OID_TRAP_DEVICE_ONLINE[] = {1,3,6,1,4,1,99999,0,6};

// LAN-discovered device trap OIDs
static const uint32_t OID_TRAP_NEW_DEVICE[]         = {1,3,6,1,4,1,99999,0,8};
static const uint32_t OID_TRAP_DEVICE_GONE[]        = {1,3,6,1,4,1,99999,0,9};
static const uint32_t OID_TRAP_DEVICE_MODE_CHANGE[] = {1,3,6,1,4,1,99999,0,10};
static const uint32_t OID_TRAP_DEVICE_FW_CHANGE[]   = {1,3,6,1,4,1,99999,0,11};
static const uint32_t OID_TRAP_INTERNET_DETECTED[]       = {1,3,6,1,4,1,99999,0,12};
static const uint32_t OID_TRAP_ROGUE_DHCP[]              = {1,3,6,1,4,1,99999,0,13};

// Human-readable name for an event type
static const char* eventTypeName(EventType t) {
  switch (t) {
    case EVT_TCP_CONN:   return "TCP";
    case EVT_UDP_CONN:   return "UDP";
    case EVT_ICMP_REQ:   return "ICMP";
    case EVT_FRAGMENT:   return "Fragment";
    case EVT_IP_OPTIONS: return "IP Options";
    default:             return "Unknown";
  }
}

// Human-readable name for a ControlLogix run-switch mode
static const char* deviceModeName(int32_t mode) {
  switch (mode) {
    case 0:  return "Program";
    case 1:  return "Run";
    case 2:  return "Test (Remote)";
    default: return "Unknown";
  }
}

// Human-readable name for a ControlLogix device state
static const char* deviceStateName(uint8_t state) {
  switch (state) {
    case 0: return "Nonexistent";
    case 1: return "Self-testing";
    case 2: return "Standby";
    case 3: return "Operational";
    case 4: return "Major recoverable fault";
    case 5: return "Major unrecoverable fault";
    case 6: return "Communication fault";
    case 7: return "Unconfigured";
    default: return "Unknown";
  }
}

// Constructor
HoneypotLogging::HoneypotLogging(const uint8_t* hostName, IPAddress localIP, IPAddress snmpTrapSvr, uint16_t snmpTrapPt,
                                 const char* snmpCommunityStr,
                                 bool debug, uint16_t tcpHoldoff, uint16_t udpHoldoff, 
                                 uint16_t icmpHoldoff,
                                 WiFiUDP* snmpUdp, NTP* ntp,
                                 bool useSMTPRelay, IPAddress smtpSvr, 
                                 uint16_t smtpPt, const char* smtpFromAddr, const char* smtpToAddr) {
  hostname = hostName;
  honeypotIP = localIP;
  snmpTrapServer = snmpTrapSvr;
  snmpTrapPort = snmpTrapPt;
  snmpCommunity = snmpCommunityStr;
  debugMode = debug;
  tcpHoldoffSeconds = tcpHoldoff;
  udpHoldoffSeconds = udpHoldoff;
  icmpHoldoffSeconds = icmpHoldoff;
  this->snmpUdp = snmpUdp;
  ntpClient = ntp;
  
  // SMTP configuration
  useSMTP = useSMTPRelay;
  smtpServer = smtpSvr;
  smtpPort = smtpPt;
  smtpFrom = smtpFromAddr;
  smtpTo = smtpToAddr;
  
  // Initialize queue indices
  logQueueHead = 0;
  logQueueTail = 0;
  
  // Initialize log indices
  tcpIPLogIndex = 0;
  udpIPLogIndex = 0;
  icmpIPLogIndex = 0;
  
  // Initialize SMTP async task members
  emailQueue = NULL;
  smtpTaskHandle = NULL;
  
  // Initialize mutex handles (created later in begin())
  serialMutex = NULL;
  trapMutex = NULL;
  gatewayMutex = NULL;
  holdoffMutex = NULL;
}

// Destructor - cleanup FreeRTOS resources
HoneypotLogging::~HoneypotLogging() {
  // Stop SMTP task if running
  if (smtpTaskHandle != NULL) {
    vTaskDelete(smtpTaskHandle);
    smtpTaskHandle = NULL;
  }
  
  // Delete email queue if created
  if (emailQueue != NULL) {
    vQueueDelete(emailQueue);
    emailQueue = NULL;
  }
  
  // Delete serial mutex if created
  if (serialMutex != NULL) {
    vSemaphoreDelete(serialMutex);
    serialMutex = NULL;
  }
  
  // Delete trap mutex if created
  if (trapMutex != NULL) {
    vSemaphoreDelete(trapMutex);
    trapMutex = NULL;
  }
  
  // Delete gateway-change mutex if created
  if (gatewayMutex != NULL) {
    vSemaphoreDelete(gatewayMutex);
    gatewayMutex = NULL;
  }
  
  // Delete holdoff mutex if created
  if (holdoffMutex != NULL) {
    vSemaphoreDelete(holdoffMutex);
    holdoffMutex = NULL;
  }
}

// Initialize logging system
void HoneypotLogging::begin() {
  // Create mutex for serial synchronization across cores
  serialMutex = xSemaphoreCreateMutex();
  
  // Create mutex for serializing SNMP trap sends
  trapMutex = xSemaphoreCreateMutex();

  // Create mutex guarding temporary default-gateway changes
  gatewayMutex = xSemaphoreCreateMutex();

  // Create mutex guarding the holdoff tracking arrays
  holdoffMutex = xSemaphoreCreateMutex();
  
  // Initialize IP tracking arrays
  for(int i = 0; i < MAX_TRACKED_IPS; i++) {
    tcpIPLog[i].ip = 0;
    tcpIPLog[i].lastLogTime = 0;
    udpIPLog[i].ip = 0;
    udpIPLog[i].lastLogTime = 0;
    icmpIPLog[i].ip = 0;
    icmpIPLog[i].lastLogTime = 0;
  }
  
  // Initialize log queue
  for(int i = 0; i < LOG_QUEUE_SIZE; i++) {
    logQueue[i].valid = false;
  }
  
  // Start SMTP async task if SMTP is enabled
  beginSMTPTask();
}

// Acquire the gateway-change lock. While held, SNMP/SMTP sends block (defer)
// until the temporary default-gateway change is complete.
void HoneypotLogging::beginGatewayChange() {
  xSemaphoreTake(gatewayMutex, portMAX_DELAY);
}

// Release the gateway-change lock, allowing deferred SNMP/SMTP sends to proceed.
void HoneypotLogging::endGatewayChange() {
  xSemaphoreGive(gatewayMutex);
}

// Send an SNMP trap under the trap mutex (thread-safe across tasks).
// Blocks on the gateway-change lock so traps are deferred (not misrouted)
// while the default gateway is temporarily changed.
void HoneypotLogging::sendTrap(const uint32_t* trapOid, size_t trapOidLen,
                               const SnmpVarbind* varbinds, size_t varbindCount) {
  xSemaphoreTake(gatewayMutex, portMAX_DELAY);
  xSemaphoreTake(trapMutex, portMAX_DELAY);
  sendSNMPv2cTrap(*snmpUdp, snmpTrapServer, snmpTrapPort, snmpCommunity,
                  millis() / 10, trapOid, trapOidLen, varbinds, varbindCount);
  xSemaphoreGive(trapMutex);
  xSemaphoreGive(gatewayMutex);
}

// Thread-safe Serial functions
void HoneypotLogging::safePrint(const char* msg) {
  xSemaphoreTake(serialMutex, portMAX_DELAY);
  Serial.print(msg);
  xSemaphoreGive(serialMutex);
}

void HoneypotLogging::safePrintln(const char* msg) {
  xSemaphoreTake(serialMutex, portMAX_DELAY);
  Serial.println(msg);
  xSemaphoreGive(serialMutex);
}

void HoneypotLogging::safePrint(unsigned long val) {
  xSemaphoreTake(serialMutex, portMAX_DELAY);
  Serial.print(val);
  xSemaphoreGive(serialMutex);
}

void HoneypotLogging::safePrintln(unsigned long val) {
  xSemaphoreTake(serialMutex, portMAX_DELAY);
  Serial.println(val);
  xSemaphoreGive(serialMutex);
}

// Initialize SMTP async task
void HoneypotLogging::beginSMTPTask() {
  // Only start if SMTP is enabled
  if (!useSMTP) {
    return;
  }
  
  // Create FreeRTOS queue for 8 pending emails
  emailQueue = xQueueCreate(8, sizeof(EmailQueueEntry));
  
  if (emailQueue == NULL) {
    if (debugMode) {
      safePrintln("[DEBUG] ERROR: Failed to create email queue");
    }
    return;
  }
  
  // Create SMTP task on core 0 (core 1 runs main loop)
  // Stack: 8KB, Priority: 1 (low), Pinned to core 0
  BaseType_t result = xTaskCreatePinnedToCore(
    smtpTask,           // Task function
    "SMTP_Task",        // Task name
    8192,               // Stack size (8KB)
    this,               // Parameter (this object)
    1,                  // Priority (low)
    &smtpTaskHandle,    // Task handle
    0                   // Core 0 (main loop on core 1)
  );
  
  if (result != pdPASS) {
    if (debugMode) {
      safePrintln("[DEBUG] ERROR: Failed to create SMTP task");
    }
    // Clean up queue if task creation failed
    vQueueDelete(emailQueue);
    emailQueue = NULL;
  }
}

// SMTP task function - runs on core 0, processes emails from queue
void HoneypotLogging::smtpTask(void* parameter) {
  HoneypotLogging* logger = (HoneypotLogging*)parameter;
  EmailQueueEntry email;
  
  if (logger->debugMode) {
    logger->safePrintln("[DEBUG] SMTP task running");
  }
  
  // Process emails from queue indefinitely
  while (true) {
    // Wait for email (blocks this task, not main loop)
    // portMAX_DELAY = wait indefinitely
    if (xQueueReceive(logger->emailQueue, &email, portMAX_DELAY) == pdTRUE) {
      // Defer until any temporary default-gateway change completes, so the
      // email is not misrouted or lost.
      xSemaphoreTake(logger->gatewayMutex, portMAX_DELAY);
      // Send email (blocks this task, main loop continues)
      logger->sendSMTPEmail(email.subject, email.body);
      xSemaphoreGive(logger->gatewayMutex);
      
      // Small delay between emails
      vTaskDelay(pdMS_TO_TICKS(10));
    }
  }
}

// Queue email for async sending (non-blocking)
bool HoneypotLogging::queueEmail(const char* subject, const char* body) {
  // Fail silently if SMTP not enabled or queue not created
  if (!useSMTP || emailQueue == NULL) {
    return false;
  }
  
  // Prepare email entry
  EmailQueueEntry email;
  strncpy(email.subject, subject, sizeof(email.subject) - 1);
  email.subject[sizeof(email.subject) - 1] = '\0';
  strncpy(email.body, body, sizeof(email.body) - 1);
  email.body[sizeof(email.body) - 1] = '\0';
  
  // Non-blocking send to queue
  if (xQueueSend(emailQueue, &email, 0) == pdTRUE) {
    if (debugMode) {
      safePrintln("[DEBUG] Email queued for async sending");
    }
    return true;
  } else {
    // Queue is full, drop email
    if (debugMode) {
      safePrintln("[DEBUG] WARNING: Email queue full, dropping email");
    }
    return false;
  }
}

// Enqueue event for main loop processing
// Called from lwIP task context (not hardware ISR), uses critical sections
bool HoneypotLogging::enqueueLogEvent(EventType eventType, uint16_t portOrType, uint32_t sourceIP, ProtocolType protocol, uint8_t ianaProtocol, const char* serviceName) {
  // SECURITY: Enter critical section to prevent race conditions with processLogQueue
  portENTER_CRITICAL(&queueMux);
  
  uint8_t nextHead = (logQueueHead + 1) % LOG_QUEUE_SIZE;
  
  // Check if queue is full
  if (nextHead == logQueueTail) {
    portEXIT_CRITICAL(&queueMux);
    return false; // Queue full, drop event
  }
  
  // Add event to queue
  logQueue[logQueueHead].eventType = eventType;
  logQueue[logQueueHead].portOrType = portOrType;
  logQueue[logQueueHead].sourceIP = sourceIP;
  logQueue[logQueueHead].protocol = protocol;
  logQueue[logQueueHead].ianaProtocol = ianaProtocol;
  logQueue[logQueueHead].serviceName = serviceName;
  logQueue[logQueueHead].valid = true;
  
  logQueueHead = nextHead;
  
  portEXIT_CRITICAL(&queueMux);
  return true;
}

// Process queued events from main loop
void HoneypotLogging::processLogQueue(IPAddress localIP, IPAddress subnetMask) {
  while (logQueueTail != logQueueHead) {
    // SECURITY: Enter critical section to safely read queue entry
    portENTER_CRITICAL(&queueMux);
    
    LogQueueEntry* entry = &logQueue[logQueueTail];
    
    // Copy data out of queue while in critical section
    bool isValid = entry->valid;
    EventType eventType = entry->eventType;
    uint16_t portOrType = entry->portOrType;
    uint32_t sourceIP_u32 = entry->sourceIP;
    ProtocolType protocol = entry->protocol;
    uint8_t ianaProtocol = entry->ianaProtocol;
    const char* serviceName = entry->serviceName;
    
    // Mark as processed and advance tail
    entry->valid = false;
    logQueueTail = (logQueueTail + 1) % LOG_QUEUE_SIZE;
    
    portEXIT_CRITICAL(&queueMux);
    
    // Process event outside critical section (avoid holding lock during I/O)
    if (isValid) {
      // Check if broadcast/multicast first (silently filter)
      if (isBroadcastOrMulticast(sourceIP_u32, localIP, subnetMask)) {
        continue; // Skip without logging
      }
      
      // Check holdoff - log if in holdoff period and DEBUG enabled
      if (!shouldLogEvent(sourceIP_u32, protocol)) {
        if (debugMode) {
          IPAddress sourceIP(sourceIP_u32);
          char debugMsg[120];
          const char* protoName = eventTypeName(eventType);
          snprintf(debugMsg, sizeof(debugMsg), "[DEBUG] %s %u (%s) <- %d.%d.%d.%d (IN HOLDOFF - IGNORING)", 
                   protoName, portOrType, serviceName, sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3]);
          safePrintln(debugMsg);
        }
        continue; // Skip logging
      }
      
      // Not in holdoff, log the event
      IPAddress sourceIP(sourceIP_u32);
      logEvent(eventType, portOrType, sourceIP, ianaProtocol, serviceName);
    }
  }
}

// Detect broadcast or multicast IPs
// Returns true if IP should be filtered
bool HoneypotLogging::isBroadcastOrMulticast(uint32_t source_ip, IPAddress localIP, IPAddress subnetMask) {
  // Extract octets from network byte order IP
  uint8_t octet1 = (source_ip & 0xFF);
  uint8_t octet2 = (source_ip >> 8) & 0xFF;
  uint8_t octet3 = (source_ip >> 16) & 0xFF;
  uint8_t octet4 = (source_ip >> 24) & 0xFF;
  
  // Check for limited broadcast (255.255.255.255)
  if (source_ip == 0xFFFFFFFF) {
    return true;
  }
  
  // Check for multicast addresses (224.0.0.0/4 - first octet 224-239)
  if (octet1 >= 224 && octet1 <= 239) {
    return true;
  }
  
  // Check for local network broadcast based on configured subnet
  uint32_t local_ip = ((uint32_t)localIP[0]) | ((uint32_t)localIP[1] << 8) | 
                      ((uint32_t)localIP[2] << 16) | ((uint32_t)localIP[3] << 24);
  uint32_t subnet_mask = ((uint32_t)subnetMask[0]) | ((uint32_t)subnetMask[1] << 8) | 
                         ((uint32_t)subnetMask[2] << 16) | ((uint32_t)subnetMask[3] << 24);
  uint32_t network_broadcast = (local_ip & subnet_mask) | (~subnet_mask);
  
  if (source_ip == network_broadcast) {
    return true;
  }
  
  // Check for link-local broadcast (169.254.255.255)
  if (octet1 == 169 && octet2 == 254 && octet3 == 255 && octet4 == 255) {
    return true;
  }
  
  return false;
}

// Check holdoff to prevent event flooding
// Returns true if event should be logged
bool HoneypotLogging::shouldLogEvent(uint32_t ip, ProtocolType protocol) {
  IPLogEntry* logArray;
  uint8_t* logIndex;
  uint16_t holdoffSeconds;
  
  // Select appropriate tracking array and holdoff time
  switch(protocol) {
    case PROTO_TCP:
      logArray = tcpIPLog;
      logIndex = &tcpIPLogIndex;
      holdoffSeconds = tcpHoldoffSeconds;
      break;
    case PROTO_UDP:
      logArray = udpIPLog;
      logIndex = &udpIPLogIndex;
      holdoffSeconds = udpHoldoffSeconds;
      break;
    case PROTO_ICMP:
      logArray = icmpIPLog;
      logIndex = &icmpIPLogIndex;
      holdoffSeconds = icmpHoldoffSeconds;
      break;
    default:
      return true;
  }
  
  // Holdoff disabled, always log
  if (holdoffSeconds == 0) {
    return true;
  }
  
  unsigned long currentTime = millis();
  unsigned long holdoffMillis = (unsigned long)holdoffSeconds * 1000;
  
  // Serialize access to the holdoff arrays (shared with the scanner task's
  // removeIPFromHoldoff and the main loop's resetHoldoff).
  xSemaphoreTake(holdoffMutex, portMAX_DELAY);
  
  bool result = true;
  
  // Search for IP in tracking array
  for(int i = 0; i < MAX_TRACKED_IPS; i++) {
    if(logArray[i].ip == ip) {
      // Check if holdoff expired
      if(currentTime - logArray[i].lastLogTime >= holdoffMillis) {
        // Update timestamp and allow logging
        logArray[i].lastLogTime = currentTime;
        result = true;
      } else {
        // Still in holdoff period
        result = false;
      }
      xSemaphoreGive(holdoffMutex);
      return result;
    }
  }
  
  // IP not tracked yet, add it
  logArray[*logIndex].ip = ip;
  logArray[*logIndex].lastLogTime = currentTime;
  *logIndex = (*logIndex + 1) % MAX_TRACKED_IPS; // Circular buffer
  
  xSemaphoreGive(holdoffMutex);
  return true;
}

// Combined IP filtering (broadcast/multicast + holdoff)
bool HoneypotLogging::shouldLogIP(uint32_t sourceIP, ProtocolType protocol, 
                                   IPAddress localIP, IPAddress subnetMask) {
  // Filter broadcast/multicast
  if (isBroadcastOrMulticast(sourceIP, localIP, subnetMask)) {
    return false;
  }
  
  // Check holdoff
  return shouldLogEvent(sourceIP, protocol);
}

// Send email via SMTP relay
bool HoneypotLogging::sendSMTPEmail(const char* subject, const char* body) {
  if (debugMode) {
    safePrintln("[DEBUG] Connecting to SMTP server...");
  }
  
  // Set timeout (5s for reads/writes, 3s for connect)
  smtpClient.setTimeout(5);
  
  // Connect to server
  unsigned long connectStart = millis();
  if (!smtpClient.connect(smtpServer, smtpPort)) {
    unsigned long connectDuration = millis() - connectStart;
    if (debugMode) {
      char msg[100];
      snprintf(msg, sizeof(msg), "[DEBUG] ERROR: Failed to connect to SMTP server after %lu ms", connectDuration);
      safePrintln(msg);
    }
    return false;
  }
  
  if (debugMode) {
    unsigned long connectDuration = millis() - connectStart;
    char msg[100];
    snprintf(msg, sizeof(msg), "[DEBUG] Connected to SMTP server in %lu ms", connectDuration);
    safePrintln(msg);
  }
  
  // Wait for server greeting
  unsigned long timeout = millis();
  while (smtpClient.available() == 0) {
    if (millis() - timeout > 5000) {
      if (debugMode) {
        safePrintln("[DEBUG] ERROR: SMTP server timeout");
      }
      smtpClient.stop();
      return false;
    }
    delay(10);
  }
  
  // Read and discard greeting
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // Send HELO
  smtpClient.print("HELO ");
  smtpClient.println((const char*)hostname);
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // MAIL FROM
  smtpClient.print("MAIL FROM:<");
  smtpClient.print(smtpFrom);
  smtpClient.println(">");
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // RCPT TO
  smtpClient.print("RCPT TO:<");
  smtpClient.print(smtpTo);
  smtpClient.println(">");
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // DATA command
  smtpClient.println("DATA");
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // Email headers
  smtpClient.print("From: ");
  smtpClient.println(smtpFrom);
  smtpClient.print("To: ");
  smtpClient.println(smtpTo);
  smtpClient.print("Subject: ");
  smtpClient.println(subject);
  smtpClient.println("Content-Type: text/plain; charset=utf-8");
  smtpClient.println();
  
  // Email body
  smtpClient.println(body);
  
  // End with CRLF.CRLF
  smtpClient.println(".");
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // QUIT
  smtpClient.println("QUIT");
  delay(100);
  
  smtpClient.stop();
  
  if (debugMode) {
    safePrintln("[DEBUG] Email sent successfully");
  }
  
  return true;
}

// Build and send SNMP trap (or SMTP email) for an event
void HoneypotLogging::logEvent(EventType eventType, uint16_t portOrType, IPAddress sourceIP, uint8_t ianaProtocol, const char* serviceName) {
  // Get wall-clock timestamp (ISO 8601 UTC)
  char eventTimeStr[32];
  const char* timeStr = ntpClient->formattedTime("%Y-%m-%dT%H:%M:%SZ");
  strncpy(eventTimeStr, timeStr, sizeof(eventTimeStr) - 1);
  eventTimeStr[sizeof(eventTimeStr) - 1] = '\0';

  // Convert IP to string
  char ipString[16];
  snprintf(ipString, sizeof(ipString), "%d.%d.%d.%d", 
           sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3]);

  // Debug output
  if (debugMode) {
    char debugMsg[120];
    snprintf(debugMsg, sizeof(debugMsg), "[DEBUG] %s %u (%s) <- %d.%d.%d.%d", 
             eventTypeName(eventType), portOrType, serviceName, sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3]);
    safePrintln(debugMsg);
  }

  // SMTP mode: send email instead
  if (useSMTP) {
    // Build email subject
    char subject[80];
    snprintf(subject, sizeof(subject), "[%s Alert] Honeypot traffic detected (%s)", 
             (const char*)hostname, eventTypeName(eventType));

    // Build email body with service name
    char body[384];
    if (eventType == EVT_ICMP_REQ) {
      snprintf(body, sizeof(body), 
               "Honeypot: %s (%d.%d.%d.%d)\nTimestamp: %s UTC\nSource IP: %s\nProtocol: %s\nType: %u (%s)\n",
               (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
               eventTimeStr, ipString, eventTypeName(eventType), portOrType, serviceName);
    } else {
      snprintf(body, sizeof(body), 
               "Honeypot: %s (%d.%d.%d.%d)\nTimestamp: %s UTC\nSource IP: %s\nProtocol: %s\nPort: %u (%s)\n",
               (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
               eventTimeStr, ipString, eventTypeName(eventType), portOrType, serviceName);
    }

    if (debugMode) {
      safePrintln("[DEBUG] Queueing email alert for async sending...");
    }

    // Queue for async send
    queueEmail(subject, body);
    return;
  }

  // SNMP trap mode: select trap OID based on event type
  const uint32_t* trapOid;
  size_t trapOidLen;
  switch (eventType) {
    case EVT_TCP_CONN:
      trapOid = OID_TRAP_TCP_CONN;
      trapOidLen = sizeof(OID_TRAP_TCP_CONN) / sizeof(uint32_t);
      break;
    case EVT_UDP_CONN:
      trapOid = OID_TRAP_UDP_CONN;
      trapOidLen = sizeof(OID_TRAP_UDP_CONN) / sizeof(uint32_t);
      break;
    case EVT_ICMP_REQ:
      trapOid = OID_TRAP_ICMP_REQ;
      trapOidLen = sizeof(OID_TRAP_ICMP_REQ) / sizeof(uint32_t);
      break;
    case EVT_FRAGMENT:
      trapOid = OID_TRAP_FRAGMENT;
      trapOidLen = sizeof(OID_TRAP_FRAGMENT) / sizeof(uint32_t);
      break;
    case EVT_IP_OPTIONS:
      trapOid = OID_TRAP_IP_OPTIONS;
      trapOidLen = sizeof(OID_TRAP_IP_OPTIONS) / sizeof(uint32_t);
      break;
    default:
      return;
  }

  // Build varbinds
  uint8_t ipBytes[4] = { sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3] };
  SnmpVarbind varbinds[5];
  size_t vbCount = 0;

  // honeypotEventTime (OCTET STRING, ISO 8601 UTC)
  varbinds[vbCount].oid = OID_HONEYPOT_EVENT_TIME;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_EVENT_TIME) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)eventTimeStr;
  varbinds[vbCount].byteLen = strlen(eventTimeStr);
  vbCount++;

  // honeypotSourceIp (IpAddress)
  varbinds[vbCount].oid = OID_HONEYPOT_SOURCE_IP;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_SOURCE_IP) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = ipBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  // honeypotProtocol (INTEGER, IANA protocol number)
  varbinds[vbCount].oid = OID_HONEYPOT_PROTOCOL;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_PROTOCOL) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_INTEGER;
  varbinds[vbCount].intValue = ianaProtocol;
  vbCount++;

  // honeypotDestPort or honeypotIcmpType (INTEGER)
  if (eventType == EVT_ICMP_REQ) {
    varbinds[vbCount].oid = OID_HONEYPOT_ICMP_TYPE;
    varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_ICMP_TYPE) / sizeof(uint32_t);
  } else {
    varbinds[vbCount].oid = OID_HONEYPOT_DEST_PORT;
    varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_DEST_PORT) / sizeof(uint32_t);
  }
  varbinds[vbCount].type = SNMP_INTEGER;
  varbinds[vbCount].intValue = portOrType;
  vbCount++;

  // honeypotServiceName (OCTET STRING)
  varbinds[vbCount].oid = OID_HONEYPOT_SERVICE_NAME;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_SERVICE_NAME) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)serviceName;
  varbinds[vbCount].byteLen = strlen(serviceName);
  vbCount++;

  // Send trap
  if (debugMode) {
    safePrintln("[DEBUG] Sending SNMP trap...");
  }
  sendTrap(trapOid, trapOidLen, varbinds, vbCount);
}

// Send a trap indicating the device has come online (boot / power recovery) or
// the Ethernet link has recovered (linkUp). The reason varbind distinguishes the cause.
void HoneypotLogging::sendDeviceOnlineTrap(DeviceOnlineReason reason) {
  // Get wall-clock timestamp (ISO 8601 UTC)
  char eventTimeStr[32];
  const char* timeStr = ntpClient->formattedTime("%Y-%m-%dT%H:%M:%SZ");
  strncpy(eventTimeStr, timeStr, sizeof(eventTimeStr) - 1);
  eventTimeStr[sizeof(eventTimeStr) - 1] = '\0';

  // Human-readable reason string for SMTP/debug output
  const char* reasonStr = (reason == ONLINE_REASON_LINK) ? "Link up" : "Power on";

  // SMTP mode: send email notification instead
  if (useSMTP) {
    char subject[80];
    snprintf(subject, sizeof(subject), "[%s Alert] Device online (%s)", (const char*)hostname, reasonStr);
    char body[256];
    snprintf(body, sizeof(body),
             "Honeypot: %s (%d.%d.%d.%d)\nTimestamp: %s UTC\nStatus: Device online\nReason: %s\n",
             (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
             eventTimeStr, reasonStr);
    if (debugMode) {
      safePrintln("[DEBUG] Queueing device online email...");
    }
    queueEmail(subject, body);
    return;
  }

  // SNMP mode: build and send trap
  uint8_t ipBytes[4] = { honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3] };
  SnmpVarbind varbinds[3];
  size_t vbCount = 0;

  // honeypotEventTime (OCTET STRING, ISO 8601 UTC)
  varbinds[vbCount].oid = OID_HONEYPOT_EVENT_TIME;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_EVENT_TIME) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)eventTimeStr;
  varbinds[vbCount].byteLen = strlen(eventTimeStr);
  vbCount++;

  // honeypotSourceIp (device's own IP address)
  varbinds[vbCount].oid = OID_HONEYPOT_SOURCE_IP;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_SOURCE_IP) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = ipBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  // honeypotStartReason (INTEGER: 1 = power on, 2 = link up)
  varbinds[vbCount].oid = OID_HONEYPOT_START_REASON;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_START_REASON) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_INTEGER;
  varbinds[vbCount].intValue = reason;
  vbCount++;

  if (debugMode) {
    safePrintln("[DEBUG] Sending device online trap...");
  }

  sendTrap(OID_TRAP_DEVICE_ONLINE, sizeof(OID_TRAP_DEVICE_ONLINE) / sizeof(uint32_t), varbinds, vbCount);
}

// Send a newDeviceDiscoveredTrap for a LAN-discovered device
void HoneypotLogging::sendNewDeviceTrap(IPAddress deviceIp, const uint8_t mac[6], bool isPlc,
                                        uint16_t vendor, const char* productName, const char* firmware,
                                        const char* serial, uint8_t state, int32_t mode) {
  char eventTimeStr[32];
  const char* timeStr = ntpClient->formattedTime("%Y-%m-%dT%H:%M:%SZ");
  strncpy(eventTimeStr, timeStr, sizeof(eventTimeStr) - 1);
  eventTimeStr[sizeof(eventTimeStr) - 1] = '\0';

  // SMTP mode: send email notification instead
  if (useSMTP) {
    char subject[80];
    snprintf(subject, sizeof(subject), "[%s Alert] New device discovered", (const char*)hostname);

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
             (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5]);

    char body[512];
    if (isPlc) {
      snprintf(body, sizeof(body),
               "Honeypot: %s (%d.%d.%d.%d)\n"
               "Timestamp: %s UTC\n"
               "Device IP: %d.%d.%d.%d\n"
               "MAC: %s\n"
               "Type: ControlLogix PLC\n"
               "Product: %s\n"
               "Firmware: %s\n"
               "Serial: %s\n"
               "State: %s\n"
               "Mode: %s\n",
               (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
               eventTimeStr,
               deviceIp[0], deviceIp[1], deviceIp[2], deviceIp[3],
               macStr,
               productName, firmware, serial,
               deviceStateName(state), deviceModeName(mode));
    } else {
      snprintf(body, sizeof(body),
               "Honeypot: %s (%d.%d.%d.%d)\n"
               "Timestamp: %s UTC\n"
               "Device IP: %d.%d.%d.%d\n"
               "MAC: %s\n"
               "Type: Network device\n",
               (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
               eventTimeStr,
               deviceIp[0], deviceIp[1], deviceIp[2], deviceIp[3],
               macStr);
    }

    if (debugMode) {
      safePrintln("[DEBUG] Queueing new device email...");
    }
    queueEmail(subject, body);
    return;
  }

  uint8_t ipBytes[4] = { deviceIp[0], deviceIp[1], deviceIp[2], deviceIp[3] };

  SnmpVarbind varbinds[9];
  size_t vbCount = 0;

  // honeypotEventTime
  varbinds[vbCount].oid = OID_HONEYPOT_EVENT_TIME;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_EVENT_TIME) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)eventTimeStr;
  varbinds[vbCount].byteLen = strlen(eventTimeStr);
  vbCount++;

  // deviceIpAddress
  varbinds[vbCount].oid = OID_DEVICE_IP;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_IP) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = ipBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  // deviceMacAddress
  varbinds[vbCount].oid = OID_DEVICE_MAC;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_MAC) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = mac;
  varbinds[vbCount].byteLen = 6;
  vbCount++;

  // PLC-specific varbinds
  if (isPlc) {
    varbinds[vbCount].oid = OID_DEVICE_VENDOR;
    varbinds[vbCount].oidLen = sizeof(OID_DEVICE_VENDOR) / sizeof(uint32_t);
    varbinds[vbCount].type = SNMP_INTEGER;
    varbinds[vbCount].intValue = vendor;
    vbCount++;

    varbinds[vbCount].oid = OID_DEVICE_PRODUCT_NAME;
    varbinds[vbCount].oidLen = sizeof(OID_DEVICE_PRODUCT_NAME) / sizeof(uint32_t);
    varbinds[vbCount].type = SNMP_OCTET_STRING;
    varbinds[vbCount].bytes = (const uint8_t*)productName;
    varbinds[vbCount].byteLen = strlen(productName);
    vbCount++;

    varbinds[vbCount].oid = OID_DEVICE_FIRMWARE;
    varbinds[vbCount].oidLen = sizeof(OID_DEVICE_FIRMWARE) / sizeof(uint32_t);
    varbinds[vbCount].type = SNMP_OCTET_STRING;
    varbinds[vbCount].bytes = (const uint8_t*)firmware;
    varbinds[vbCount].byteLen = strlen(firmware);
    vbCount++;

    varbinds[vbCount].oid = OID_DEVICE_SERIAL;
    varbinds[vbCount].oidLen = sizeof(OID_DEVICE_SERIAL) / sizeof(uint32_t);
    varbinds[vbCount].type = SNMP_OCTET_STRING;
    varbinds[vbCount].bytes = (const uint8_t*)serial;
    varbinds[vbCount].byteLen = strlen(serial);
    vbCount++;

    varbinds[vbCount].oid = OID_DEVICE_STATE;
    varbinds[vbCount].oidLen = sizeof(OID_DEVICE_STATE) / sizeof(uint32_t);
    varbinds[vbCount].type = SNMP_INTEGER;
    varbinds[vbCount].intValue = state;
    vbCount++;

    varbinds[vbCount].oid = OID_DEVICE_MODE;
    varbinds[vbCount].oidLen = sizeof(OID_DEVICE_MODE) / sizeof(uint32_t);
    varbinds[vbCount].type = SNMP_INTEGER;
    varbinds[vbCount].intValue = mode;
    vbCount++;
  }

  if (debugMode) {
    safePrintln("[DEBUG] Sending new device trap...");
  }

  sendTrap(OID_TRAP_NEW_DEVICE, sizeof(OID_TRAP_NEW_DEVICE) / sizeof(uint32_t), varbinds, vbCount);
}

// Send a deviceDisappearedTrap for a device that no longer responds to ping
void HoneypotLogging::sendDeviceGoneTrap(IPAddress deviceIp, const uint8_t mac[6]) {
  char eventTimeStr[32];
  const char* timeStr = ntpClient->formattedTime("%Y-%m-%dT%H:%M:%SZ");
  strncpy(eventTimeStr, timeStr, sizeof(eventTimeStr) - 1);
  eventTimeStr[sizeof(eventTimeStr) - 1] = '\0';

  // SMTP mode: send email notification instead
  if (useSMTP) {
    char subject[80];
    snprintf(subject, sizeof(subject), "[%s Alert] Device disappeared", (const char*)hostname);

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
             (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5]);

    char body[256];
    snprintf(body, sizeof(body),
             "Honeypot: %s (%d.%d.%d.%d)\n"
             "Timestamp: %s UTC\n"
             "Device IP: %d.%d.%d.%d\n"
             "MAC: %s\n"
             "Status: Device disappeared\n",
             (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
             eventTimeStr,
             deviceIp[0], deviceIp[1], deviceIp[2], deviceIp[3],
             macStr);

    if (debugMode) {
      safePrintln("[DEBUG] Queueing device disappeared email...");
    }
    queueEmail(subject, body);
    return;
  }

  uint8_t ipBytes[4] = { deviceIp[0], deviceIp[1], deviceIp[2], deviceIp[3] };

  SnmpVarbind varbinds[3];
  size_t vbCount = 0;

  varbinds[vbCount].oid = OID_HONEYPOT_EVENT_TIME;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_EVENT_TIME) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)eventTimeStr;
  varbinds[vbCount].byteLen = strlen(eventTimeStr);
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_IP;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_IP) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = ipBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_MAC;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_MAC) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = mac;
  varbinds[vbCount].byteLen = 6;
  vbCount++;

  if (debugMode) {
    safePrintln("[DEBUG] Sending device gone trap...");
  }

  sendTrap(OID_TRAP_DEVICE_GONE, sizeof(OID_TRAP_DEVICE_GONE) / sizeof(uint32_t), varbinds, vbCount);
}

// Send a deviceModeChangedTrap for a ControlLogix run-switch change
void HoneypotLogging::sendDeviceModeChangeTrap(IPAddress deviceIp, const uint8_t mac[6], int32_t prevMode, int32_t mode) {
  char eventTimeStr[32];
  const char* timeStr = ntpClient->formattedTime("%Y-%m-%dT%H:%M:%SZ");
  strncpy(eventTimeStr, timeStr, sizeof(eventTimeStr) - 1);
  eventTimeStr[sizeof(eventTimeStr) - 1] = '\0';

  // SMTP mode: send email notification instead
  if (useSMTP) {
    char subject[80];
    snprintf(subject, sizeof(subject), "[%s %s] Device mode changed",
             (const char*)hostname, (mode == 1) ? "Notice" : "Alert");

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
             (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5]);

    char body[256];
    snprintf(body, sizeof(body),
             "Honeypot: %s (%d.%d.%d.%d)\n"
             "Timestamp: %s UTC\n"
             "Device IP: %d.%d.%d.%d\n"
             "MAC: %s\n"
             "Mode: %s -> %s\n",
             (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
             eventTimeStr,
             deviceIp[0], deviceIp[1], deviceIp[2], deviceIp[3],
             macStr,
             deviceModeName(prevMode), deviceModeName(mode));

    if (debugMode) {
      safePrintln("[DEBUG] Queueing device mode change email...");
    }
    queueEmail(subject, body);
    return;
  }

  uint8_t ipBytes[4] = { deviceIp[0], deviceIp[1], deviceIp[2], deviceIp[3] };

  SnmpVarbind varbinds[5];
  size_t vbCount = 0;

  varbinds[vbCount].oid = OID_HONEYPOT_EVENT_TIME;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_EVENT_TIME) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)eventTimeStr;
  varbinds[vbCount].byteLen = strlen(eventTimeStr);
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_IP;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_IP) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = ipBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_MAC;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_MAC) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = mac;
  varbinds[vbCount].byteLen = 6;
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_PREV_MODE;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_PREV_MODE) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_INTEGER;
  varbinds[vbCount].intValue = prevMode;
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_MODE;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_MODE) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_INTEGER;
  varbinds[vbCount].intValue = mode;
  vbCount++;

  if (debugMode) {
    safePrintln("[DEBUG] Sending device mode change trap...");
  }

  sendTrap(OID_TRAP_DEVICE_MODE_CHANGE, sizeof(OID_TRAP_DEVICE_MODE_CHANGE) / sizeof(uint32_t), varbinds, vbCount);
}

// Send a deviceFirmwareChangedTrap for a ControlLogix firmware change
void HoneypotLogging::sendDeviceFirmwareChangeTrap(IPAddress deviceIp, const uint8_t mac[6],
                                                   const char* prevFirmware, const char* firmware, int32_t vulnerable) {
  char eventTimeStr[32];
  const char* timeStr = ntpClient->formattedTime("%Y-%m-%dT%H:%M:%SZ");
  strncpy(eventTimeStr, timeStr, sizeof(eventTimeStr) - 1);
  eventTimeStr[sizeof(eventTimeStr) - 1] = '\0';

  // SMTP mode: send email notification instead
  if (useSMTP) {
    char subject[80];
    snprintf(subject, sizeof(subject), "[%s Notice] Device firmware changed", (const char*)hostname);

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
             (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5]);

    char body[256];
    snprintf(body, sizeof(body),
             "Honeypot: %s (%d.%d.%d.%d)\n"
             "Timestamp: %s UTC\n"
             "Device IP: %d.%d.%d.%d\n"
             "MAC: %s\n"
             "Firmware: %s -> %s\n",
             (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
             eventTimeStr,
             deviceIp[0], deviceIp[1], deviceIp[2], deviceIp[3],
             macStr,
             prevFirmware, firmware);

    if (debugMode) {
      safePrintln("[DEBUG] Queueing device firmware change email...");
    }
    queueEmail(subject, body);
    return;
  }

  uint8_t ipBytes[4] = { deviceIp[0], deviceIp[1], deviceIp[2], deviceIp[3] };

  SnmpVarbind varbinds[6];
  size_t vbCount = 0;

  varbinds[vbCount].oid = OID_HONEYPOT_EVENT_TIME;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_EVENT_TIME) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)eventTimeStr;
  varbinds[vbCount].byteLen = strlen(eventTimeStr);
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_IP;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_IP) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = ipBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_MAC;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_MAC) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = mac;
  varbinds[vbCount].byteLen = 6;
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_PREV_FIRMWARE;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_PREV_FIRMWARE) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)prevFirmware;
  varbinds[vbCount].byteLen = strlen(prevFirmware);
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_FIRMWARE;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_FIRMWARE) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)firmware;
  varbinds[vbCount].byteLen = strlen(firmware);
  vbCount++;

  varbinds[vbCount].oid = OID_DEVICE_FIRMWARE_VULN;
  varbinds[vbCount].oidLen = sizeof(OID_DEVICE_FIRMWARE_VULN) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_INTEGER;
  varbinds[vbCount].intValue = vulnerable;
  vbCount++;

  if (debugMode) {
    safePrintln("[DEBUG] Sending device firmware change trap...");
  }

  sendTrap(OID_TRAP_DEVICE_FW_CHANGE, sizeof(OID_TRAP_DEVICE_FW_CHANGE) / sizeof(uint32_t), varbinds, vbCount);
}

// Send an internetDetectedTrap when Internet access is detected.
void HoneypotLogging::sendInternetDetectedTrap(IPAddress gatewayIp, IPAddress dhcpServerIp,
                                               bool internetAccessible, int32_t detectionMethod) {
  char eventTimeStr[32];
  const char* timeStr = ntpClient->formattedTime("%Y-%m-%dT%H:%M:%SZ");
  strncpy(eventTimeStr, timeStr, sizeof(eventTimeStr) - 1);
  eventTimeStr[sizeof(eventTimeStr) - 1] = '\0';

  // SMTP mode: send email notification instead
  if (useSMTP) {
    char subject[80];
    snprintf(subject, sizeof(subject), "[%s Alert] Internet access detected", (const char*)hostname);

    char body[512];
    snprintf(body, sizeof(body),
             "Honeypot: %s (%d.%d.%d.%d)\n"
             "Timestamp: %s UTC\n"
             "Gateway: %d.%d.%d.%d\n"
             "DHCP server: %d.%d.%d.%d\n"
             "Internet access: %s\n"
             "Detection method: %s\n",
             (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
             eventTimeStr,
             gatewayIp[0], gatewayIp[1], gatewayIp[2], gatewayIp[3],
             dhcpServerIp[0], dhcpServerIp[1], dhcpServerIp[2], dhcpServerIp[3],
             internetAccessible ? "accessible" : "not accessible",
             detectionMethod == 1 ? "TCP connect" : "DNS query");

    if (debugMode) {
      safePrintln("[DEBUG] Queueing Internet detection email...");
    }
    queueEmail(subject, body);
    return;
  }

  uint8_t gatewayBytes[4] = { gatewayIp[0], gatewayIp[1], gatewayIp[2], gatewayIp[3] };
  uint8_t dhcpBytes[4] = { dhcpServerIp[0], dhcpServerIp[1], dhcpServerIp[2], dhcpServerIp[3] };

  SnmpVarbind varbinds[5];
  size_t vbCount = 0;

  varbinds[vbCount].oid = OID_HONEYPOT_EVENT_TIME;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_EVENT_TIME) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)eventTimeStr;
  varbinds[vbCount].byteLen = strlen(eventTimeStr);
  vbCount++;

  varbinds[vbCount].oid = OID_INTERNET_GATEWAY;
  varbinds[vbCount].oidLen = sizeof(OID_INTERNET_GATEWAY) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = gatewayBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  varbinds[vbCount].oid = OID_INTERNET_DHCP_SERVER;
  varbinds[vbCount].oidLen = sizeof(OID_INTERNET_DHCP_SERVER) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = dhcpBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  varbinds[vbCount].oid = OID_INTERNET_ACCESS;
  varbinds[vbCount].oidLen = sizeof(OID_INTERNET_ACCESS) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_INTEGER;
  varbinds[vbCount].intValue = internetAccessible ? 1 : 0;
  vbCount++;

  varbinds[vbCount].oid = OID_INTERNET_DETECTION_METHOD;
  varbinds[vbCount].oidLen = sizeof(OID_INTERNET_DETECTION_METHOD) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_INTEGER;
  varbinds[vbCount].intValue = detectionMethod;
  vbCount++;

  if (debugMode) {
    safePrintln("[DEBUG] Sending Internet access detected trap...");
  }

  sendTrap(OID_TRAP_INTERNET_DETECTED, sizeof(OID_TRAP_INTERNET_DETECTED) / sizeof(uint32_t), varbinds, vbCount);
}

// Send a rogueDhcpServerTrap when a DHCP server advertises a gateway outside
// this device's configured subnet (indicating a rogue/malicious DHCP server).
void HoneypotLogging::sendRogueDhcpTrap(IPAddress dhcpServerIp, IPAddress advertisedGatewayIp) {
  char eventTimeStr[32];
  const char* timeStr = ntpClient->formattedTime("%Y-%m-%dT%H:%M:%SZ");
  strncpy(eventTimeStr, timeStr, sizeof(eventTimeStr) - 1);
  eventTimeStr[sizeof(eventTimeStr) - 1] = '\0';

  // SMTP mode: send email notification instead
  if (useSMTP) {
    char subject[80];
    snprintf(subject, sizeof(subject), "[%s Alert] Rogue DHCP server detected", (const char*)hostname);

    char body[512];
    snprintf(body, sizeof(body),
             "Honeypot: %s (%d.%d.%d.%d)\n"
             "Timestamp: %s UTC\n"
             "DHCP server: %d.%d.%d.%d\n"
             "Advertised gateway: %d.%d.%d.%d\n",
             (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
             eventTimeStr,
             dhcpServerIp[0], dhcpServerIp[1], dhcpServerIp[2], dhcpServerIp[3],
             advertisedGatewayIp[0], advertisedGatewayIp[1], advertisedGatewayIp[2], advertisedGatewayIp[3]);

    if (debugMode) {
      safePrintln("[DEBUG] Queueing rogue DHCP server email...");
    }
    queueEmail(subject, body);
    return;
  }

  uint8_t dhcpBytes[4] = { dhcpServerIp[0], dhcpServerIp[1], dhcpServerIp[2], dhcpServerIp[3] };
  uint8_t gwBytes[4] = { advertisedGatewayIp[0], advertisedGatewayIp[1], advertisedGatewayIp[2], advertisedGatewayIp[3] };

  SnmpVarbind varbinds[3];
  size_t vbCount = 0;

  varbinds[vbCount].oid = OID_HONEYPOT_EVENT_TIME;
  varbinds[vbCount].oidLen = sizeof(OID_HONEYPOT_EVENT_TIME) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_OCTET_STRING;
  varbinds[vbCount].bytes = (const uint8_t*)eventTimeStr;
  varbinds[vbCount].byteLen = strlen(eventTimeStr);
  vbCount++;

  varbinds[vbCount].oid = OID_INTERNET_DHCP_SERVER;
  varbinds[vbCount].oidLen = sizeof(OID_INTERNET_DHCP_SERVER) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = dhcpBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  varbinds[vbCount].oid = OID_INTERNET_GATEWAY;
  varbinds[vbCount].oidLen = sizeof(OID_INTERNET_GATEWAY) / sizeof(uint32_t);
  varbinds[vbCount].type = SNMP_IP_ADDRESS;
  varbinds[vbCount].bytes = gwBytes;
  varbinds[vbCount].byteLen = 4;
  vbCount++;

  if (debugMode) {
    safePrintln("[DEBUG] Sending rogue DHCP server trap...");
  }

  sendTrap(OID_TRAP_ROGUE_DHCP, sizeof(OID_TRAP_ROGUE_DHCP) / sizeof(uint32_t), varbinds, vbCount);
}

// Remove an IP from all holdoff tracking arrays (called when a device disappears)
void HoneypotLogging::removeIPFromHoldoff(IPAddress ip) {
  uint32_t ipU32 = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3];
  xSemaphoreTake(holdoffMutex, portMAX_DELAY);
  for (int i = 0; i < MAX_TRACKED_IPS; i++) {
    if (tcpIPLog[i].ip == ipU32) { tcpIPLog[i].ip = 0; tcpIPLog[i].lastLogTime = 0; }
    if (udpIPLog[i].ip == ipU32) { udpIPLog[i].ip = 0; udpIPLog[i].lastLogTime = 0; }
    if (icmpIPLog[i].ip == ipU32) { icmpIPLog[i].ip = 0; icmpIPLog[i].lastLogTime = 0; }
  }
  xSemaphoreGive(holdoffMutex);
}

// Clear all holdoff tracking arrays (called on a user-requested state reset)
void HoneypotLogging::resetHoldoff() {
  xSemaphoreTake(holdoffMutex, portMAX_DELAY);
  tcpIPLogIndex = 0;
  udpIPLogIndex = 0;
  icmpIPLogIndex = 0;
  for (int i = 0; i < MAX_TRACKED_IPS; i++) {
    tcpIPLog[i].ip = 0;
    tcpIPLog[i].lastLogTime = 0;
    udpIPLog[i].ip = 0;
    udpIPLog[i].lastLogTime = 0;
    icmpIPLog[i].ip = 0;
    icmpIPLog[i].lastLogTime = 0;
  }
  xSemaphoreGive(holdoffMutex);
}
