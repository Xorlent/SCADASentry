/*
 * ConfigValidation.cpp
 * 
 * Configuration validation implementation for SCADASentry
 * 
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#include <Arduino.h>
#include "Config.h"
#include "ConfigValidation.h"

// Validate configuration at startup
// Returns false if critical errors found
bool validateConfiguration() {
  bool hasErrors = false;
  bool hasWarnings = false;
  
  Serial.println("=== Configuration Validation ===");
  
  // Validate hostname
  size_t hostnameLen = strlen((const char*)hostName);
  if (hostnameLen == 0) {
    Serial.println("ERROR: hostName is empty");
    hasErrors = true;
  } else if (hostnameLen > 255) {
    Serial.println("ERROR: hostName exceeds 255 characters");
    hasErrors = true;
  } else {
    // Check for invalid characters (spaces, CRLF, control chars)
    for (size_t i = 0; i < hostnameLen; i++) {
      if (hostName[i] == ' ') {
        Serial.println("ERROR: hostName contains spaces (not allowed per RFC 3164)");
        hasErrors = true;
        break;
      } else if (hostName[i] == '\r' || hostName[i] == '\n') {
        Serial.println("ERROR: hostName contains CR/LF");
        hasErrors = true;
        break;
      } else if (hostName[i] < 32 || hostName[i] > 126) {
        Serial.println("ERROR: hostName contains non-printable characters");
        hasErrors = true;
        break;
      }
    }
  }
  
  // Validate SMTP if enabled
  if (USE_SMTP) {
    Serial.println("SMTP mode enabled, validating email configuration...");
    
    // Validate SMTP server IP
    if (smtpServer[0] == 0 && smtpServer[1] == 0 && 
        smtpServer[2] == 0 && smtpServer[3] == 0) {
      Serial.println("ERROR: smtpServer IP is 0.0.0.0 (invalid)");
      hasErrors = true;
    }
    
    // Validate SMTP port
    if (smtpPort == 0) {
      Serial.println("ERROR: smtpPort is 0 (invalid)");
      hasErrors = true;
    }
    
    // Validate email addresses
    if (smtpFromAddr != NULL) {
      size_t fromLen = strlen(smtpFromAddr);
      if (fromLen == 0) {
        Serial.println("ERROR: smtpFromAddr is empty");
        hasErrors = true;
      } else {
        for (size_t i = 0; i < fromLen; i++) {
          if (smtpFromAddr[i] == '\r' || smtpFromAddr[i] == '\n') {
            Serial.println("ERROR: smtpFromAddr contains CR/LF");
            hasErrors = true;
            break;
          }
        }
        // Basic email format check
        if (strchr(smtpFromAddr, '@') == NULL) {
          Serial.println("WARNING: smtpFromAddr missing '@' symbol");
          hasWarnings = true;
        }
        if (strchr(smtpFromAddr, '.') == NULL) {
          Serial.println("WARNING: smtpFromAddr missing '.' character");
          hasWarnings = true;
        }
      }
    } else {
      Serial.println("ERROR: smtpFromAddr is NULL");
      hasErrors = true;
    }
    
    if (smtpToAddr != NULL) {
      size_t toLen = strlen(smtpToAddr);
      if (toLen == 0) {
        Serial.println("ERROR: smtpToAddr is empty");
        hasErrors = true;
      } else {
        for (size_t i = 0; i < toLen; i++) {
          if (smtpToAddr[i] == '\r' || smtpToAddr[i] == '\n') {
            Serial.println("ERROR: smtpToAddr contains CR/LF");
            hasErrors = true;
            break;
          }
        }
        // Basic email format check
        if (strchr(smtpToAddr, '@') == NULL) {
          Serial.println("WARNING: smtpToAddr missing '@' symbol");
          hasWarnings = true;
        }
        if (strchr(smtpToAddr, '.') == NULL) {
          Serial.println("WARNING: smtpToAddr missing '.' character");
          hasWarnings = true;
        }
      }
    } else {
      Serial.println("ERROR: smtpToAddr is NULL");
      hasErrors = true;
    }
  } else {
    // Validate SNMP trap configuration
    if (snmpTrapSvr[0] == 0 && snmpTrapSvr[1] == 0 && 
        snmpTrapSvr[2] == 0 && snmpTrapSvr[3] == 0) {
      Serial.println("ERROR: snmpTrapSvr IP is 0.0.0.0 (invalid)");
      hasErrors = true;
    }
    
    if (snmpTrapPort == 0) {
      Serial.println("ERROR: snmpTrapPort is 0 (invalid)");
      hasErrors = true;
    }
    
    // Validate SNMP community string
    if (snmpCommunity == NULL || strlen(snmpCommunity) == 0) {
      Serial.println("ERROR: snmpCommunity is empty");
      hasErrors = true;
    }
  }
  
  // Validate network config
  if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
    Serial.println("ERROR: Local IP is 0.0.0.0 (invalid)");
    hasErrors = true;
  }
  if (gateway[0] == 0 && gateway[1] == 0 && gateway[2] == 0 && gateway[3] == 0) {
    Serial.println("WARNING: Gateway IP is 0.0.0.0");
    hasWarnings = true;
  }
  
  // Validate holdoff values
  if (TCP_HOLDOFF_SECONDS > 3600) {
    Serial.println("WARNING: TCP_HOLDOFF_SECONDS excessively large (may miss events)");
    hasWarnings = true;
  }
  if (UDP_HOLDOFF_SECONDS > 3600) {
    Serial.println("WARNING: UDP_HOLDOFF_SECONDS excessively large (may miss events)");
    hasWarnings = true;
  }
  if (ICMP_HOLDOFF_SECONDS > 3600) {
    Serial.println("WARNING: ICMP_HOLDOFF_SECONDS excessively large (may miss events)");
    hasWarnings = true;
  }
  
  // Validate MAX_TRACKED_IPS
  if (MAX_TRACKED_IPS == 0) {
    Serial.println("ERROR: MAX_TRACKED_IPS is 0 (holdoff will not work)");
    hasErrors = true;
  } else if (MAX_TRACKED_IPS > 255) {
    Serial.println("WARNING: MAX_TRACKED_IPS is very large (may consume excessive memory)");
    hasWarnings = true;
  }
  
  // Validate port counts
  if (honeypotNumPorts == 0) {
    Serial.println("WARNING: No TCP ports configured for monitoring");
    hasWarnings = true;
  }
  if (MONITOR_UDP && honeypotNumUDPPorts == 0) {
    Serial.println("WARNING: UDP monitoring enabled but no ports configured");
    hasWarnings = true;
  }
  if (MONITOR_ICMP && honeypotNumICMPTypes == 0) {
    Serial.println("WARNING: ICMP monitoring enabled but no types configured");
    hasWarnings = true;
  }
  
  // Validate TCP port service names
  for (int i = 0; i < honeypotNumPorts; i++) {
    if (honeypotTCPPorts[i].service == NULL) {
      Serial.print("WARNING: TCP port ");
      Serial.print(honeypotTCPPorts[i].port);
      Serial.println(" has NULL service name (will log as 'unknown')");
      hasWarnings = true;
      continue;
    }
    size_t svcLen = strlen(honeypotTCPPorts[i].service);
    if (svcLen > 64) {
      Serial.print("ERROR: TCP port ");
      Serial.print(honeypotTCPPorts[i].port);
      Serial.println(" service name exceeds 64 characters");
      hasErrors = true;
    }
    for (size_t j = 0; j < svcLen; j++) {
      if (honeypotTCPPorts[i].service[j] == '\r' || honeypotTCPPorts[i].service[j] == '\n') {
        Serial.print("ERROR: TCP port ");
        Serial.print(honeypotTCPPorts[i].port);
        Serial.println(" service name contains CR/LF");
        hasErrors = true;
        break;
      }
    }
  }
  
  // Validate UDP port service names
  if (MONITOR_UDP) {
    for (int i = 0; i < honeypotNumUDPPorts; i++) {
      if (honeypotUDPPorts[i].service == NULL) {
        Serial.print("WARNING: UDP port ");
        Serial.print(honeypotUDPPorts[i].port);
        Serial.println(" has NULL service name (will log as 'unknown')");
        hasWarnings = true;
        continue;
      }
      size_t svcLen = strlen(honeypotUDPPorts[i].service);
      if (svcLen > 64) {
        Serial.print("ERROR: UDP port ");
        Serial.print(honeypotUDPPorts[i].port);
        Serial.println(" service name exceeds 64 characters");
        hasErrors = true;
      }
      for (size_t j = 0; j < svcLen; j++) {
        if (honeypotUDPPorts[i].service[j] == '\r' || honeypotUDPPorts[i].service[j] == '\n') {
          Serial.print("ERROR: UDP port ");
          Serial.print(honeypotUDPPorts[i].port);
          Serial.println(" service name contains CR/LF");
          hasErrors = true;
          break;
        }
      }
    }
  }
  
  // Validate ICMP type names
  if (MONITOR_ICMP) {
    for (int i = 0; i < honeypotNumICMPTypes; i++) {
      if (honeypotICMPTypes[i].name == NULL) {
        Serial.print("WARNING: ICMP type ");
        Serial.print(honeypotICMPTypes[i].type);
        Serial.println(" has NULL name (will log as 'unknown')");
        hasWarnings = true;
        continue;
      }
      size_t nameLen = strlen(honeypotICMPTypes[i].name);
      if (nameLen > 64) {
        Serial.print("ERROR: ICMP type ");
        Serial.print(honeypotICMPTypes[i].type);
        Serial.println(" name exceeds 64 characters");
        hasErrors = true;
      }
      for (size_t j = 0; j < nameLen; j++) {
        if (honeypotICMPTypes[i].name[j] == '\r' || honeypotICMPTypes[i].name[j] == '\n') {
          Serial.print("ERROR: ICMP type ");
          Serial.print(honeypotICMPTypes[i].type);
          Serial.println(" name contains CR/LF");
          hasErrors = true;
          break;
        }
      }
    }
  }
  
  // Print summary
  Serial.println("=== Validation Complete ===");
  if (hasErrors) {
    Serial.println("CRITICAL ERRORS FOUND - Please fix Config.h");
    Serial.println("Device will not start until errors are resolved.");
    return false;
  } else if (hasWarnings) {
    Serial.println("Warnings found - review Config.h (continuing anyway)");
  }
  Serial.println();
  
  return true;
}
