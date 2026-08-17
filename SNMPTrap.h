/*
 * SNMPTrap.h
 * 
 * SNMPv2c trap encoder for SCADASentry
 * Declares the ASN.1 BER trap encoder interface
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#ifndef SNMP_TRAP_H
#define SNMP_TRAP_H

#include <Arduino.h>
#include <WiFiUdp.h>
#include <IPAddress.h>

// SNMP varbind value types (ASN.1 tags)
enum SnmpValueType {
  SNMP_INTEGER      = 0x02,  // INTEGER
  SNMP_OCTET_STRING = 0x04,  // OCTET STRING
  SNMP_OID          = 0x06,  // OBJECT IDENTIFIER
  SNMP_IP_ADDRESS   = 0x40,  // IpAddress (application type)
  SNMP_TIME_TICKS   = 0x43   // TimeTicks (application type)
};

// A single SNMP variable binding (name + value)
struct SnmpVarbind {
  const uint32_t* oid;   // Name OID subidentifier array
  size_t oidLen;         // Number of subidentifiers
  SnmpValueType type;    // Value type
  const uint8_t* bytes;  // Raw value bytes (OCTET STRING / IpAddress)
  size_t byteLen;        // Length of bytes
  int32_t intValue;      // Value for INTEGER / TimeTicks
};

// Send an SNMPv2c trap to a receiver.
// The sysUpTime.0 and snmpTrapOID.0 varbinds are added automatically.
// Returns true on success, false on failure.
bool sendSNMPv2cTrap(WiFiUDP& udp, IPAddress receiver, uint16_t port,
                     const char* community,
                     uint32_t sysUpTimeTicks,
                     const uint32_t* trapOid, size_t trapOidLen,
                     const SnmpVarbind* varbinds, size_t varbindCount);

#endif // SNMP_TRAP_H
