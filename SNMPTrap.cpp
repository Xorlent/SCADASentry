/*
 * SNMPTrap.cpp
 * 
 * SNMPv2c trap encoder for SCADASentry
 * Implements ASN.1 BER encoding of SNMPv2c trap PDUs
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#include "SNMPTrap.h"

// Maximum encoded trap message size (UDP-safe)
#define SNMP_MAX_MESSAGE 512

// BER tag bytes
#define TAG_INTEGER      0x02
#define TAG_OCTET_STRING 0x04
#define TAG_OID          0x06
#define TAG_SEQUENCE     0x30
#define TAG_IP_ADDRESS   0x40
#define TAG_TIME_TICKS   0x43
#define TAG_TRAP_PDU     0xA7  // [7] context-specific, constructed

// Standard SNMP OIDs used internally
static const uint32_t OID_SYS_UPTIME[]     = {1,3,6,1,2,1,1,3,0};       // 1.3.6.1.2.1.1.3.0
static const uint32_t OID_SNMP_TRAP_OID[]  = {1,3,6,1,6,3,1,1,4,1,0};   // 1.3.6.1.6.3.1.1.4.1.0

// Write BER length encoding; returns bytes written
static size_t berLength(uint8_t* buf, size_t len) {
  if (len < 0x80) {
    buf[0] = (uint8_t)len;
    return 1;
  } else if (len <= 0xFF) {
    buf[0] = 0x81;
    buf[1] = (uint8_t)len;
    return 2;
  } else {
    buf[0] = 0x82;
    buf[1] = (uint8_t)(len >> 8);
    buf[2] = (uint8_t)(len & 0xFF);
    return 3;
  }
}

// Encode a single OID subidentifier in base-128; returns bytes written
static size_t encodeSubId(uint8_t* buf, uint32_t value) {
  uint8_t tmp[5];
  size_t n = 0;
  tmp[n++] = (uint8_t)(value & 0x7F);
  value >>= 7;
  while (value) {
    tmp[n++] = (uint8_t)((value & 0x7F) | 0x80);
    value >>= 7;
  }
  size_t pos = 0;
  for (size_t i = n; i > 0; i--) {
    buf[pos++] = tmp[i - 1];
  }
  return pos;
}

// Encode an OID (subidentifier list) into BER content (no tag/length)
static size_t encodeOIDContent(uint8_t* buf, const uint32_t* oid, size_t oidLen) {
  if (oidLen < 2) return 0;
  size_t pos = 0;
  pos += encodeSubId(buf + pos, oid[0] * 40 + oid[1]);
  for (size_t i = 2; i < oidLen; i++) {
    pos += encodeSubId(buf + pos, oid[i]);
  }
  return pos;
}

// Write INTEGER TLV; returns bytes written
static size_t writeInteger(uint8_t* buf, int32_t value) {
  uint8_t content[5];
  size_t len = 0;
  if (value >= 0) {
    uint32_t v = (uint32_t)value;
    uint8_t tmp[4];
    int n = 0;
    do {
      tmp[n++] = (uint8_t)(v & 0xFF);
      v >>= 8;
    } while (v);
    for (int i = n - 1; i >= 0; i--) content[len++] = tmp[i];
    // If the high bit is set, prepend 0x00 to keep the value positive
    if (content[0] & 0x80) {
      memmove(content + 1, content, len);
      content[0] = 0x00;
      len++;
    }
  } else {
    content[0] = 0xFF;
    len = 1;
  }
  buf[0] = TAG_INTEGER;
  size_t l = berLength(buf + 1, len);
  memcpy(buf + 1 + l, content, len);
  return 1 + l + len;
}

// Write TimeTicks TLV (unsigned integer); returns bytes written
static size_t writeTimeTicks(uint8_t* buf, uint32_t value) {
  uint8_t content[4];
  size_t len = 0;
  uint8_t tmp[4];
  int n = 0;
  do {
    tmp[n++] = (uint8_t)(value & 0xFF);
    value >>= 8;
  } while (value);
  for (int i = n - 1; i >= 0; i--) content[len++] = tmp[i];
  buf[0] = TAG_TIME_TICKS;
  size_t l = berLength(buf + 1, len);
  memcpy(buf + 1 + l, content, len);
  return 1 + l + len;
}

// Write OCTET STRING TLV; returns bytes written
static size_t writeOctetString(uint8_t* buf, const uint8_t* data, size_t len) {
  buf[0] = TAG_OCTET_STRING;
  size_t l = berLength(buf + 1, len);
  memcpy(buf + 1 + l, data, len);
  return 1 + l + len;
}

// Write IpAddress TLV (always 4 bytes); returns bytes written
static size_t writeIpAddress(uint8_t* buf, const uint8_t* addr4) {
  buf[0] = TAG_IP_ADDRESS;
  buf[1] = 4;
  memcpy(buf + 2, addr4, 4);
  return 6;
}

// Write OID TLV; returns bytes written
static size_t writeOID(uint8_t* buf, const uint32_t* oid, size_t oidLen) {
  uint8_t content[64];
  size_t clen = encodeOIDContent(content, oid, oidLen);
  buf[0] = TAG_OID;
  size_t l = berLength(buf + 1, clen);
  memcpy(buf + 1 + l, content, clen);
  return 1 + l + clen;
}

// Write SEQUENCE TLV wrapping pre-built content; returns bytes written
static size_t writeSequence(uint8_t* buf, const uint8_t* content, size_t len) {
  buf[0] = TAG_SEQUENCE;
  size_t l = berLength(buf + 1, len);
  memcpy(buf + 1 + l, content, len);
  return 1 + l + len;
}

// Write context-specific constructed TLV (e.g. trap PDU 0xA7)
static size_t writeContextTag(uint8_t* buf, uint8_t tag, const uint8_t* content, size_t len) {
  buf[0] = tag;
  size_t l = berLength(buf + 1, len);
  memcpy(buf + 1 + l, content, len);
  return 1 + l + len;
}

// Send an SNMPv2c trap
bool sendSNMPv2cTrap(WiFiUDP& udp, IPAddress receiver, uint16_t port,
                     const char* community,
                     uint32_t sysUpTimeTicks,
                     const uint32_t* trapOid, size_t trapOidLen,
                     const SnmpVarbind* varbinds, size_t varbindCount) {
  // Build varbind list content
  uint8_t vbl[SNMP_MAX_MESSAGE];
  size_t vblLen = 0;

  // Varbind 1: sysUpTime.0 (TimeTicks)
  {
    uint8_t vb[128];
    uint8_t content[64];
    size_t clen = 0;
    clen += writeOID(content + clen, OID_SYS_UPTIME, sizeof(OID_SYS_UPTIME) / sizeof(uint32_t));
    clen += writeTimeTicks(content + clen, sysUpTimeTicks);
    size_t vblen = writeSequence(vb, content, clen);
    memcpy(vbl + vblLen, vb, vblen);
    vblLen += vblen;
  }

  // Varbind 2: snmpTrapOID.0 (OID value)
  {
    uint8_t vb[128];
    uint8_t content[64];
    size_t clen = 0;
    clen += writeOID(content + clen, OID_SNMP_TRAP_OID, sizeof(OID_SNMP_TRAP_OID) / sizeof(uint32_t));
    clen += writeOID(content + clen, trapOid, trapOidLen);
    size_t vblen = writeSequence(vb, content, clen);
    memcpy(vbl + vblLen, vb, vblen);
    vblLen += vblen;
  }

  // Payload varbinds
  for (size_t i = 0; i < varbindCount; i++) {
    uint8_t vb[192];
    uint8_t content[160];
    size_t clen = 0;
    clen += writeOID(content + clen, varbinds[i].oid, varbinds[i].oidLen);
    switch (varbinds[i].type) {
      case SNMP_INTEGER:
        clen += writeInteger(content + clen, varbinds[i].intValue);
        break;
      case SNMP_OCTET_STRING:
        clen += writeOctetString(content + clen, varbinds[i].bytes, varbinds[i].byteLen);
        break;
      case SNMP_IP_ADDRESS:
        clen += writeIpAddress(content + clen, varbinds[i].bytes);
        break;
      default:
        return false; // Unsupported value type
    }
    size_t vblen = writeSequence(vb, content, clen);
    memcpy(vbl + vblLen, vb, vblen);
    vblLen += vblen;
  }

  // Build varbind list TLV
  uint8_t vblTlv[SNMP_MAX_MESSAGE];
  size_t vblTlvLen = writeSequence(vblTlv, vbl, vblLen);

  // Build trap PDU content: request-id, error-status, error-index, varbind list
  uint8_t pduContent[SNMP_MAX_MESSAGE];
  size_t pduLen = 0;
  pduLen += writeInteger(pduContent + pduLen, 1);  // request-id
  pduLen += writeInteger(pduContent + pduLen, 0);  // error-status
  pduLen += writeInteger(pduContent + pduLen, 0);  // error-index
  memcpy(pduContent + pduLen, vblTlv, vblTlvLen);
  pduLen += vblTlvLen;

  // Build trap PDU TLV ([7] context tag)
  uint8_t pduTlv[SNMP_MAX_MESSAGE];
  size_t pduTlvLen = writeContextTag(pduTlv, TAG_TRAP_PDU, pduContent, pduLen);

  // Build message content: version, community, trap PDU
  uint8_t msgContent[SNMP_MAX_MESSAGE];
  size_t msgContentLen = 0;
  msgContentLen += writeInteger(msgContent + msgContentLen, 1);  // SNMPv2c version = 1
  msgContentLen += writeOctetString(msgContent + msgContentLen, (const uint8_t*)community, strlen(community));
  memcpy(msgContent + msgContentLen, pduTlv, pduTlvLen);
  msgContentLen += pduTlvLen;

  // Build message TLV (SEQUENCE)
  uint8_t msg[SNMP_MAX_MESSAGE];
  size_t msgLen = writeSequence(msg, msgContent, msgContentLen);

  // Send over UDP
  udp.beginPacket(receiver, port);
  udp.write(msg, msgLen);
  return udp.endPacket() == 1;
}

