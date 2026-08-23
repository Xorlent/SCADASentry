//
// ControlLogixDiscovery.cpp
//

#include "ControlLogixDiscovery.h"

// EtherNet/IP encapsulation commands (little-endian)
static const uint16_t ENC_LIST_IDENTITY      = 0x0063;
static const uint16_t ENC_REGISTER_SESSION   = 0x0065;
static const uint16_t ENC_UNREGISTER_SESSION = 0x0066;
static const uint16_t ENC_SEND_RR_DATA       = 0x006F;

// CIP services
static const uint8_t SVC_GET_ATTR_ALL    = 0x01;
static const uint8_t SVC_GET_ATTR_SINGLE = 0x0E;
static const uint8_t SVC_UNCONNECTED_SEND = 0x52;

// CIP class codes
static const uint8_t CLASS_IDENTITY        = 0x01;
static const uint8_t CLASS_CONN_MANAGER    = 0x06;
static const uint8_t CLASS_PROGRAM_NAME    = 0x64;
static const uint8_t CLASS_TCP_IP_INTERFACE = 0xF5;

// CIP item type codes
static const uint16_t ITEM_IDENTITY         = 0x000C;  // ListIdentity response item
static const uint16_t ITEM_UNCONNECTED_DATA = 0x00B2;  // SendRRData unconnected data item

// CIP device types
static const uint16_t DEVICE_TYPE_COMM_ADAPTER = 0x0C; // Communications Adapter (Ethernet module)
static const uint16_t DEVICE_TYPE_PLC           = 0x0E; // Programmable Logic Controller (CPU)

// CIP response service flag (set in the service byte of a reply).
static const uint8_t CIP_RESPONSE_BIT = 0x80;

// Identity status word keyswitch encodings (low byte = mode, high byte = remote).
static const uint8_t KEYSWITCH_RUN      = 0x60;
static const uint8_t KEYSWITCH_PROG     = 0x70;
static const uint8_t KEYSWITCH_REMOTE_0 = 0x30;
static const uint8_t KEYSWITCH_REMOTE_1 = 0x31;

// Maximum backplane slot to scan for Ethernet modules (17-slot 1756 chassis).
static const uint8_t MAX_SLOT = 16;

// Maximum CIP response data size (receive buffer for CIP replies).
static const uint16_t MAX_CIP_RESPONSE = 256;

static const uint16_t CIP_PORT = 44818;

// Maximum acceptable SendRRData response body length. The CIP data item is
// bounded by the 256-byte receive buffer, so a 512-byte cap (16-byte item
// header + 256-byte data + headroom) is more than enough and prevents a
// malicious/broken device from forcing a huge heap allocation.
static const uint16_t MAX_RESPONSE_BODY = 512;

// All-zero encapsulation context (sender context bytes are unused here).
static const uint8_t ZERO_CONTEXT[8] = {0, 0, 0, 0, 0, 0, 0, 0};

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------
static inline void putU16(uint8_t* p, uint16_t v) { p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; }
static inline void putU32(uint8_t* p, uint32_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static inline uint16_t getU16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static inline uint32_t getU32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }

// ---------------------------------------------------------------------------
// Build the 24-byte encapsulation header. `dataLen` is the length of the
// optional data portion that follows the header.
// ---------------------------------------------------------------------------
static void buildEncapHeader(uint8_t* hdr, uint16_t command, uint16_t dataLen,
                             uint32_t session, const uint8_t context[8]) {
    putU16(hdr + 0, command);
    putU16(hdr + 2, dataLen);
    putU32(hdr + 4, session);
    putU32(hdr + 8, 0);               // status
    for (int i = 0; i < 8; i++) hdr[12 + i] = context[i];
    putU32(hdr + 20, 0);              // options
}

// ---------------------------------------------------------------------------
// Build the CIP "Unconnected Send" message that routes an embedded request
// through the Connection Manager to the module in `slot` (0..16).
//   out = 0x52 | path(CM) | priority | timeout | len | embedded | pad | route
// ---------------------------------------------------------------------------
static void buildUnconnectedSend(const uint8_t* embedded, uint16_t embeddedLen,
                                 uint8_t slot, std::vector<uint8_t>& out) {
    out.clear();
    out.push_back(SVC_UNCONNECTED_SEND);   // 0x52
    // Path to Connection Manager (class 0x06, instance 1): 02 20 06 24 01
    out.push_back(0x02);
    out.push_back(0x20); out.push_back(CLASS_CONN_MANAGER);
    out.push_back(0x24); out.push_back(0x01);
    out.push_back(0x0A);                    // priority (10)
    out.push_back(0x05);                    // timeout ticks (5)
    out.push_back(embeddedLen & 0xFF);      // message length (UINT, little-endian)
    out.push_back((embeddedLen >> 8) & 0xFF);
    for (uint16_t i = 0; i < embeddedLen; i++) out.push_back(embedded[i]);
    if (embeddedLen & 1) out.push_back(0x00);   // pad to even
    // Route path: backplane (port 1) -> slot. Encoded as PADDED_EPATH:
    //   length(1 word)=0x01, pad=0x00, port=0x01, link=slot
    out.push_back(0x01);
    out.push_back(0x00);
    out.push_back(0x01);
    out.push_back(slot);
}

// ---------------------------------------------------------------------------
// Build the embedded "Get Attributes All" request for the Identity object
// (class 0x01, instance 1). Result: 01 02 20 01 24 01
// ---------------------------------------------------------------------------
static void buildGetIdentity(std::vector<uint8_t>& out) {
    out.clear();
    out.push_back(SVC_GET_ATTR_ALL);        // 0x01
    out.push_back(0x02);                    // path size = 2 words
    out.push_back(0x20); out.push_back(CLASS_IDENTITY); // class 0x01
    out.push_back(0x24); out.push_back(0x01);           // instance 1
}

// ---------------------------------------------------------------------------
// Build the embedded "Get Attribute Single" request for the TCP/IP Interface
// object (class 0xF5), instance 1, attribute 6 (Host Name).
// Result: 0E 03 20 F5 24 01 30 06
// ---------------------------------------------------------------------------
static void buildGetHostname(std::vector<uint8_t>& out) {
    out.clear();
    out.push_back(SVC_GET_ATTR_SINGLE);     // 0x0E
    out.push_back(0x03);                    // path size = 3 words
    out.push_back(0x20); out.push_back(CLASS_TCP_IP_INTERFACE); // class 0xF5
    out.push_back(0x24); out.push_back(0x01);                   // instance 1
    out.push_back(0x30); out.push_back(0x06);                   // attribute 6
}

// ---------------------------------------------------------------------------
// Build the embedded "Get Attributes All" request for the Program Name object
// (class 0x64, instance 1). Result: 01 02 20 64 24 01
// ---------------------------------------------------------------------------
static void buildGetProgramName(std::vector<uint8_t>& out) {
    out.clear();
    out.push_back(SVC_GET_ATTR_ALL);        // 0x01
    out.push_back(0x02);                    // path size = 2 words
    out.push_back(0x20); out.push_back(CLASS_PROGRAM_NAME); // class 0x64
    out.push_back(0x24); out.push_back(0x01);               // instance 1
}

// ---------------------------------------------------------------------------
// Discovery via ListIdentity (UDP broadcast)
// ---------------------------------------------------------------------------
int ControlLogixDiscovery::discover(std::vector<ClxDiscoveryResult>& devices, uint32_t timeoutMs) {
    devices.clear();   // start fresh; don't retain results from prior runs

    WiFiUDP udp;
    if (!udp.begin(CIP_PORT)) {
        return 0;
    }

    // ListIdentity request: 24-byte header, command 0x0063, no data.
    uint8_t req[24];
    buildEncapHeader(req, ENC_LIST_IDENTITY, 0, 0, ZERO_CONTEXT);

    udp.beginPacket(IPAddress(255, 255, 255, 255), CIP_PORT);
    udp.write(req, sizeof(req));
    udp.endPacket();

    uint32_t start = millis();
    while ((uint32_t)(millis() - start) < timeoutMs) {
        int sz = udp.parsePacket();
        if (sz <= 0) {
            delay(5);
            continue;
        }
        uint8_t buf[512];
        int len = udp.read(buf, sizeof(buf));
        if (len < 26) continue;   // header (24) + item count (2)

        // Confirm it is a ListIdentity response.
        if (getU16(buf) != ENC_LIST_IDENTITY) continue;

        uint16_t itemCount = getU16(buf + 24);
        int off = 26;
        for (uint16_t i = 0; i < itemCount && off + 4 <= len; i++) {
            uint16_t type = getU16(buf + off);
            uint16_t ilen = getU16(buf + off + 2);
            off += 4;
            if (off + ilen > len) break;
            // Identity item. The fixed fields extend through the name-length
            // byte at offset 32 (IP@6, vendor@18, devType@20, prodCode@22,
            // rev@24, status@26, serial@28, nameLen@32), so require >= 33 bytes
            // to avoid reading past the received data.
            if (type == ITEM_IDENTITY && ilen >= 33) {
                ClxDiscoveryResult d;
                const uint8_t* p = buf + off;
                // Item data: encap version(2) family(2) port(2) ip(4) zero(8)
                //             vendor(2) devType(2) prodCode(2) rev(2) status(2)
                //             serial(4) nameLen(1) name(...) state(1)
                d.ipAddress = IPAddress(p[6], p[7], p[8], p[9]);
                d.vendorId      = getU16(p + 18);
                d.deviceType    = getU16(p + 20);
                d.productCode   = getU16(p + 22);
                d.majorRevision = p[24];
                d.minorRevision = p[25];
                d.serialNumber  = getU32(p + 28);
                uint8_t nameLen = p[32];
                d.productName = "";
                if (33 + nameLen <= ilen) {
                    d.productName = String((const char*)(p + 33), nameLen);
                }
                d.state = (33 + nameLen < ilen) ? p[33 + nameLen] : 0;
                devices.push_back(d);
            }
            off += ilen;
        }
    }

    udp.stop();
    return devices.size();
}

// ---------------------------------------------------------------------------
// TCP connection + RegisterSession
// ---------------------------------------------------------------------------
bool ControlLogixDiscovery::registerSession() {
    // RegisterSession request: header + protocol version(2) + option flags(2)
    uint8_t req[28];
    buildEncapHeader(req, ENC_REGISTER_SESSION, 4, 0, ZERO_CONTEXT);
    putU16(req + 24, 1);   // protocol version 1
    putU16(req + 26, 0);   // option flags 0

    if (_client.write(req, sizeof(req)) != (int)sizeof(req)) return false;
    _client.flush();

    // Read response header (24 bytes) then the declared body length.
    uint8_t hdr[24];
    if (!readExact(hdr, 24, 2000)) return false;
    uint16_t dataLen = getU16(hdr + 2);
    if (dataLen < 4) return false;
    // Read the full declared body (normally 4 bytes) to keep the TCP stream
    // aligned for subsequent reads. Cap the length to reject a malicious or
    // malformed response that would otherwise force a large read.
    uint8_t body[16];
    if (dataLen > sizeof(body) || !readExact(body, dataLen, 2000)) return false;

    _session = getU32(hdr + 4);
    return (_session != 0);
}

void ControlLogixDiscovery::unregisterSession() {
    if (!_client.connected() || _session == 0) return;
    uint8_t req[24];
    buildEncapHeader(req, ENC_UNREGISTER_SESSION, 0, _session, ZERO_CONTEXT);
    _client.write(req, sizeof(req));
    _client.flush();
    _session = 0;
}

// ---------------------------------------------------------------------------
// Read exactly `len` bytes from the TCP stream within `timeoutMs`.
// ---------------------------------------------------------------------------
bool ControlLogixDiscovery::readExact(uint8_t* buf, uint16_t len, uint32_t timeoutMs) {
    uint32_t start = millis();
    uint16_t got = 0;
    while (got < len) {
        if ((uint32_t)(millis() - start) > timeoutMs) return false;
        int n = _client.read(buf + got, len - got);
        if (n > 0) {
            got += n;
            start = millis();   // reset timeout on progress
        } else if (n < 0) {
            return false;
        } else {
            delay(1);
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Send a CIP message via SendRRData (unconnected send) and read the reply.
// The reply buffer receives the raw CIP response data item (starting at the
// response service byte).
// ---------------------------------------------------------------------------
bool ControlLogixDiscovery::sendRRData(const uint8_t* cipMsg, uint16_t cipLen,
                                       uint8_t* resp, uint16_t& respLen, uint32_t timeoutMs) {
    // SendRRData request body:
    //   interface handle(4)=0, timeout(2)=10, item count(2)=2,
    //   address item: type 0x0000 len 0, data item: type 0x00B2 len cipLen
    uint16_t bodyLen = 4 + 2 + 2 + 2 + 2 + 2 + 2 + cipLen;   // 16 + cipLen
    uint16_t total = 24 + bodyLen;
    std::vector<uint8_t> req(total);
    buildEncapHeader(req.data(), ENC_SEND_RR_DATA, bodyLen, _session, ZERO_CONTEXT);
    uint8_t* b = req.data() + 24;
    putU32(b + 0, 0);                 // interface handle
    putU16(b + 4, 10);                // timeout (ticks)
    putU16(b + 6, 2);                 // item count
    putU16(b + 8, 0x0000);            // address item type (null)
    putU16(b + 10, 0);                // address item length
    putU16(b + 12, ITEM_UNCONNECTED_DATA);   // data item type (unconnected)
    putU16(b + 14, cipLen);           // data item length
    memcpy(b + 16, cipMsg, cipLen);

    if (_client.write(req.data(), total) != (int)total) return false;
    _client.flush();

    // Read response header.
    uint8_t hdr[24];
    if (!readExact(hdr, 24, timeoutMs)) return false;
    uint16_t dataLen = getU16(hdr + 2);
    if (dataLen < 16 || dataLen > MAX_RESPONSE_BODY) return false;
    std::vector<uint8_t> body(dataLen);
    if (!readExact(body.data(), dataLen, timeoutMs)) return false;

    // body layout: iface(4) timeout(2) count(2) addrType(2) addrLen(2)
    //              dataType(2) dataLen(2) data(...)
    uint16_t count = getU16(body.data() + 6);
    int off = 8;
    for (uint16_t i = 0; i < count && off + 4 <= (int)dataLen; i++) {
        uint16_t type = getU16(body.data() + off);
        uint16_t ilen = getU16(body.data() + off + 2);
        off += 4;
        if (off + ilen > (int)dataLen) return false;
        if (type == ITEM_UNCONNECTED_DATA) {
            if (ilen > respLen) return false;
            memcpy(resp, body.data() + off, ilen);
            respLen = ilen;
            return true;
        }
        off += ilen;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Read the Identity object of the module in `slot`.
// ---------------------------------------------------------------------------
bool ControlLogixDiscovery::readIdentity(uint8_t slot, String& productName, uint8_t& major,
                                         uint8_t& minor, uint16_t* statusWord,
                                         uint16_t* deviceType, uint32_t timeoutMs) {
    std::vector<uint8_t> embedded;
    buildGetIdentity(embedded);

    std::vector<uint8_t> cip;
    buildUnconnectedSend(embedded.data(), embedded.size(), slot, cip);

    uint8_t resp[MAX_CIP_RESPONSE];
    uint16_t respLen = sizeof(resp);
    if (!sendRRData(cip.data(), cip.size(), resp, respLen, timeoutMs)) return false;

    // CIP response: service(1) reserved(1) status(1) addl-status-size(1) data...
    if (respLen < 5) return false;
    if (resp[0] != (SVC_GET_ATTR_ALL | CIP_RESPONSE_BIT)) return false;   // 0x81
    if (resp[2] != 0x00) return false;                        // general status

    const uint8_t* d = resp + 4;   // skip service, reserved, status, addl size
    uint16_t avail = respLen - 4;
    if (avail < 15) return false;  // need fixed fields + name length byte

    // vendor(2) at d+0 and product code(2) at d+4 are not needed; skip them.
    if (deviceType) *deviceType = getU16(d + 2);
    major              = d[6];
    minor              = d[7];
    if (statusWord) *statusWord = getU16(d + 8);
    // serial(4) at d+10
    uint8_t nameLen    = d[14];
    productName = "";
    if (15 + nameLen <= avail) {
        productName = String((const char*)(d + 15), nameLen);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Read the Host Name from the TCP/IP Interface object (0xF5) attr 6.
// ---------------------------------------------------------------------------
bool ControlLogixDiscovery::readHostname(String& hostname, uint32_t timeoutMs) {
    std::vector<uint8_t> embedded;
    buildGetHostname(embedded);

    std::vector<uint8_t> cip;
    buildUnconnectedSend(embedded.data(), embedded.size(), 0, cip);   // slot 0 (CPU)

    uint8_t resp[MAX_CIP_RESPONSE];
    uint16_t respLen = sizeof(resp);
    if (!sendRRData(cip.data(), cip.size(), resp, respLen, timeoutMs)) return false;

    if (respLen < 6) return false;
    if (resp[0] != (SVC_GET_ATTR_SINGLE | CIP_RESPONSE_BIT)) return false;   // 0x8E
    if (resp[2] != 0x00) return false;

    const uint8_t* d = resp + 4;   // skip service, reserved, status, addl size
    uint16_t avail = respLen - 4;
    if (avail < 2) return false;
    uint16_t len = getU16(d);      // STRING length (UINT)
    if (2 + len > avail) return false;
    hostname = String((const char*)(d + 2), len);
    return true;
}

// ---------------------------------------------------------------------------
// Read the Program Name from the Program Name object (0x64), instance 1.
// ---------------------------------------------------------------------------
bool ControlLogixDiscovery::readProgramName(String& programName, uint32_t timeoutMs) {
    std::vector<uint8_t> embedded;
    buildGetProgramName(embedded);

    std::vector<uint8_t> cip;
    buildUnconnectedSend(embedded.data(), embedded.size(), 0, cip);   // slot 0 (CPU)

    uint8_t resp[MAX_CIP_RESPONSE];
    uint16_t respLen = sizeof(resp);
    if (!sendRRData(cip.data(), cip.size(), resp, respLen, timeoutMs)) return false;

    if (respLen < 6) return false;
    if (resp[0] != (SVC_GET_ATTR_ALL | CIP_RESPONSE_BIT)) return false;   // 0x81
    if (resp[2] != 0x00) return false;

    const uint8_t* d = resp + 4;   // skip service, reserved, status, addl size
    uint16_t avail = respLen - 4;
    if (avail < 2) return false;
    uint16_t len = getU16(d);      // STRING length (UINT)
    if (2 + len > avail) return false;
    programName = String((const char*)(d + 2), len);
    return true;
}

// ---------------------------------------------------------------------------
// Connect to a PLC and read all requested information.
// ---------------------------------------------------------------------------
bool ControlLogixDiscovery::getPlcInfo(const IPAddress& ip, ClxPlcInfo& info, uint32_t timeoutMs) {
    info = ClxPlcInfo();
    info.ipAddress = ip;
    _session = 0;   // discard any stale session handle from a prior connection

    if (!_client.connect(ip, CIP_PORT, timeoutMs)) return false;

    if (!registerSession()) {
        _client.stop();
        return false;
    }

    // --- CPU (slot 0) Identity object ---
    String cpuName;
    uint8_t major = 0, minor = 0;
    uint16_t statusWord = 0;
    uint16_t slot0Type = 0;
    if (!readIdentity(0, cpuName, major, minor, &statusWord, &slot0Type, timeoutMs)) {
        unregisterSession();
        _client.stop();
        return false;
    }

    info.productName       = cpuName;
    info.cpuMajorRevision  = major;
    info.cpuMinorRevision  = minor;

    // Keyswitch position from the Identity status word.
    uint8_t s0 = statusWord & 0xFF;          // first byte
    uint8_t s1 = (statusWord >> 8) & 0xFF;   // second byte
    info.isRun = false;
    if (s0 == KEYSWITCH_RUN) {               // RUN family
        info.isRun = true;
        info.keyswitch = (s1 == KEYSWITCH_REMOTE_0 || s1 == KEYSWITCH_REMOTE_1) ? "REMOTE RUN" : "RUN";
    } else if (s0 == KEYSWITCH_PROG) {       // PROG family
        info.keyswitch = (s1 == KEYSWITCH_REMOTE_0 || s1 == KEYSWITCH_REMOTE_1) ? "REMOTE PROG" : "PROG";
    } else {
        info.keyswitch = "UNKNOWN";
    }

    // Add the slot 0 CPU to the module list.
    ClxModule cpuMod;
    cpuMod.slot          = 0;
    cpuMod.deviceType    = slot0Type;
    cpuMod.productName   = cpuName;
    cpuMod.majorRevision = major;
    cpuMod.minorRevision = minor;
    cpuMod.isRun         = info.isRun;
    info.modules.push_back(cpuMod);

    // --- Hostname (TCP/IP Interface object, attribute 6) ---
    readHostname(info.hostname, timeoutMs);   // best-effort; may be empty

    // --- Program name (Program Name object 0x64) ---
    readProgramName(info.programName, timeoutMs);   // best-effort; may be empty

    // --- Scan slots 1..16 for additional CPUs and Ethernet modules ---
    for (uint8_t slot = 1; slot <= MAX_SLOT; slot++) {
        String name;
        uint8_t m = 0, mn = 0;
        uint16_t dt = 0;
        uint16_t sw = 0;
        if (readIdentity(slot, name, m, mn, &sw, &dt, timeoutMs)) {
            if (dt == DEVICE_TYPE_COMM_ADAPTER || dt == DEVICE_TYPE_PLC) {
                ClxModule mod;
                mod.slot          = slot;
                mod.deviceType    = dt;
                mod.productName   = name;
                mod.majorRevision = m;
                mod.minorRevision = mn;
                mod.isRun         = (dt == DEVICE_TYPE_PLC) && ((sw & 0xFF) == KEYSWITCH_RUN);
                info.modules.push_back(mod);
            }
        }
    }

    return true;
}

void ControlLogixDiscovery::disconnect() {
    unregisterSession();
    if (_client.connected()) _client.stop();
}
