#pragma once
//
// ControlLogixDiscovery - a minimal EtherNet/IP client for ESP32 (Arduino)
// -----------------------------------------------------------------------
// Discovers Rockwell ControlLogix PLCs on the local network (CIP ListIdentity)
// and reads: hostname, CPU product name, keyswitch position, CPU firmware
// revision, and the firmware revision of any Ethernet modules in the rack.
//
// Protocol references (from the provided packet captures):
//   * Discovery   : CIP ListIdentity (0x0063) over UDP port 44818 (broadcast)
//   * Session     : CIP RegisterSession (0x0065) over TCP port 44818
//   * Data reads  : CIP SendRRData (0x006F) carrying an "Unconnected Send"
//                   (Connection Manager service 0x52) that wraps a
//                   Get Attributes All (0x01) / Get Attribute Single (0x0E)
//
// The CPU is assumed to be in slot 0 of the backplane. Additional CPU modules
// (redundant controllers) and Ethernet modules are located by scanning slots
// 1..16 for modules whose Identity "device type" is 0x0E (PLC) or 0x0C
// (Communications Adapter).
//

#include <WiFi.h>
#include <WiFiUdp.h>
#include <vector>

// Result of a single ListIdentity discovery response.
struct ClxDiscoveryResult {
    IPAddress ipAddress;
    String    productName;
    uint16_t  vendorId;
    uint16_t  deviceType;      // 0x0E = PLC, 0x0C = Communications Adapter
    uint16_t  productCode;
    uint8_t   majorRevision;
    uint8_t   minorRevision;
    uint32_t  serialNumber;
    uint8_t   state;
};

// A CPU or Ethernet module found in the rack.
struct ClxModule {
    uint8_t  slot;
    uint16_t deviceType;    // 0x0E = CPU, 0x0C = Ethernet module
    String   productName;
    uint8_t  majorRevision;
    uint8_t  minorRevision;
    bool     isRun;         // run key status (CPU only; false for Ethernet)
};

// Full information gathered for one PLC.
struct ClxPlcInfo {
    IPAddress ipAddress;
    String    hostname;           // TCP/IP host name (TCP/IP Interface object 0xF5 attr 6)
    String    programName;       // controller program name (Program Name object 0x64)
    String    productName;        // CPU product name (slot 0)
    String    keyswitch;          // "RUN", "REMOTE RUN", "PROG", "REMOTE PROG", "UNKNOWN"
    bool      isRun;              // true when the keyswitch is in RUN or REMOTE RUN
    uint8_t   cpuMajorRevision;
    uint8_t   cpuMinorRevision;
    std::vector<ClxModule> modules;
};

class ControlLogixDiscovery {
public:
    // Broadcast a ListIdentity request and collect responses.
    // Clears `devices` first, then returns the number of devices found.
    int discover(std::vector<ClxDiscoveryResult>& devices, uint32_t timeoutMs = 5000);

    // Connect to a PLC and read hostname, CPU info and Ethernet module revisions.
    // Returns true on success. The connection is left open; call disconnect() when done.
    // `maxSlot` bounds the backplane slot scan (slots 1..maxSlot); pass 16 for a
    // full 17-slot chassis scan, or a smaller value to skip probing higher slots.
    // `readNames` controls the best-effort hostname/program-name reads.
    bool getPlcInfo(const IPAddress& ip, ClxPlcInfo& info, uint32_t timeoutMs = 2000,
                    uint8_t maxSlot = 16, bool readNames = true);

    // Unregister the CIP session and close the TCP connection.
    void disconnect();

private:
    WiFiClient _client;
    uint32_t   _session = 0;

    bool registerSession();
    void unregisterSession();

    // Read the Identity object (class 0x01, instance 1) of the module in `slot`.
    // `statusWord` and `deviceType` are optional; pass nullptr to skip them.
    bool readIdentity(uint8_t slot, String& productName, uint8_t& major, uint8_t& minor,
                      uint16_t* statusWord = nullptr, uint16_t* deviceType = nullptr,
                      uint32_t timeoutMs = 2000);

    // Read the Host Name (TCP/IP Interface object 0xF5, instance 1, attribute 6).
    bool readHostname(String& hostname, uint32_t timeoutMs);

    // Read the Program Name (Program Name object 0x64, instance 1).
    bool readProgramName(String& programName, uint32_t timeoutMs);

    // Send a CIP message using SendRRData (unconnected send) and receive the reply.
    bool sendRRData(const uint8_t* cipMsg, uint16_t cipLen,
                    uint8_t* resp, uint16_t& respLen, uint32_t timeoutMs);

    bool readExact(uint8_t* buf, uint16_t len, uint32_t timeoutMs);
};
