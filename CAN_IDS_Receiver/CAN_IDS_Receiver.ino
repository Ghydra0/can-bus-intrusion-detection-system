/*
 * File:   CAN_IDS_Receiver.INO
 * Author: Caden Nihart
 * Date:   April 18, 2025
 *
 * Description:
 *   Implements a CAN‐bus intrusion detection node for RP2040 + MCP2515.
 *   - Monitors 0x100/0x200/0x300 packet sequence
 *   - Detects DoS, spoof, and replay attacks
 *   - Alerts via LED and serial logging
 *
 * Usage:
 *   Deploy this code to one node on car 2's CAN bus.
 *   If bus addresses, # of nodes, or overall architecture ever changes
 *   then this code will need to be reviewed and updated
 *
 */ 

#include <Adafruit_MCP2515.h>

// Constants
#define CS_PIN       PIN_CAN_CS
#define CAN_BAUDRATE 250000
#define LED_PIN      LED_BUILTIN
#define DOS_THRESHOLD 5  // ms between repeated packets from same ID
#define HISTORY_SIZE 32
#define REPLAY_WINDOW_MS 5000  // how long to keep old entries

// CAN object
Adafruit_MCP2515 mcp(CS_PIN);

// Tracking last seen times for DoS detection (only safe for 11-bit IDs)
unsigned long lastSeen[2048];  // 0x000 to 0x7FF

uint32_t currentState = 0x100; // Initial state
uint64_t packed = 0; // Packed sequence data for analysis

// Storage for packed sequences + timestamps
struct HistoryEntry {
  uint64_t packed;
  unsigned long ts;
};
HistoryEntry history[HISTORY_SIZE];
int historyIdx = 0;

// Call this after computing `packed` for one full 3‑packet cycle
void storePackedSequence(uint64_t packed) {
  history[historyIdx].packed = packed;
  history[historyIdx].ts     = millis();
  historyIdx = (historyIdx + 1) % HISTORY_SIZE;
}

// Replay check
bool isReplay(uint64_t packed) {
  unsigned long now = millis();
  for (int i = 0; i < HISTORY_SIZE; i++) {
    // Skip entries older than our window
    if (now - history[i].ts > REPLAY_WINDOW_MS) continue;
    if (history[i].packed == packed) {
      return true;
    }
  }
  return false;
}

// Anomaly analysis function
void runAnalysis(uint32_t id) {
  unsigned long now = millis();
  unsigned long interval = now - lastSeen[id];

  // === DoS Detection ===
  if (interval < DOS_THRESHOLD) {
    Serial.print("DoS DETECTED on ID 0x");
    Serial.print(id, HEX);
    Serial.print(" | Interval: ");
    Serial.print(interval);
    Serial.println(" ms");

    digitalWrite(LED_PIN, HIGH);
  }
  lastSeen[id] = now;

  // === Spoofed Messages "Fuzzy Attack" ===
  // - Check data against known values
  
  // - STEER: steerDirCmd = 4-6, steerValueRaw = 255-924 (sent as high and low, must rebuild)
  if (id == 0x100) {
    packed = 0; // Reset packed for new sequence
    uint8_t steerDirCmd = mcp.read();
    uint8_t steerHigh = mcp.read();
    uint8_t steerLow = mcp.read();
    uint16_t steerValueRaw = (steerHigh << 8) | steerLow;

    if (steerDirCmd < 4 || steerDirCmd > 6) {
      Serial.print("ALERT: Invalid steerDirCmd: ");
      Serial.println(steerDirCmd);
      digitalWrite(LED_PIN, HIGH); // Alert
    }
    if (steerValueRaw < 255 || steerValueRaw > 924) {
      Serial.print("ALERT: Invalid steerValueRaw: ");
      Serial.println(steerValueRaw);
      digitalWrite(LED_PIN, HIGH); // Alert
    }

    packed = steerDirCmd;
    packed = (packed << 8) | steerHigh;
    packed = (packed << 8) | steerLow;
  }

  // - THROTTLE: throttleRaw = 0-512 (sent as high and low, must rebuild), driveModeCmd = 0-3
  else if (id == 0x200) {
    uint8_t driveModeCmd = mcp.read();
    uint8_t throttleHigh = mcp.read();
    uint8_t throttleLow = mcp.read();
    uint16_t throttleRaw = (throttleHigh << 8) | throttleLow;

    if (driveModeCmd > 3) {
      Serial.print("ALERT: Invalid driveModeCmd: ");
      Serial.println(driveModeCmd);
      digitalWrite(LED_PIN, HIGH); // Alert
    }
    if (throttleRaw > 512) {
      Serial.print("ALERT: Invalid throttleRaw: ");
      Serial.println(throttleRaw);
      digitalWrite(LED_PIN, HIGH); // Alert
    }

    packed = (packed << 8) | driveModeCmd;
    packed = (packed << 8) | throttleHigh;
    packed = (packed << 8) | throttleLow;
  }
  
  // - BRAKE: brakeModeCmd = 7 (extend) | 8 (retract)
  else if (id == 0x300) {
    uint8_t brakeModeCmd = mcp.read();
    if (brakeModeCmd != 7 && brakeModeCmd != 8) {
      Serial.print("ALERT: Invalid brakeModeCmd: ");
      Serial.println(brakeModeCmd);
      digitalWrite(LED_PIN, HIGH); // Alert
    }

    packed = (packed << 8) | brakeModeCmd;
    //Check sequence for replay, store sequence for replay checking
    if (isReplay(packed)) {
      Serial.print("ALERT: Replay detected for packed sequence: ");
      Serial.println(packed, HEX);
      digitalWrite(LED_PIN, HIGH); // Alert
    } else {
      storePackedSequence(packed);
    }
  }
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  Serial.println("MCP2515 test!");
  if (!mcp.begin(CAN_BAUDRATE)) {
    Serial.println("Error initializing MCP2515.");
    while (1) delay(10);
  }

  Serial.println("MCP2515 chip found");
}

void loop() {
  int packetSize = mcp.parsePacket();
  
  if (packetSize) {
    uint32_t id = mcp.packetId();  // ID of received packet

    // Sequence verification
    // - 0x100 -> 0x200 -> 0x300 -> 0x100
    switch (currentState) {
      case 0x100:
        if(id != 0x100) {
          Serial.print("ALERT: Invalid packet ID 0x");
          digitalWrite(LED_PIN, HIGH); // Alert
        }
        else {
          Serial.print("Received STEER packet: ID 0x");
          currentState = 0x200; // Next expected state
        }
        break;
      case 0x200:
        if(id != 0x200) {
          Serial.print("ALERT: Invalid packet ID 0x");
          digitalWrite(LED_PIN, HIGH); // Alert
        }
        else {
          Serial.print("Received THROTTLE packet: ID 0x");
          currentState = 0x300; // Next expected state
        }
        break;
      case 0x300:
        if(id != 0x300) {
          Serial.print("ALERT: Invalid packet ID 0x");
          digitalWrite(LED_PIN, HIGH); // Alert
        }
        else {
          Serial.print("Received BRAKE packet: ID 0x");
          currentState = 0x100; // Next expected state
        }
        break;
    }

    Serial.print(id, HEX);
    Serial.print(" | Length: ");
    Serial.println(packetSize);

    runAnalysis(id);
  }
}

// dos not caught? fix that
// next set up button control for sending packet sequences
// set up button control to ack errors

