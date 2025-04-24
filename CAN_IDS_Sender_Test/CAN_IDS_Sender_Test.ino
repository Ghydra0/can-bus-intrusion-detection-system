#include <SPI.h>
#include <Adafruit_MCP2515.h>

// Use the same CS pin and baudrate as the receiver
#define CS_PIN       PIN_CAN_CS
#define CAN_BAUDRATE 250000

Adafruit_MCP2515 mcp(CS_PIN);


// —— Helper functions to send each type of packet ——

void sendSteer(uint8_t dir, uint16_t value) {
  Serial.print("  › STEER: dir="); Serial.print(dir);
  Serial.print("  value="); Serial.println(value);
  mcp.beginPacket(0x100);
  mcp.write(dir);
  mcp.write(highByte(value));
  mcp.write(lowByte(value));
  mcp.endPacket();
}

void sendThrottle(uint8_t mode, uint16_t value) {
  Serial.print("  › THROTTLE: mode="); Serial.print(mode);
  Serial.print("  value="); Serial.println(value);
  mcp.beginPacket(0x200);
  mcp.write(mode);
  mcp.write(highByte(value));
  mcp.write(lowByte(value));
  mcp.endPacket();
}

void sendBrake(uint8_t mode) {
  Serial.print("  › BRAKE: mode="); Serial.println(mode);
  mcp.beginPacket(0x300);
  mcp.write(mode);
  mcp.endPacket();
}

void sendPriority(uint8_t mode) {
  Serial.print("  › PRIORITY OVERRIDE 0X0: mode="); Serial.println(mode);
  mcp.beginPacket(0x0);
  mcp.write(mode);
  mcp.endPacket();
}

// —— Test routines ——

void testNormalSequence() {
  Serial.println("[Test] Normal sequence");
  sendSteer(random(4, 7), random(255, 925));
  sendThrottle(random(0, 4), random(0, 513));
  sendBrake(random(7, 9));
}

void testDoS() {
  Serial.println("[Test] DoS – rapid sequences");
  // Two STEER packets with no delay → interval < DOS_THRESHOLD (1 ms)
  sendSteer(5, 300);
  sendThrottle(0, 400);
  sendBrake(8);

  sendSteer(5, 299);
  sendThrottle(0, 400);
  sendBrake(7);
}

void testDoSPriority() {
  Serial.println("[Test] DoS w/ priority flooding");
  sendPriority(7);
}

void testSpoof() {
  Serial.println("[Test] Spoof – invalid command values");
  // STEER: dir out of 4–6, valueRaw out of 255–924
  sendSteer(3, 1000);

  // THROTTLE: mode >3, valueRaw >512
  sendThrottle(4, 600);

  // BRAKE: mode not 7 or 8
  sendBrake(6);
}

void testReplay() {
  Serial.println("[Test] Replay – repeat valid sequence");
  // First (valid) sequence
  sendSteer(5, 300);
  delay(100);
  sendThrottle(2, 200);
  delay(100);
  sendBrake(7);
  // Immediately send it again within REPLAY_WINDOW_MS (5 s)
  delay(200);
  Serial.println("  → Replaying same sequence");
  sendSteer(5, 300);
  delay(100);
  sendThrottle(2, 200);
  delay(100);
  sendBrake(7);
}

// —— Setup & main loop ——

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  Serial.println("MCP2515 CAN Sender Test Node");

  if (!mcp.begin(CAN_BAUDRATE)) {
    Serial.println("ERROR: MCP2515 init failed");
    while (1) delay(10);
  }
  Serial.println("MCP2515 initialized");

}

void loop() {
  if (Serial.available()) {
    // read one line (up to newline)
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();  // remove whitespace/newline
    
    if (cmd == "1") {
      testNormalSequence();
      delay(10);
      testNormalSequence();
    }
    else if (cmd == "2") {
      testDoS();
    }
    else if (cmd == "3") {
    testDoSPriority();
    }
    else if (cmd == "4") {
      testSpoof();
    }
    else if (cmd == "5") {
      testReplay();
    }
    else {
      Serial.print(F("Unknown command: "));
      Serial.println(cmd);
      Serial.println(F("Use 1,2,3 4, or 5"));
    }
    // small pause so outputs don't jumble if you type fast
    delay(100);
  }
}
