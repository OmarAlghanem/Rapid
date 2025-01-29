// ESP32 WROOM-32 Code in C++ for Arduino IDE
// This code should be uploaded to the ESP32 using the Arduino IDE.

#include <HardwareSerial.h>
#include <Arduino.h>

// Pin configuration
#define RESET_PIN 18  // Connect to Raspberry Pi's RUN pin
#define SIGNAL_PIN 23 // Connected to Raspberry Pi's GPIO2

const int WATCHDOG_TIMEOUT = 15000; 
int current_time = WATCHDOG_TIMEOUT;

HardwareSerial espSerial(2); 

void setup() {
    pinMode(RESET_PIN, OUTPUT);
    digitalWrite(RESET_PIN, HIGH); // HIGH pin keeps Raspberry Pi alive
    pinMode(SIGNAL_PIN, INPUT);

    espSerial.begin(9600, SERIAL_8N1, 16, 17); 
    Serial.begin(115200);
    Serial.println("ESP32 Watchdog Initialized");
}

void resetRaspberryPi() {
    Serial.println("Watchdog timer expired. Triggering Raspberry Pi RUN pin...");
    digitalWrite(RESET_PIN, LOW);
    delay(100);
    digitalWrite(RESET_PIN, HIGH);
}

void loop() {
    int signal = digitalRead(SIGNAL_PIN);

    if (signal == HIGH) {
        current_time = WATCHDOG_TIMEOUT; 
        Serial.println("Watchdog timer reset via GPIO signal");
    }

    if (current_time > 0) {
        current_time -= 1000;
        Serial.printf("Watchdog timer: %d milliseconds remaining\n", current_time);
    } else {
        resetRaspberryPi();
        current_time = WATCHDOG_TIMEOUT;
    }

    delay(1000); 
}
