#include <Wire.h>

#define RESET_PIN 18
#define SIGNAL_PIN 23
#define I2C_SLAVE_ADDR 0x08
#define BUF_SIZE 1024
#define WATCHDOG_TIMEOUT_MS 15000

uint32_t decryption_key = 0;
int *expected_sequence = nullptr;
size_t sequence_length = 0;
size_t current_sequence_index = 0;
unsigned long last_valid_time = 0;
bool handshake_done = false;

void resetRaspberryPi() {
    Serial.println("Resetting Raspberry Pi...");
    digitalWrite(RESET_PIN, LOW);
    delay(100);
    digitalWrite(RESET_PIN, HIGH);
    delay(100);
}

int parseHandshakeMessage(char *message) {
    Serial.print("Parsing Handshake: ");
    Serial.println(message);
    
    char *key_part = strstr(message, "KEY=");
    char *seq_part = strstr(message, "SEQ=");
    
    if (!key_part || !seq_part) {
        Serial.println("ERROR: Missing KEY or SEQ in handshake");
        return -1;
    }

    // Free previous sequence if any
    free(expected_sequence);
    expected_sequence = nullptr;
    sequence_length = 0;

    // Extract Key
    key_part += 4; // Move past "KEY="
    char *semi = strchr(key_part, ';');
    if (semi) *semi = '\0'; // Terminate key part
    decryption_key = strtoul(key_part, NULL, 10);
    
    // Extract Sequence
    seq_part += 4; // Move past "SEQ="
    int count = 1;
    for (char *p = seq_part; *p; ++p) if (*p == ',') count++;
    
    expected_sequence = (int *)malloc(count * sizeof(int));
    if (!expected_sequence) {
        Serial.println("ERROR: Memory allocation failed");
        return -1;
    }
    
    sequence_length = count;
    char *token = strtok(seq_part, ",");
    for (int i = 0; token && i < count; i++) {
        expected_sequence[i] = strtol(token, NULL, 10);
        token = strtok(NULL, ",");
    }
    
    return 0;
}

uint32_t decryptNumber(uint32_t encrypted) {
    return encrypted ^ decryption_key;
}

void receiveEvent(int bytesReceived) {
    char buffer[BUF_SIZE] = {0};
    int i = 0;
    
    while (Wire.available() && i < BUF_SIZE - 1) {
        buffer[i++] = Wire.read();
    }
    buffer[i] = '\0'; // Null-terminate received data

    Serial.print("Received: ");
    Serial.println(buffer);

    if (!handshake_done) {
        if (parseHandshakeMessage(buffer) == 0) {
            Serial.print("Handshake successful. Key: ");
            Serial.println(decryption_key);
            Wire.write((uint8_t*)"ACK\n", 4);
            last_valid_time = millis();
            handshake_done = true;
        } else {
            Serial.println("Invalid handshake format");
        }
    } else {
        uint32_t encrypted = 0;
        sscanf(buffer, "%u", &encrypted); // Read uint32_t properly
        int decrypted = decryptNumber(encrypted);

        if (current_sequence_index < sequence_length && decrypted == expected_sequence[current_sequence_index]) {
            Serial.print("Valid sequence ");
            Serial.print(current_sequence_index + 1);
            Serial.print("/");
            Serial.println(sequence_length);
            last_valid_time = millis();
            current_sequence_index = (current_sequence_index + 1) % sequence_length;
            
            digitalWrite(SIGNAL_PIN, HIGH);
            delay(100);
            digitalWrite(SIGNAL_PIN, LOW);
        } else {
            Serial.print("Invalid value: ");
            Serial.println(decrypted);
        }
    }
}

void setup() {
    Serial.begin(115200);
    pinMode(RESET_PIN, OUTPUT);
    pinMode(SIGNAL_PIN, OUTPUT);
    digitalWrite(RESET_PIN, HIGH);
    digitalWrite(SIGNAL_PIN, LOW);

    Wire.begin(I2C_SLAVE_ADDR);
    Wire.onReceive(receiveEvent);
    Serial.println("I2C Slave initialized");
}

void loop() {
    if (millis() - last_valid_time >= WATCHDOG_TIMEOUT_MS) {
        resetRaspberryPi();
        // Reset handshake state
        handshake_done = false;
        free(expected_sequence);
        expected_sequence = nullptr;
        sequence_length = 0;
        current_sequence_index = 0;
        decryption_key = 0;
        last_valid_time = millis(); // Reset the timer after handling
    }
    delay(100);
}
