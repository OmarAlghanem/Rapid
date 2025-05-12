#include <Wire.h>
#include <stdlib.h> // Required for strtoul, malloc, free, strtok, strtol

#define RESET_PIN 18
#define SIGNAL_PIN 23 // GPIO for indicating valid sequence received
#define I2C_SLAVE_ADDR 0x08
#define BUF_SIZE 256 // Reduced buffer size, handshake message is relatively short
#define WATCHDOG_TIMEOUT_MS 15000 // 15 seconds

uint32_t decryption_key = 0;
int *expected_sequence = nullptr;
size_t sequence_length = 0;
size_t current_sequence_index = 0;
unsigned long last_valid_time = 0;
bool handshake_done = false;

// Function to reset the Raspberry Pi
void resetRaspberryPi() {
    Serial.println("Watchdog timeout: Resetting Raspberry Pi...");
    digitalWrite(RESET_PIN, LOW);
    delay(200); // Hold reset longer
    digitalWrite(RESET_PIN, HIGH);
    delay(100);
    Serial.println("Raspberry Pi reset signal sent.");
}

// Parses the handshake message "KEY=key_val;SEQ=num1,num2,..."
int parseHandshakeMessage(char *message) {
    Serial.print("Parsing Handshake: ");
    Serial.println(message);

    char *key_part = strstr(message, "KEY=");
    char *seq_part = strstr(message, "SEQ=");

    if (!key_part || !seq_part) {
        Serial.println("ERROR: Missing KEY or SEQ in handshake message.");
        return -1;
    }

    // Free previous sequence memory if it exists
    if (expected_sequence != nullptr) {
        free(expected_sequence);
        expected_sequence = nullptr;
        sequence_length = 0;
        current_sequence_index = 0; // Reset index too
    }

    // --- Extract Key ---
    key_part += 4; // Move pointer past "KEY="
    char *semi_colon = strchr(key_part, ';');
    if (semi_colon) {
        *semi_colon = '\0'; // Null-terminate the key string
    } else {
        Serial.println("ERROR: Handshake message missing semicolon after KEY.");
        return -1; // Invalid format if no semicolon found
    }
    // Use strtoul for unsigned long (uint32_t)
    char *endptr;
    decryption_key = strtoul(key_part, &endptr, 10);
     if (*endptr != '\0') { // Check if conversion consumed the whole string part
        Serial.println("ERROR: Invalid characters in decryption key.");
        return -1;
    }
    Serial.print("Extracted Key: "); Serial.println(decryption_key);


    seq_part += 4; // Move pointer past "SEQ="
    int count = 1; // Starts at 1 element
    char *temp_ptr = seq_part;
    while (*temp_ptr) {
        if (*temp_ptr == ',') {
            count++;
        }
        temp_ptr++;
    }

    expected_sequence = (int *)malloc(count * sizeof(int));
    if (expected_sequence == nullptr) {
        Serial.println("ERROR: Memory allocation failed for sequence.");
        decryption_key = 0; // Reset key on failure
        return -1;
    }
    sequence_length = count;

    char *token = strtok(seq_part, ",");
    int i = 0;
    while (token != nullptr && i < sequence_length) {
        expected_sequence[i] = strtol(token, &endptr, 10);
         if (*endptr != '\0' && *endptr != '\n' && *endptr != '\r') { // Allow termination chars
            Serial.print("ERROR: Invalid characters in sequence number: "); Serial.println(token);
            free(expected_sequence); // Clean up allocated memory
            expected_sequence = nullptr;
            sequence_length = 0;
            decryption_key = 0;
            return -1;
         }
        Serial.print("Seq["); Serial.print(i); Serial.print("]: "); Serial.println(expected_sequence[i]);
        token = strtok(nullptr, ",");
        i++;
    }

     if (i != sequence_length) {
        Serial.println("ERROR: Parsed token count doesn't match expected sequence length.");
        free(expected_sequence);
        expected_sequence = nullptr;
        sequence_length = 0;
        decryption_key = 0;
        return -1;
     }

    Serial.print("Expected sequence length: "); Serial.println(sequence_length);
    current_sequence_index = 0; // Start sequence from the beginning
    return 0; // Success
}

uint32_t decryptNumber(uint32_t encrypted) {
    // Simple XOR decryption
    return encrypted ^ decryption_key;
}

void receiveEvent(int bytesReceived) {
    char buffer[BUF_SIZE] = {0}; // Initialize buffer to zeros
    int i = 0;

    while (Wire.available() && i < BUF_SIZE - 1) {
        buffer[i++] = Wire.read();
    }
    buffer[i] = '\0'; 

    if (i > 0) {
         Serial.print("I2C Received ("); Serial.print(i); Serial.print(" bytes): ");
         Serial.println(buffer);
    } else {
         Serial.println("I2C Received empty message.");
         return; 
    }


    if (!handshake_done) {
        if (parseHandshakeMessage(buffer) == 0) {
            Serial.print("Handshake successful. Key: "); Serial.println(decryption_key);
            Serial.print("Sequence Length: "); Serial.println(sequence_length);

             Wire.beginTransmission(I2C_SLAVE_ADDR); 
             Wire.write((uint8_t*)"ACK\n", 4); 
             Wire.endTransmission();
             Serial.println("Sent ACK to Pi");

            last_valid_time = millis(); 
            handshake_done = true;
            current_sequence_index = 0; 
        } else {
            Serial.println("Handshake failed or invalid format.");
             Wire.beginTransmission(I2C_SLAVE_ADDR);
             Wire.write((uint8_t*)"NACK\n", 5); 
             Wire.endTransmission();
             Serial.println("Sent NACK to Pi");
        }
    } else {
        uint32_t encrypted_val = 0;
        if (sscanf(buffer, "%lu", &encrypted_val) == 1) { 
            uint32_t decrypted_val = decryptNumber(encrypted_val);
            Serial.print("Decrypted value: "); Serial.println(decrypted_val);

            if (sequence_length > 0 && decrypted_val == expected_sequence[current_sequence_index]) {
                Serial.print("Valid sequence number received: ");
                Serial.print(decrypted_val);
                Serial.print(" (Index "); Serial.print(current_sequence_index); Serial.println(")");

                last_valid_time = millis(); 

                digitalWrite(SIGNAL_PIN, HIGH);
                delay(50); 
                digitalWrite(SIGNAL_PIN, LOW);

                current_sequence_index = (current_sequence_index + 1) % sequence_length;
                 Serial.print("Next expected index: "); Serial.println(current_sequence_index);


            } else {
                Serial.print("Invalid sequence number received. Expected: ");
                if (sequence_length > 0) {
                   Serial.print(expected_sequence[current_sequence_index]);
                } else {
                   Serial.print("N/A (no sequence)");
                }
                Serial.print(", Got (decrypted): "); Serial.println(decrypted_val);
            }
        } else {
            Serial.print("Failed to parse received data as a number: "); Serial.println(buffer);
        }
    }
}

void setup() {
    Serial.begin(115200);
    while (!Serial);
    Serial.println("\nESP32 Watchdog Initializing...");

    pinMode(RESET_PIN, OUTPUT);
    pinMode(SIGNAL_PIN, OUTPUT);
    digitalWrite(RESET_PIN, HIGH); 
    digitalWrite(SIGNAL_PIN, LOW);  

    Wire.begin(I2C_SLAVE_ADDR);   
    Wire.onReceive(receiveEvent); 

    Serial.println("I2C Slave mode initialized on address 0x08");
    Serial.print("Watchdog Timeout: "); Serial.print(WATCHDOG_TIMEOUT_MS); Serial.println(" ms");

    last_valid_time = millis();
    handshake_done = false; 
    expected_sequence = nullptr; 
    sequence_length = 0;
    current_sequence_index = 0;
    decryption_key = 0;

    Serial.println("Setup complete. Waiting for Raspberry Pi handshake...");
}

void loop() {
    if (handshake_done && (millis() - last_valid_time >= WATCHDOG_TIMEOUT_MS)) {
        resetRaspberryPi(); // Timeout occurred, reset the Pi

        Serial.println("Resetting internal state for new handshake.");
        handshake_done = false;
        if (expected_sequence != nullptr) {
            free(expected_sequence); // Free memory from the old sequence
            expected_sequence = nullptr;
        }
        sequence_length = 0;
        current_sequence_index = 0;
        decryption_key = 0; // Reset decryption key

        last_valid_time = millis();
    } else if (!handshake_done && (millis() - last_valid_time >= WATCHDOG_TIMEOUT_MS * 2)) {
         Serial.println("Watchdog check: No handshake yet, resetting check timer.");
    }

    delay(100);
}
