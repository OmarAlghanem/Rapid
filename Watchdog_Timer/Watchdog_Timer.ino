#include <Wire.h>
#include <stdlib.h> // Required for strtoul, malloc, free, strtok, strtol
#include <string.h> // Required for strstr, strtok, strncpy, strlen, strdup, memset
#include <ctype.h>  // Required for isprint

#define RESET_PIN 18
#define SIGNAL_PIN 21 // As per your original
#define I2C_SLAVE_ADDR 0x08
#define BUF_SIZE 1024 // As per your original
#define WATCHDOG_TIMEOUT_MS 15000

uint32_t decryption_key = 0;
int *expected_sequence = nullptr;
size_t sequence_length = 0;
size_t current_sequence_index = 0;
unsigned long last_valid_time = 0;
bool handshake_done = false;

// Buffer for I2C response (ACK/NACK)
char i2c_response_payload[10];
bool i2c_response_ready = false;

void resetRaspberryPi() {
    Serial.println("ESP32 WD: Resetting Raspberry Pi...");
    digitalWrite(RESET_PIN, LOW);
    delay(100); // Original delay
    digitalWrite(RESET_PIN, HIGH);
    delay(100); // Original delay
    Serial.println("ESP32 WD: Pi reset signal sent.");

    // Reset handshake state
    handshake_done = false;
    if (expected_sequence != nullptr) {
        free(expected_sequence);
        expected_sequence = nullptr;
    }
    sequence_length = 0;
    current_sequence_index = 0;
    decryption_key = 0;
    i2c_response_ready = false; // No response ready after reset
    last_valid_time = millis(); // Reset the timer
}

// Parses the handshake message "KEY=key_val;SEQ=num1,num2,..."
// Returns 0 on success, -1 on failure.
int parseHandshakeMessage(char *message_input) { // Renamed to avoid modifying original if passed by value
    Serial.print("ESP32 I2C: Parsing Handshake: '");
    // Print message safely
    for(int i=0; message_input[i] != '\0' && i < BUF_SIZE -1; ++i) {
        if(isprint(message_input[i])) Serial.print(message_input[i]);
        else Serial.print('.'); // Print dot for non-printable
    }
    Serial.println("'");

    // strtok modifies the string, so work on a copy if message_input shouldn't be changed
    // However, the original code passed the buffer directly, implying it can be modified.
    // For safety with strtok, let's ensure it's a modifiable copy if it's not already.
    // The buffer from Wire.read should be modifiable.

    char *key_part_str = strstr(message_input, "KEY=");
    char *seq_part_str = strstr(message_input, "SEQ=");

    if (!key_part_str || !seq_part_str) {
        Serial.println("ESP32 I2C ERROR: Missing KEY or SEQ in handshake string.");
        return -1;
    }
    Serial.println("ESP32 I2C DEBUG: Found KEY= and SEQ= markers.");

    // Free previous sequence if any
    if (expected_sequence != nullptr) {
        Serial.println("ESP32 I2C DEBUG: Freeing previous expected_sequence.");
        free(expected_sequence);
        expected_sequence = nullptr;
    }
    sequence_length = 0; // Reset these too
    current_sequence_index = 0;


    // Extract Key
    key_part_str += 4; // Move past "KEY="
    char *semi_colon_ptr = strchr(key_part_str, ';');
    if (semi_colon_ptr) {
        *semi_colon_ptr = '\0'; // Terminate key part
        Serial.print("ESP32 I2C DEBUG: Key part for strtoul: '"); Serial.print(key_part_str); Serial.println("'");
    } else {
        Serial.println("ESP32 I2C ERROR: No semicolon after KEY in handshake.");
        return -1; // Invalid format if no semicolon
    }
    
    char *endptr_key;
    decryption_key = strtoul(key_part_str, &endptr_key, 10);
    if (*endptr_key != '\0') { // Check if conversion consumed the whole key part
        Serial.print("ESP32 I2C ERROR: Invalid characters in decryption key. Remainder: '"); Serial.print(endptr_key); Serial.println("'");
        decryption_key = 0; // Reset on error
        return -1;
    }
    Serial.print("ESP32 I2C: Extracted Key: "); Serial.println(decryption_key);

    // Extract Sequence
    // seq_part_str was based on original message_input. If message_input was modified by strtok for key, re-find SEQ.
    // Better: use the pointer from after the semicolon.
    seq_part_str = semi_colon_ptr + 1; // Start after the null-terminated key
    seq_part_str = strstr(seq_part_str, "SEQ="); // Find SEQ= in the rest of the string
    if (!seq_part_str) {
        Serial.println("ESP32 I2C ERROR: SEQ= not found after KEY= part.");
        decryption_key = 0; // Reset key on error
        return -1;
    }
    seq_part_str += 4; // Move past "SEQ="
    Serial.print("ESP32 I2C DEBUG: Sequence part for tokenizing: '"); Serial.print(seq_part_str); Serial.println("'");

    // Count numbers in sequence to allocate memory
    int count = 0;
    char *temp_seq_for_counting = strdup(seq_part_str); // Use strdup for counting to not alter seq_part_str before final tokenizing
    if (temp_seq_for_counting == NULL) {
        Serial.println("ESP32 I2C ERROR: strdup failed for sequence counting.");
        decryption_key = 0; return -1;
    }
    char *token_counter = strtok(temp_seq_for_counting, ",");
    while (token_counter != NULL) {
        count++;
        token_counter = strtok(NULL, ",");
    }
    free(temp_seq_for_counting);

    if (count == 0) {
        Serial.println("ESP32 I2C ERROR: No numbers found in sequence part.");
        decryption_key = 0; return -1;
    }
    Serial.print("ESP32 I2C: Expecting sequence of length: "); Serial.println(count);

    expected_sequence = (int *)malloc(count * sizeof(int));
    if (!expected_sequence) {
        Serial.println("ESP32 I2C ERROR: Memory allocation failed for sequence array.");
        decryption_key = 0; // Reset key
        return -1;
    }
    
    sequence_length = count;
    char *token = strtok(seq_part_str, ","); // Now tokenize the original seq_part_str
    char *endptr_seq_num;
    for (int i = 0; token != NULL && i < count; i++) {
        Serial.print("ESP32 I2C DEBUG: Tokenizing SEQ value: '"); Serial.print(token); Serial.println("'");
        expected_sequence[i] = strtol(token, &endptr_seq_num, 10);
        if (*endptr_seq_num != '\0' && *endptr_seq_num != '\n' && *endptr_seq_num != '\r') { // Allow trailing newline/cr from message
            Serial.print("ESP32 I2C ERROR: Invalid characters in sequence number token: '"); Serial.print(token); 
            Serial.print("'. Remainder: '"); Serial.print(endptr_seq_num); Serial.println("'");
            free(expected_sequence); expected_sequence = nullptr;
            sequence_length = 0; decryption_key = 0;
            return -1;
        }
        Serial.print("ESP32 I2C: Parsed Seq["); Serial.print(i); Serial.print("]: "); Serial.println(expected_sequence[i]);
        token = strtok(NULL, ",");
    }
    // Check if we got the right number of tokens
    if (token != NULL || (token == NULL && sequence_length != count && count !=0) ) { // If token is not null, means more tokens than expected or parsing stopped early
         Serial.println("ESP32 I2C ERROR: Mismatch in parsed sequence numbers and expected count.");
         free(expected_sequence); expected_sequence = nullptr;
         sequence_length = 0; decryption_key = 0;
         return -1;
    }

    current_sequence_index = 0; // Reset for the new sequence
    Serial.println("ESP32 I2C: Handshake message parsed successfully.");
    return 0;
}

uint32_t decryptNumber(uint32_t encrypted) {
    return encrypted ^ decryption_key;
}

void receiveEvent(int bytesReceived) {
    char buffer[BUF_SIZE] = {0};
    int i = 0;
    Serial.print("ESP32 I2C: receiveEvent (bytes:"); Serial.print(bytesReceived); Serial.println(")");

    // Critical: Reset response state for this new transaction
    i2c_response_ready = false;
    memset(i2c_response_payload, 0, sizeof(i2c_response_payload));

    while (Wire.available() && i < BUF_SIZE - 1) {
        buffer[i++] = Wire.read();
    }
    buffer[i] = '\0'; 

    Serial.print("ESP32 I2C: Received raw data: '");
    for(int j=0; j<i; ++j) {
        if(isprint(buffer[j])) Serial.print(buffer[j]); else { Serial.print("\\x"); Serial.print(buffer[j], HEX); }
    }
    Serial.println("'");

    if (i == 0) { // No actual data bytes received
        Serial.println("ESP32 I2C: Received empty message.");
        if (!handshake_done) { // If handshake not done, an empty message is an error for KEY/SEQ
            strncpy(i2c_response_payload, "NACK\n", sizeof(i2c_response_payload) -1);
            i2c_response_payload[sizeof(i2c_response_payload)-1] = '\0'; // Ensure null termination
            i2c_response_ready = true;
            Serial.println("ESP32 I2C: Prepared NACK (empty message during handshake).");
        }
        return;
    }

    if (!handshake_done) {
        if (parseHandshakeMessage(buffer) == 0) {
            // Response payload and flag are set *before* extensive Serial.prints
            strncpy(i2c_response_payload, "ACK\n", sizeof(i2c_response_payload)-1);
            i2c_response_payload[sizeof(i2c_response_payload)-1] = '\0';
            i2c_response_ready = true; 
            Serial.print("ESP32 I2C: Handshake successful. Key: "); Serial.println(decryption_key);
            Serial.println("ESP32 I2C: Prepared ACK for Pi.");
            last_valid_time = millis();
            handshake_done = true;
        } else {
            strncpy(i2c_response_payload, "NACK\n", sizeof(i2c_response_payload)-1);
            i2c_response_payload[sizeof(i2c_response_payload)-1] = '\0';
            i2c_response_ready = true;
            Serial.println("ESP32 I2C: Invalid handshake format. Prepared NACK for Pi.");
        }
    } else { // handshake_done is true, expecting encrypted numbers
        uint32_t encrypted_val = 0;
        // sscanf expects a null-terminated string. buffer is.
        if (sscanf(buffer, "%u", &encrypted_val) == 1) { 
            int decrypted_val = decryptNumber(encrypted_val); // Original used int, stick to it for now
            Serial.print("ESP32 I2C: Received encrypted: "); Serial.print(encrypted_val);
            Serial.print(", Decrypted: "); Serial.println(decrypted_val);

            if (expected_sequence != nullptr && current_sequence_index < sequence_length && decrypted_val == expected_sequence[current_sequence_index]) {
                Serial.print("ESP32 I2C: Valid sequence "); Serial.print(current_sequence_index + 1);
                Serial.print("/"); Serial.println(sequence_length);
                last_valid_time = millis();
                current_sequence_index = (current_sequence_index + 1) % sequence_length;
                digitalWrite(SIGNAL_PIN, HIGH); delay(100); digitalWrite(SIGNAL_PIN, LOW);
            } else {
                Serial.print("ESP32 I2C: Invalid value. Expected: ");
                if(expected_sequence != nullptr && current_sequence_index < sequence_length) Serial.print(expected_sequence[current_sequence_index]);
                else Serial.print("N/A");
                Serial.print(", Got (decrypted): "); Serial.println(decrypted_val);
            }
        } else {
            Serial.print("ESP32 I2C WARNING: Failed to parse as number post-handshake: '"); Serial.print(buffer); Serial.println("'");
        }
        // Note: The original ESP32 code did not prepare an ACK/NACK for sequence numbers.
        // The Pi client also doesn't seem to expect one after sending an encrypted number.
        // So, i2c_response_ready remains false here unless explicitly set.
    }
}

// Called when Master requests data from this slave
void requestEvent() {
    Serial.println("ESP32 I2C: requestEvent triggered.");
    if (i2c_response_ready) {
        Wire.write((const uint8_t*)i2c_response_payload, strlen(i2c_response_payload));
        Serial.print("ESP32 I2C: Sent to Pi via onRequest: '");
        for(size_t k=0; k < strlen(i2c_response_payload); ++k) { // Print without internal newline for cleaner log
            if(isprint(i2c_response_payload[k])) Serial.print(i2c_response_payload[k]);
        }
        Serial.println("'");
        i2c_response_ready = false; // Reset flag after sending
    } else {
        Serial.println("ESP32 I2C WARNING: onRequest called, but no response was prepared.");
        // Optionally send a default "empty" or "waiting" response if master expects something
        // Wire.write((const uint8_t*)"WAIT\n", 5);
    }
}

void setup() {
    Serial.begin(115200);
    unsigned long setupStartTime = millis();
    while (!Serial && (millis() - setupStartTime < 2000)); // Wait max 2s for serial
    Serial.println("\nESP32 Watchdog Initializing (Original Base Fixed)...");

    pinMode(RESET_PIN, OUTPUT);
    pinMode(SIGNAL_PIN, OUTPUT);
    digitalWrite(RESET_PIN, HIGH); // Pi not in reset
    digitalWrite(SIGNAL_PIN, LOW);  // Signal off

    Wire.begin(I2C_SLAVE_ADDR);
    Wire.onReceive(receiveEvent);
    Wire.onRequest(requestEvent); // Register the request handler

    Serial.print("ESP32 I2C: Slave mode initialized on address 0x"); Serial.println(I2C_SLAVE_ADDR, HEX);
    Serial.print("ESP32 Watchdog: Timeout set to "); Serial.print(WATCHDOG_TIMEOUT_MS); Serial.println(" ms");
    
    last_valid_time = millis(); // Initialize watchdog timer
    Serial.println("ESP32 Setup complete. Waiting for Raspberry Pi handshake data via I2C...");
}

void loop() {
    if (handshake_done && (millis() - last_valid_time >= WATCHDOG_TIMEOUT_MS)) {
        resetRaspberryPi();
    } else if (!handshake_done && (millis() - last_valid_time >= WATCHDOG_TIMEOUT_MS * 2)) {
        // If handshake never completes, this provides a periodic log message.
        // The Pi is responsible for initiating the handshake.
        Serial.println("ESP32 Watchdog: Still no handshake from Pi. Resetting initial check timer.");
        last_valid_time = millis(); 
    }
    delay(100);
}
