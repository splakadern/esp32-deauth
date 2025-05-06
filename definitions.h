// Header File: definitions.h
#ifndef DEFINITIONS_H
#define DEFINITIONS_H

// --- Configuration Constants and Defines ---
#define AP_SSID "don't mind me" // SSID for the SoftAP web interface
#define AP_PASS "@suckmydickplease" // Password for the SoftAP web interface (min 8 characters)
#define LED 2             // Define the GPIO pin number for an LED (e.g., built-in LED)
#define SERIAL_DEBUG      // Uncomment this line to enable serial debugging output

#define CHANNEL_MAX 13           // Max Wi-Fi channel to cycle through in "all" mode (1-13 are common)
#define NUM_FRAMES_PER_DEAUTH 16 // Number of deauthentication frames to send per detected packet

#define DEAUTH_TYPE_SINGLE 0 // Define a value representing the single AP attack mode
#define DEAUTH_TYPE_ALL 1    // Define a value representing the all networks attack mode

// --- LED Blink Definitions (if LED is defined) ---
#define DEAUTH_BLINK_TIMES     2 // How many times to blink the LED per deauth event
#define DEAUTH_BLINK_DURATION  20 // Duration of each blink cycle in milliseconds (total time for one on/off cycle)


// --- Debug and Blink Macros ---
// These macros wrap Serial print and LED blink calls, making them conditional
// on SERIAL_DEBUG and LED defines.

// Debugging macros - Check if SERIAL_DEBUG is enabled
#ifdef SERIAL_DEBUG
#define DEBUG_PRINT(...)       Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...)     Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...)      Serial.printf(__VA_ARGS__)
#else
// If SERIAL_DEBUG is NOT defined, the macros expand to nothing
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif

// LED Blink macro - Check if LED pin is defined
#ifdef LED
// If LED is defined, BLINK_LED calls the blink_led function
#define BLINK_LED(num_times, blink_duration) blink_led(num_times, blink_duration)
#else
// If LED is NOT defined, BLINK_LED is defined as an empty macro.
// It MUST take the same arguments as when called elsewhere, even if it does nothing.
#define BLINK_LED(num_times, blink_duration)
#endif

// --- Function Declarations ---
// Declare the blink_led function. Its definition is expected elsewhere (likely in the main .ino or a .cpp file)
// It's declared here because the BLINK_LED macro calls it.
void blink_led(int num_times, int blink_duration);


#endif // DEFINITIONS_H
