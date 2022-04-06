#include <WebUSB.h>

/**
 * Creating an instance of WebUSBSerial will add an additional USB interface to
 * the device that is marked as vendor-specific (rather than USB CDC-ACM) and
 * is therefore accessible to the browser.
 *
 * The URL here provides a hint to the browser about what page the user should
 * navigate to to interact with the device.
 */
WebUSB WebUSBSerial(1 /* https:// */, "webusb.github.io/arduino/demos/console");

#define Serial WebUSBSerial
#define COMMAND_LENGTH 10

const int ledPin = 13;

int command[COMMAND_LENGTH];

int command_index = 0;

void setup() {
  while (!Serial) {
    ;
  }
  Serial.begin(9600);
  Serial.write("Sketch begins.\r\n> ");
  Serial.flush();
  pinMode(ledPin, OUTPUT);
}

void loop() {
  
  if (Serial && Serial.available()) {
    int b = Serial.read();

    command[command_index] = b;

    if (b==0) {
      // process_command

      Serial.write("\nCOMMAND: ");
      
      for (int i=0; i<=command_index; i++) {
        Serial.write(command[i]);
        command[i] = 0;
      }

      Serial.flush();
      
      command_index = 0;
      
    } else {

      command_index++;
      
    }
    
  }
  
}
