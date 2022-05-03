#define BUTTON_PIN 10

byte confirm_user_presence() {

  int buttonState = 0;

  int time = millis();

  while (true) {

    DISPLAY_IF_DEBUG("USER PRESENCE LOOP");

    buttonState = digitalRead(BUTTON_PIN);

    DISPLAY_IF_DEBUG(buttonState);

    if (buttonState == HIGH) return 0x01;

    // if (millis() - time > 5000) break;

  }

  return 0x00;

}