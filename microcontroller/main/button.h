#define BUTTON_PIN 12

byte confirm_user_presence() {

  int buttonState = 0;

  int time = millis();

  while (true) {

    buttonState = digitalRead(BUTTON_PIN);

    if (buttonState == HIGH) return 0x01;

    if (millis() - time > 5000) break;

  }

  return 0x00;

}
