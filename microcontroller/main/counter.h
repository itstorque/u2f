#pragma mark - COUNTER
// using EEPROM to keep a counter

int getCounter() {

	unsigned int address = 0;
	unsigned int value;

	EEPROM.get(address, value);

	return value;

}

void setCounter(int value) {

	unsigned int address = 0;

	EEPROM.put(address, value);

}