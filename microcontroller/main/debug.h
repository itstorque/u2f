#ifdef DEBUG

	#define DISPLAY_IF_DEBUG(X) Serial.println(X)
	#define DISPLAY_HEX_IF_DEBUG(X) Serial.println(X, HEX)

	void debug_dump_hex(byte *buffer, int len) {

		for (int i = 0 ; i < len; i++) {

		    if (buffer[i] <= 0xf) {
		       Serial.print(0);
		    }

		    Serial.print(buffer[i], HEX);
		    Serial.print(" ");

		}

		Serial.println();

	}

	void debug_hex_loop(byte *data, int start, int end) {

		for (int i = start; i < end; i++) {
			Serial.print(data[i], HEX);
		}
		DISPLAY_IF_DEBUG("");

	}

#else

	#define DISPLAY_IF_DEBUG(X) do { } while(0) // do nothing avoiding empty statements
	#define DISPLAY_HEX_IF_DEBUG(X) do { } while(0) // do nothing avoiding empty statements

	void debug_dump_hex(byte *buffer, int len) { }
	void debug_hex_loop(byte *data, int start, int end) { }

#endif