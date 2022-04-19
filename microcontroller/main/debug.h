#include "WProgram.h"

#ifndef DEBUG_INCLUDED
#define DEBUG_INCLUDED

#ifdef DEBUG

	#define DISPLAY_IF_DEBUG(X) Serial.println(X)
	#define DISPLAY_HEX_IF_DEBUG(X) Serial.println(X, HEX)

	#define DEBUG_DUMP_HEX(buffer, len) \
			for (int i = 0 ; i < len; i++) { \
				if (buffer[i] <= 0xf) DISPLAY_IF_DEBUG(0); \
			 	DISPLAY_HEX_IF_DEBUG(buffer[i]); \
			  DISPLAY_IF_DEBUG(" "); \
			} \
		 	DISPLAY_IF_DEBUG("\n");

	#define DEBUG_HEX_LOOP(data, start, end) \
			for (int i = start; i < end; i++) { Serial.print(data[i], HEX); } \
			DISPLAY_IF_DEBUG("");

#else

	#define DISPLAY_IF_DEBUG(X) do { } while(0) // do nothing avoiding empty statements
	#define DISPLAY_HEX_IF_DEBUG(X) do { } while(0) // do nothing avoiding empty statements

	#define DEBUG_DUMP_HEX(buffer, len) do { } while(0)
	#define DEBUG_HEX_LOOP(data, start, end) do { } while(0)

#endif
#endif
