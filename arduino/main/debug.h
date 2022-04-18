#include "WProgram.h"

#ifndef DEBUG_INCLUDED
#define DEBUG_INCLUDED

#ifdef DEBUG

	#define DISPLAY_IF_DEBUG(X) Serial.println(X)
	#define DISPLAY_HEX_IF_DEBUG(X) Serial.println(X, HEX)

#else

	#define DISPLAY_IF_DEBUG(X) do { } while(0) // do nothing avoiding empty statements
	#define DISPLAY_HEX_IF_DEBUG(X) do { } while(0) // do nothing avoiding empty statements

#endif


void debug_dump_hex(byte *buffer, int len);

void debug_hex_loop(byte *data, int start, int end);

#endif
