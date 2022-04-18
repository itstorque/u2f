#include "debug.h"
#include "global_buffers.h"

// persistent memory lib
#include <EEPROM.h>

// encryption libs
#include "src/sha256/sha256.h"
#include "src/uECC/uECC.h"

#include "channels.h"

CHANNEL_STATUS channel_status[CHANNEL_COUNT];

#ifndef communication
#define communication
#include "communication.h"
#endif
