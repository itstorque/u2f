#include "debug.h"
#include "global_buffers.h"
#include "keys.h"

// encryption libs
#include "src/sha256/sha256.h"
#include "src/uECC/uECC.h"



#ifndef encryption
#define encryption
#include "encryption.h"
#endif

// persistent memory lib
#include <EEPROM.h>

#include "channels.h"

CHANNEL_STATUS channel_status[CHANNEL_COUNT];

#ifndef communication
#define communication
#include "communication.h"
#endif