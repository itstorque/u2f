#ifndef CHANNEL_SETUP
#define CHANNEL_SETUP

// CHANNELS

#define CHANNEL_COUNT 4

enum CHANNEL_STATE {
	Available, Wait_init, Wait_cont, Timeout, Large
};

struct CHANNEL_STATUS {
	int channel_id;
	enum CHANNEL_STATE state;
	int last_millis;
};

#endif
