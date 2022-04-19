#pragma mark - u2f raw message format header from
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f.h
// TODO: move into a separate header file too

// U2F native commands

#define U2F_REGISTER            0x01    // Registration command
#define U2F_AUTHENTICATE        0x02    // Authenticate/sign command
#define U2F_VERSION             0x03    // Read version string command

#define U2F_VENDOR_FIRST        0x40    // First vendor defined command
#define U2F_VENDOR_LAST         0xbf    // Last vendor defined command

// U2F_CMD_REGISTER command defines

#define U2F_REGISTER_ID         0x05    // Version 2 registration identifier
#define U2F_REGISTER_HASH_ID    0x00    // Version 2 hash identintifier

// Authentication control byte

#define U2F_AUTH_ENFORCE        0x03    // Enforce user presence and sign
#define U2F_AUTH_CHECK_ONLY     0x07    // Check only
#define U2F_AUTH_FLAG_TUP       0x01    // Test of user presence set

// Command status responses

#define U2F_SW_NO_ERROR                 0x9000 // SW_NO_ERROR
#define U2F_SW_WRONG_DATA               0x6A80 // SW_WRONG_DATA
#define U2F_SW_CONDITIONS_NOT_SATISFIED 0x6985 // SW_CONDITIONS_NOT_SATISFIED
#define U2F_SW_COMMAND_NOT_ALLOWED      0x6986 // SW_COMMAND_NOT_ALLOWED
#define U2F_SW_INS_NOT_SUPPORTED        0x6D00 // SW_INS_NOT_SUPPORTED

#pragma mark - Command status responses
// Sourced from ISO-7816
#define SW_NO_ERROR                       0x9000
#define SW_CONDITIONS_NOT_SATISFIED       0x6985
#define SW_WRONG_DATA                     0x6A80
#define SW_WRONG_LENGTH                   0x6700
#define SW_INS_NOT_SUPPORTED              0x6D00
#define SW_CLA_NOT_SUPPORTED              0x6E00

#define ADD_SW_OK(x) do { (*x++)=0x90; (*x++)=0x00;} while (0)
