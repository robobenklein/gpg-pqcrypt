#include "params.h"
#include "gf.h"

#define NB_ERRORS ERROR_WEIGHT
#define EXT_DEGREE LOG_LENGTH

#define LENGTH (1 << EXT_DEGREE)
#define CODIMENSION (NB_ERRORS * EXT_DEGREE)
#define DIMENSION (LENGTH - CODIMENSION)

// number of bytes needed for storing nb_bits bits
#define BITS_TO_BYTES(nb_bits) (((nb_bits) - 1) / 8 + 1)
// number bits in one long
#define BIT_SIZE_OF_LONG (8 * sizeof(long))
// number of long needed for storing nb_bits bits
#define BITS_TO_LONG(nb_bits) (((nb_bits) - 1) / BIT_SIZE_OF_LONG + 1)

#define SECRETKEY_BYTES (LENGTH * sizeof (long) * BITS_TO_LONG(CODIMENSION) + (LENGTH + 1 + (NB_ERRORS + 1) * NB_ERRORS) * sizeof (gf_t))
#define PUBLICKEY_BYTES (BITS_TO_LONG(CODIMENSION) * sizeof(long) * DIMENSION)

#define CLEARTEXT_LENGTH (DIMENSION + ERROR_SIZE)

#define CLEARTEXT_BYTES BITS_TO_BYTES(CLEARTEXT_LENGTH)

#define CIPHERTEXT_BYTES BITS_TO_BYTES(LENGTH)

// CLEARTEXT_BYTES is the number of bytes of the block to be encrypted
// (= CLEARTEXT_LENGTH / 8 rounded up)
// MESSAGE_BYTES is the number of information bytes in each block
// (= CLEARTEXT_LENGTH / 8 rounded down possibly one less than
// CLEARTEXT_BYTES)
// To add a semantically secure conversion, one can reduce
// MESSAGE_BYTES accordingly and add a randomization layer before
// encryption (and after decryption)
#define MESSAGE_BYTES (CLEARTEXT_LENGTH / 8)
