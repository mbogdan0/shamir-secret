export const RADIX_BITS = 10;
export const RADIX = 1 << RADIX_BITS;
export const ID_LENGTH_BITS = 15;
export const EXTENDABLE_FLAG_LENGTH_BITS = 1;
export const ITERATION_EXP_LENGTH_BITS = 4;
export const ID_EXP_LENGTH_WORDS = 2;
export const MAX_SHARE_COUNT = 16;
export const CHECKSUM_LENGTH_WORDS = 3;
export const DIGEST_LENGTH_BYTES = 4;
export const CUSTOMIZATION_STRING_ORIG = "shamir";
export const CUSTOMIZATION_STRING_EXTENDABLE = "shamir_extendable";
export const GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1;
export const METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS;
export const MIN_STRENGTH_BITS = 128;
export const MIN_MNEMONIC_LENGTH_WORDS =
  METADATA_LENGTH_WORDS + Math.ceil(MIN_STRENGTH_BITS / RADIX_BITS);
export const BASE_ITERATION_COUNT = 10000;
export const ROUND_COUNT = 4;
export const SECRET_INDEX = 255;
export const DIGEST_INDEX = 254;

export const CHECKSUM_GEN: readonly number[] = [
  0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48,
  0x21b1f890, 0x3f3f120
];
