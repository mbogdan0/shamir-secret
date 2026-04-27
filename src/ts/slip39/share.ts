import {
  CHECKSUM_LENGTH_WORDS,
  EXTENDABLE_FLAG_LENGTH_BITS,
  ID_EXP_LENGTH_WORDS,
  ITERATION_EXP_LENGTH_BITS,
  METADATA_LENGTH_WORDS,
  MIN_MNEMONIC_LENGTH_WORDS,
  RADIX_BITS
} from "./constants.ts";
import { createChecksum, customizationString, verifyChecksum } from "./checksum.ts";
import { Slip39Error } from "./errors.ts";
import {
  bigIntToBytes,
  bitsToBytes,
  bitsToWords,
  bytesToIndices,
  indicesToWords,
  intFromIndices,
  intToIndices,
  mnemonicToIndices
} from "./utils.ts";

export class Share {
  identifier: number;
  extendable: boolean;
  iterationExponent: number;
  groupIndex: number;
  groupThreshold: number;
  groupCount: number;
  index: number;
  memberThreshold: number;
  value: Uint8Array;

  constructor(
    identifier: number,
    extendable: boolean,
    iterationExponent: number,
    groupIndex: number,
    groupThreshold: number,
    groupCount: number,
    index: number,
    memberThreshold: number,
    value: Uint8Array
  ) {
    this.identifier = identifier;
    this.extendable = extendable;
    this.iterationExponent = iterationExponent;
    this.groupIndex = groupIndex;
    this.groupThreshold = groupThreshold;
    this.groupCount = groupCount;
    this.index = index;
    this.memberThreshold = memberThreshold;
    this.value = new Uint8Array(value);
  }

  commonKey(): string {
    return [
      this.identifier,
      Number(this.extendable),
      this.iterationExponent,
      this.groupThreshold,
      this.groupCount
    ].join(":");
  }

  groupKey(): string {
    return [
      this.identifier,
      Number(this.extendable),
      this.iterationExponent,
      this.groupIndex,
      this.groupThreshold,
      this.groupCount,
      this.memberThreshold
    ].join(":");
  }

  encodeIdExp(): number[] {
    const value =
      (BigInt(this.identifier) << 5n) |
      (BigInt(this.extendable ? 1 : 0) << 4n) |
      BigInt(this.iterationExponent);
    return intToIndices(value, ID_EXP_LENGTH_WORDS);
  }

  encodeShareParams(): number[] {
    let value = BigInt(this.groupIndex);
    value = (value << 4n) | BigInt(this.groupThreshold - 1);
    value = (value << 4n) | BigInt(this.groupCount - 1);
    value = (value << 4n) | BigInt(this.index);
    value = (value << 4n) | BigInt(this.memberThreshold - 1);
    return intToIndices(value, 2);
  }

  words(): string[] {
    const valueWordCount = bitsToWords(this.value.length * 8);
    const shareData = [
      ...this.encodeIdExp(),
      ...this.encodeShareParams(),
      ...bytesToIndices(this.value, valueWordCount)
    ];
    const checksum = createChecksum(shareData, customizationString(this.extendable));
    return indicesToWords([...shareData, ...checksum]);
  }

  toMnemonic(): string {
    return this.words().join(" ");
  }

  static fromMnemonic(mnemonic: string): Share {
    const mnemonicData = mnemonicToIndices(mnemonic);

    if (mnemonicData.length < MIN_MNEMONIC_LENGTH_WORDS) {
      throw new Slip39Error(
        `Invalid mnemonic length. Each mnemonic must be at least ${MIN_MNEMONIC_LENGTH_WORDS} words.`
      );
    }

    const paddingLength = (RADIX_BITS * (mnemonicData.length - METADATA_LENGTH_WORDS)) % 16;
    if (paddingLength > 8) {
      throw new Slip39Error("Invalid mnemonic length.");
    }

    const idExpData = mnemonicData.slice(0, ID_EXP_LENGTH_WORDS);
    const idExpInt = Number(intFromIndices(idExpData));
    const identifier = idExpInt >> (EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS);
    const extendable = Boolean((idExpInt >> ITERATION_EXP_LENGTH_BITS) & 1);
    const iterationExponent = idExpInt & ((1 << ITERATION_EXP_LENGTH_BITS) - 1);

    if (!verifyChecksum(mnemonicData, customizationString(extendable))) {
      const prefix = mnemonic
        .trim()
        .split(/\s+/)
        .slice(0, ID_EXP_LENGTH_WORDS + 2)
        .join(" ");
      throw new Slip39Error(`Invalid mnemonic checksum for "${prefix} ...".`);
    }

    const shareParamsData = mnemonicData.slice(ID_EXP_LENGTH_WORDS, ID_EXP_LENGTH_WORDS + 2);
    const shareParams = intToIndices(intFromIndices(shareParamsData), 5, 4);
    const [groupIndex, encodedGroupThreshold, encodedGroupCount, index, encodedMemberThreshold] =
      shareParams;

    if (encodedGroupCount < encodedGroupThreshold) {
      throw new Slip39Error("Group threshold cannot be greater than group count.");
    }
    if (groupIndex > encodedGroupCount) {
      throw new Slip39Error("Group index cannot be greater than or equal to group count.");
    }

    const valueData = mnemonicData.slice(ID_EXP_LENGTH_WORDS + 2, -CHECKSUM_LENGTH_WORDS);
    const valueBitCount = RADIX_BITS * valueData.length - paddingLength;
    const valueByteCount = bitsToBytes(valueBitCount);
    const value = bigIntToBytes(intFromIndices(valueData), valueByteCount);

    return new Share(
      identifier,
      extendable,
      iterationExponent,
      groupIndex,
      encodedGroupThreshold + 1,
      encodedGroupCount + 1,
      index,
      encodedMemberThreshold + 1,
      value
    );
  }
}
