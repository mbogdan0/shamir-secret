import { decrypt, encrypt, randomIdentifier } from "./cipher.ts";
import {
  GROUP_PREFIX_LENGTH_WORDS,
  ID_EXP_LENGTH_WORDS,
  MAX_RECOVERY_CANDIDATE_COMBINATIONS,
  MAX_RECOVERY_INPUT_LINES
} from "./constants.ts";
import { Slip39Error } from "./errors.ts";
import type { RawShare } from "./gf256.ts";
import { recoverSecret, splitSecret } from "./secret-sharing.ts";
import { Share } from "./share.ts";
import { zeroize } from "./utils.ts";
import {
  validateIdentifier,
  validateIterationExponent,
  validateMasterSecretBytes,
  validatePassphrase,
  validateSingleGroupParameters
} from "./validation.ts";

export type EncryptedMasterSecret = {
  identifier: number;
  extendable: boolean;
  iterationExponent: number;
  ciphertext: Uint8Array;
};

export type GenerateOptions = {
  identifier?: number;
  extendable?: boolean;
  iterationExponent?: number;
};

type FlexibleShareEntry = { mnemonic: string; share: Share };

type FlexibleGroup = {
  groupKey: string;
  sharesByMemberIndex: Map<number, FlexibleShareEntry>;
};

class ShareGroup {
  shares: Map<number, Share> = new Map();
  groupKeyValue: string | null = null;

  add(share: Share): void {
    if (this.groupKeyValue && this.groupKeyValue !== share.groupKey()) {
      throw new Slip39Error("Invalid set of mnemonics. Group parameters do not match.");
    }
    if (this.shares.has(share.index)) {
      throw new Slip39Error("Invalid set of mnemonics. Member share indices must be unique.");
    }
    this.groupKeyValue = share.groupKey();
    this.shares.set(share.index, share);
  }

  first(): Share {
    const share = this.shares.values().next().value;
    if (!share) {
      throw new Slip39Error("The share group is empty.");
    }
    return share;
  }

  memberThreshold(): number {
    return this.first().memberThreshold;
  }

  rawShares(): RawShare[] {
    return [...this.shares.values()].map((share) => ({ x: share.index, data: share.value }));
  }
}

function decodeMnemonics(mnemonics: string[]): Map<number, ShareGroup> {
  const groups: Map<number, ShareGroup> = new Map();
  let commonKey: string | null = null;
  let decodedCount = 0;

  for (const mnemonic of mnemonics) {
    if (!mnemonic.trim()) {
      continue;
    }
    const share = Share.fromMnemonic(mnemonic);
    decodedCount += 1;
    if (commonKey && commonKey !== share.commonKey()) {
      throw new Slip39Error(
        `Invalid set of mnemonics. All mnemonics must begin with the same ${ID_EXP_LENGTH_WORDS} words and use the same group policy.`
      );
    }
    commonKey = share.commonKey();
    if (!groups.has(share.groupIndex)) {
      groups.set(share.groupIndex, new ShareGroup());
    }
    const group = groups.get(share.groupIndex);
    if (!group) {
      throw new Slip39Error("Invalid mnemonic group state.");
    }
    group.add(share);
  }

  if (decodedCount === 0) {
    throw new Slip39Error("The list of mnemonics is empty.");
  }

  return groups;
}

async function recoverEms(groups: Map<number, ShareGroup>): Promise<EncryptedMasterSecret> {
  if (groups.size === 0) {
    throw new Slip39Error("The set of shares is empty.");
  }

  const firstGroup = groups.values().next().value;
  if (!firstGroup) {
    throw new Slip39Error("The set of shares is empty.");
  }
  const params = firstGroup.first();

  if (groups.size < params.groupThreshold) {
    throw new Slip39Error(
      `Insufficient number of mnemonic groups. Required groups: ${params.groupThreshold}.`
    );
  }
  if (groups.size !== params.groupThreshold) {
    throw new Slip39Error(
      `Wrong number of mnemonic groups. Expected ${params.groupThreshold}, got ${groups.size}.`
    );
  }

  const groupShares: RawShare[] = [];
  for (const [groupIndex, group] of groups) {
    const memberThreshold = group.memberThreshold();
    if (group.shares.size !== memberThreshold) {
      const prefix = group.first().words().slice(0, GROUP_PREFIX_LENGTH_WORDS).join(" ");
      throw new Slip39Error(
        `Wrong number of mnemonics. Expected ${memberThreshold} shares starting with "${prefix} ...", got ${group.shares.size}.`
      );
    }
    groupShares.push({
      x: groupIndex,
      data: await recoverSecret(memberThreshold, group.rawShares())
    });
  }

  return {
    identifier: params.identifier,
    extendable: params.extendable,
    iterationExponent: params.iterationExponent,
    ciphertext: await recoverSecret(params.groupThreshold, groupShares)
  };
}

export async function generateMnemonics(
  threshold: number,
  shareCount: number,
  masterSecret: Uint8Array,
  passphrase: string = "",
  options: GenerateOptions = {}
): Promise<string[]> {
  validateSingleGroupParameters(threshold, shareCount);
  validateMasterSecretBytes(masterSecret);
  const passphraseBytes = validatePassphrase(passphrase);
  const iterationExponent = options.iterationExponent ?? 1;
  validateIterationExponent(iterationExponent);
  const extendable = options.extendable ?? true;
  const identifier = options.identifier ?? randomIdentifier();
  validateIdentifier(identifier);

  let encryptedMasterSecret: Uint8Array | undefined;
  try {
    encryptedMasterSecret = await encrypt(
      masterSecret,
      passphraseBytes,
      iterationExponent,
      identifier,
      extendable
    );
    const groupShares = await splitSecret(1, 1, encryptedMasterSecret);
    const memberShares = await splitSecret(threshold, shareCount, groupShares[0].data);

    return memberShares.map((share) =>
      new Share(
        identifier,
        extendable,
        iterationExponent,
        0,
        1,
        1,
        share.x,
        threshold,
        share.data
      ).toMnemonic()
    );
  } finally {
    zeroize(passphraseBytes, encryptedMasterSecret);
  }
}

export async function combineMnemonics(
  mnemonics: string[],
  passphrase: string = ""
): Promise<Uint8Array> {
  const passphraseBytes = validatePassphrase(passphrase);
  try {
    const groups = decodeMnemonics(mnemonics);
    const encryptedMasterSecret = await recoverEms(groups);
    return await decrypt(
      encryptedMasterSecret.ciphertext,
      passphraseBytes,
      encryptedMasterSecret.iterationExponent,
      encryptedMasterSecret.identifier,
      encryptedMasterSecret.extendable
    );
  } finally {
    zeroize(passphraseBytes);
  }
}

function* combinations<T>(items: T[], size: number): Generator<T[]> {
  if (size < 0 || size > items.length) {
    return;
  }
  if (size === 0) {
    yield [];
    return;
  }

  const current: T[] = [];

  function* visit(start: number): Generator<T[]> {
    if (current.length === size) {
      yield [...current];
      return;
    }

    const remaining = size - current.length;
    for (let index = start; index <= items.length - remaining; index += 1) {
      current.push(items[index]);
      yield* visit(index + 1);
      current.pop();
    }
  }

  yield* visit(0);
}

function* candidateMemberSets(
  groups: Array<{ memberThreshold: number; shares: FlexibleShareEntry[] }>,
  index: number = 0,
  current: string[][] = []
): Generator<string[][]> {
  if (index === groups.length) {
    yield current.map((candidate) => [...candidate]);
    return;
  }

  const group = groups[index];
  for (const candidate of combinations(group.shares, group.memberThreshold)) {
    current.push(candidate.map((entry) => entry.mnemonic));
    yield* candidateMemberSets(groups, index + 1, current);
    current.pop();
  }
}

function parseFlexibleMnemonics(mnemonics: string[]): Map<number, FlexibleGroup> {
  const groups: Map<number, FlexibleGroup> = new Map();
  const seenMnemonics: Set<string> = new Set();
  let commonKey: string | null = null;
  let decodedCount = 0;
  const inputLines = mnemonics.filter((mnemonic) => mnemonic.trim()).length;

  if (inputLines > MAX_RECOVERY_INPUT_LINES) {
    throw new Slip39Error(`Too many mnemonic share lines. Maximum is ${MAX_RECOVERY_INPUT_LINES}.`);
  }

  for (const mnemonic of mnemonics) {
    if (!mnemonic.trim()) {
      continue;
    }

    const share = Share.fromMnemonic(mnemonic);
    const canonicalMnemonic = share.toMnemonic();
    if (seenMnemonics.has(canonicalMnemonic)) {
      continue;
    }
    seenMnemonics.add(canonicalMnemonic);
    decodedCount += 1;

    if (commonKey && commonKey !== share.commonKey()) {
      throw new Slip39Error(
        `Invalid set of mnemonics. All mnemonics must begin with the same ${ID_EXP_LENGTH_WORDS} words and use the same group policy.`
      );
    }
    commonKey = share.commonKey();

    if (!groups.has(share.groupIndex)) {
      groups.set(share.groupIndex, {
        groupKey: share.groupKey(),
        sharesByMemberIndex: new Map()
      });
    }

    const group = groups.get(share.groupIndex);
    if (!group) {
      throw new Slip39Error("Invalid mnemonic group state.");
    }
    if (group.groupKey !== share.groupKey()) {
      throw new Slip39Error("Invalid set of mnemonics. Group parameters do not match.");
    }

    const existing = group.sharesByMemberIndex.get(share.index);
    if (existing) {
      if (existing.mnemonic !== canonicalMnemonic) {
        throw new Slip39Error(
          `Conflicting mnemonic shares for group ${share.groupIndex + 1}, member ${share.index + 1}.`
        );
      }
      continue;
    }

    group.sharesByMemberIndex.set(share.index, {
      mnemonic: canonicalMnemonic,
      share
    });
  }

  if (decodedCount === 0) {
    throw new Slip39Error("The list of mnemonics is empty.");
  }

  return groups;
}

export async function combineMnemonicsFlexible(
  mnemonics: string[],
  passphrase: string = ""
): Promise<Uint8Array> {
  const groups = parseFlexibleMnemonics(mnemonics);
  const firstGroup = groups.values().next().value;
  if (!firstGroup) {
    throw new Slip39Error("The list of mnemonics is empty.");
  }
  const firstEntry = firstGroup.sharesByMemberIndex.values().next().value;
  if (!firstEntry) {
    throw new Slip39Error("The list of mnemonics is empty.");
  }
  const firstShare = firstEntry.share;
  const groupThreshold = firstShare.groupThreshold;
  const completeGroups = [...groups.entries()]
    .map(([, group]) => {
      const firstMemberEntry = group.sharesByMemberIndex.values().next().value;
      if (!firstMemberEntry) {
        throw new Slip39Error("Invalid mnemonic group state.");
      }
      const memberThreshold = firstMemberEntry.share.memberThreshold;
      const shares = [...group.sharesByMemberIndex.values()];
      return {
        memberThreshold,
        shares
      };
    })
    .filter((group) => group.shares.length >= group.memberThreshold);

  if (completeGroups.length < groupThreshold) {
    throw new Slip39Error(
      `Insufficient number of mnemonic groups. Required groups: ${groupThreshold}.`
    );
  }

  const errorCounts = new Map<string, number>();
  let attemptCount = 0;
  for (const groupSet of combinations(completeGroups, groupThreshold)) {
    for (const memberCombinationSet of candidateMemberSets(groupSet)) {
      if (attemptCount >= MAX_RECOVERY_CANDIDATE_COMBINATIONS) {
        throw new Slip39Error("Too many candidate combinations.");
      }
      attemptCount += 1;
      const candidateMnemonics = memberCombinationSet.flat();
      try {
        return await combineMnemonics(candidateMnemonics, passphrase);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        errorCounts.set(message, (errorCounts.get(message) ?? 0) + 1);
      }
    }
  }

  if (errorCounts.size === 0) {
    throw new Slip39Error("No valid threshold-complete mnemonic subset was found.");
  }
  if (errorCounts.size === 1) {
    const onlyMessage =
      [...errorCounts.keys()][0] ?? "No valid threshold-complete mnemonic subset was found.";
    throw new Slip39Error(onlyMessage);
  }
  const ranked = [...errorCounts.entries()].sort((a, b) => b[1] - a[1]);
  const summary = ranked.map(([message, count]) => `  - ${message} (x${count} times)`).join("\n");
  throw new Slip39Error(
    `No valid threshold-complete mnemonic subset was found.\nTried ${attemptCount} combinations. Most common errors:\n${summary}`
  );
}
