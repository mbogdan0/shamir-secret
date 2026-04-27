import { decrypt, encrypt, randomIdentifier } from "./cipher.js";
import { GROUP_PREFIX_LENGTH_WORDS, ID_EXP_LENGTH_WORDS } from "./constants.js";
import { Slip39Error } from "./errors.js";
import { recoverSecret, splitSecret } from "./secret-sharing.js";
import { Share } from "./share.js";
import { zeroize } from "./utils.js";
import {
  validateIdentifier,
  validateIterationExponent,
  validateMasterSecretBytes,
  validatePassphrase,
  validateSingleGroupParameters
} from "./validation.js";

class ShareGroup {
  constructor() {
    this.shares = new Map();
    this.groupKeyValue = null;
  }

  add(share) {
    if (this.groupKeyValue && this.groupKeyValue !== share.groupKey()) {
      throw new Slip39Error("Invalid set of mnemonics. Group parameters do not match.");
    }
    if (this.shares.has(share.index)) {
      throw new Slip39Error("Invalid set of mnemonics. Member share indices must be unique.");
    }
    this.groupKeyValue = share.groupKey();
    this.shares.set(share.index, share);
  }

  first() {
    return this.shares.values().next().value;
  }

  memberThreshold() {
    return this.first().memberThreshold;
  }

  rawShares() {
    return [...this.shares.values()].map((share) => ({ x: share.index, data: share.value }));
  }
}

function decodeMnemonics(mnemonics) {
  const groups = new Map();
  let commonKey = null;
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
    groups.get(share.groupIndex).add(share);
  }

  if (decodedCount === 0) {
    throw new Slip39Error("The list of mnemonics is empty.");
  }

  return groups;
}

async function recoverEms(groups) {
  if (groups.size === 0) {
    throw new Slip39Error("The set of shares is empty.");
  }

  const firstGroup = groups.values().next().value;
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

  const groupShares = [];
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
  threshold,
  shareCount,
  masterSecret,
  passphrase = "",
  options = {}
) {
  validateSingleGroupParameters(threshold, shareCount);
  validateMasterSecretBytes(masterSecret);
  const passphraseBytes = validatePassphrase(passphrase);
  const iterationExponent = options.iterationExponent ?? 1;
  validateIterationExponent(iterationExponent);
  const extendable = options.extendable ?? true;
  const identifier = options.identifier ?? randomIdentifier();
  validateIdentifier(identifier);

  let encryptedMasterSecret;
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

export async function combineMnemonics(mnemonics, passphrase = "") {
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

function combinations(items, size) {
  if (size < 0 || size > items.length) {
    return [];
  }
  if (size === 0) {
    return [[]];
  }

  const result = [];
  const current = [];

  function visit(start) {
    if (current.length === size) {
      result.push([...current]);
      return;
    }

    const remaining = size - current.length;
    for (let index = start; index <= items.length - remaining; index += 1) {
      current.push(items[index]);
      visit(index + 1);
      current.pop();
    }
  }

  visit(0);
  return result;
}

function cartesianProduct(groups) {
  return groups.reduce(
    (product, group) => product.flatMap((prefix) => group.map((item) => [...prefix, item])),
    [[]]
  );
}

function parseFlexibleMnemonics(mnemonics) {
  const groups = new Map();
  const seenMnemonics = new Set();
  let commonKey = null;
  let decodedCount = 0;

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

export async function combineMnemonicsFlexible(mnemonics, passphrase = "") {
  const groups = parseFlexibleMnemonics(mnemonics);
  const firstGroup = groups.values().next().value;
  const firstShare = firstGroup.sharesByMemberIndex.values().next().value.share;
  const groupThreshold = firstShare.groupThreshold;
  const completeGroups = [...groups.entries()]
    .map(([groupIndex, group]) => {
      const memberThreshold = group.sharesByMemberIndex.values().next().value.share.memberThreshold;
      const shares = [...group.sharesByMemberIndex.values()];
      return {
        groupIndex,
        memberThreshold,
        shareCombinations:
          shares.length >= memberThreshold
            ? combinations(shares, memberThreshold).map((candidate) =>
                candidate.map((entry) => entry.mnemonic)
              )
            : []
      };
    })
    .filter((group) => group.shareCombinations.length > 0);

  if (completeGroups.length < groupThreshold) {
    throw new Slip39Error(
      `Insufficient number of mnemonic groups. Required groups: ${groupThreshold}.`
    );
  }

  const errorCounts = new Map();
  let attemptCount = 0;
  for (const groupSet of combinations(completeGroups, groupThreshold)) {
    const memberCombinationSets = cartesianProduct(
      groupSet.map((group) => group.shareCombinations)
    );
    for (const memberCombinationSet of memberCombinationSets) {
      attemptCount += 1;
      const candidateMnemonics = memberCombinationSet.flat();
      try {
        return await combineMnemonics(candidateMnemonics, passphrase);
      } catch (error) {
        const message = error?.message ?? String(error);
        errorCounts.set(message, (errorCounts.get(message) ?? 0) + 1);
      }
    }
  }

  if (errorCounts.size === 0) {
    throw new Slip39Error("No valid threshold-complete mnemonic subset was found.");
  }
  if (errorCounts.size === 1) {
    const [onlyMessage] = errorCounts.keys();
    throw new Slip39Error(onlyMessage);
  }
  const ranked = [...errorCounts.entries()].sort((a, b) => b[1] - a[1]);
  const summary = ranked.map(([message, count]) => `  - ${message} (x${count} times)`).join("\n");
  throw new Slip39Error(
    `No valid threshold-complete mnemonic subset was found.\nTried ${attemptCount} combinations. Most common errors:\n${summary}`
  );
}
