import * as slip39 from "./slip39/index.ts";
import { startUi, type AppCore } from "./ui/app-ui.ts";

const appCore: AppCore = {
  MIN_STRENGTH_BITS: slip39.MIN_STRENGTH_BITS,
  bitsToBytes: slip39.bitsToBytes,
  bytesToHex: slip39.bytesToHex,
  combineMnemonicsFlexible: slip39.combineMnemonicsFlexible,
  compactHex: slip39.compactHex,
  decodeTextMasterSecret: slip39.decodeTextMasterSecret,
  describeTextMasterSecret: slip39.describeTextMasterSecret,
  encodeTextMasterSecret: slip39.encodeTextMasterSecret,
  generateMnemonics: slip39.generateMnemonics,
  hasRequiredCrypto: slip39.hasRequiredCrypto,
  parseMasterSecretHex: slip39.parseMasterSecretHex
};

const testApi = {
  SLIP39_WORDS: slip39.SLIP39_WORDS,
  Share: slip39.Share,
  Slip39Error: slip39.Slip39Error,
  bytesToHex: slip39.bytesToHex,
  combineMnemonics: slip39.combineMnemonics,
  combineMnemonicsFlexible: slip39.combineMnemonicsFlexible,
  createChecksum: slip39.createChecksum,
  decodeTextMasterSecret: slip39.decodeTextMasterSecret,
  describeTextMasterSecret: slip39.describeTextMasterSecret,
  encodeTextMasterSecret: slip39.encodeTextMasterSecret,
  generateMnemonics: slip39.generateMnemonics,
  gfMultiply: slip39.gfMultiply,
  hasRequiredCrypto: slip39.hasRequiredCrypto,
  hexToBytes: slip39.hexToBytes,
  interpolate: slip39.interpolate,
  isTextMasterSecretEnvelope: slip39.isTextMasterSecretEnvelope,
  normalizeHex: slip39.normalizeHex,
  parseMasterSecretHex: slip39.parseMasterSecretHex,
  splitSecret: slip39.splitSecret,
  verifyChecksum: slip39.verifyChecksum
};

(globalThis as unknown as { __SLIP39_APP__: typeof testApi }).__SLIP39_APP__ = testApi;

if (typeof document !== "undefined") {
  startUi(appCore);
}
