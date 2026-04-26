import * as slip39 from "./slip39/index.js";
import { startUi } from "./ui/app-ui.js";

globalThis.__SLIP39_APP__ = {
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

if (typeof document !== "undefined") {
  startUi(slip39);
}
