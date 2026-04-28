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

if (typeof document !== "undefined") {
  startUi(appCore);
}
