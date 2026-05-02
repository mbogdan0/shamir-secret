export class Slip39Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class MalformedMnemonicError extends Slip39Error {}

export class InvalidChecksumError extends Slip39Error {}

export class IncompatibleSharesError extends Slip39Error {}

export class DuplicateShareError extends Slip39Error {}

export class InsufficientSharesError extends Slip39Error {}

export class InvalidThresholdError extends Slip39Error {}

export class InvalidSecretLengthError extends Slip39Error {}

export class RecoveryDigestMismatchError extends Slip39Error {}

export class UnsupportedSlip39FeatureError extends Slip39Error {}
