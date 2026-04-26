export class Slip39Error extends Error {
  constructor(message) {
    super(message);
    this.name = "Slip39Error";
  }
}
