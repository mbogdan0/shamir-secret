export class Slip39Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Slip39Error";
  }
}
