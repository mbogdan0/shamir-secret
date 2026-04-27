export class Slip39Error extends Error {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message);
    this.name = "Slip39Error";
  }
}
