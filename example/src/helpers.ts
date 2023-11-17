/**
 * Pauses execution of a function.
 * @param {number} ms The time to wait in milliseconds.
 * @returns {Promise<void>}
 */
export const sleep = (ms = 1000): Promise<void> => {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
};
