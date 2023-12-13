import { assert } from 'chai';

export const t = {
  assert: assert,
  deepEqual: assert.deepEqual,
  deepEquals: assert.deepEqual,
  end: () => {},
  equal: assert.equal,
  fail: assert.fail,
  notDeepEqual: assert.notDeepEqual,
  notEqual: assert.notEqual,
  notEquals: assert.notEqual,
  notOk: assert.isNotOk,
  notSame: assert.notDeepEqual,
  ok: assert,
  pass: (message: string) => assert.isOk(true, message),
  same: assert.deepEqual,
  // @ts-ignore
  doesNotThrow: (...args) => {
    if (args.length === 2 && typeof args[1] === 'string') {
      return assert.doesNotThrow(args[0], undefined, undefined, args[1]);
    }
    // @ts-ignore
    return assert.doesNotThrow(...args);
  },
  // @ts-ignore
  throws: (...args) => {
    if (args.length === 2 && typeof args[1] === 'string') {
      return assert.throws(args[0], undefined, undefined, args[1]);
    }
    // @ts-ignore
    return assert.throws(...args);
  },
};
