import { it } from 'mocha';
import { t as assert } from '../t';
var freq = require('buffer-byte-frequency')

module.exports = function (sodium) {
  it.skip('Various test cases', function () {
    sodium.randombytes_buf(Buffer.alloc(0))
    sodium.randombytes_buf(new Uint8Array(16))

    assert.throws(function () {
      sodium.randombytes_buf([])
    })

    assert.end()
  })

  it('Generates random bytes', function () {
    var bufConst = Buffer.alloc(64)
    sodium.randombytes_buf(bufConst)

    var buf1 = Buffer.alloc(64)
    for (var i = 0; i < 1e4; i++) {
      sodium.randombytes_buf(buf1)
      if (Buffer.compare(buf1, bufConst) === 0) {
        assert.fail('Constant buffer should not be equal')
        assert.end()
        return
      }
    }

    assert.pass('Generated unique buffers')
    assert.end()
  })

  it('Exceed quota', function () {
    var buf = Buffer.alloc(1 << 17)
    sodium.randombytes_buf(buf)

    freq(buf)
    .map(function (cnt) {
      return (cnt / 256) | 0
    })
    .forEach(function (cnt) {
      if (cnt < 1 && cnt > 3) assert.fail('Statistically unreasonable')
    })

    assert.end()
  })
}
