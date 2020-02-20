const bio = require('bufio')
const blake2b = require('bcrypto/lib/blake2b')

const blacklist = new Set([
  'example', // ICANN reserved
  'invalid', // ICANN reserved
  'local', // mDNS
  'localhost', // ICANN reserved
  'test' // ICANN reserved
])

const MAX_NAME_SIZE = 63

const CHARSET = new Uint8Array([
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
  0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 4,
  0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0
])

function verifyString (str) {
  if (str.length === 0) { return false }

  if (str.length > MAX_NAME_SIZE) { return false }

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i)

    // No unicode characters.
    if (ch & 0xff80) { return false }

    const type = CHARSET[ch]

    switch (type) {
      case 0: // non-printable
        return false
      case 1: // 0-9
        break
      case 2: // A-Z
        return false
      case 3: // a-z
        break
      case 4: // - and _
        // Do not allow at end or beginning.
        if (i === 0 || i === str.length - 1) { return false }
        break
    }
  }

  if (blacklist.has(str)) { return false }

  return true
}

const types = {
  NONE: 0,
  CLAIM: 1,
  OPEN: 2,
  BID: 3,
  REVEAL: 4,
  REDEEM: 5,
  REGISTER: 6,
  UPDATE: 7,
  RENEW: 8,
  TRANSFER: 9,
  FINALIZE: 10,
  REVOKE: 11
}

function createBlind (value, nonce) {
  const bw = bio.write(40)
  bw.writeU64(value)
  bw.writeBytes(nonce)

  return blake2b.digest(bw.render())
};

module.exports = {
  verifyString,
  types,
  createBlind
}
