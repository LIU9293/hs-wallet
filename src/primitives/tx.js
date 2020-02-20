/*!
 * tx.js - transaction object for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict'

const assert = require('bsert')
const bio = require('bufio')
const blake2b = require('bcrypto/lib/blake2b')
const secp256k1 = require('bcrypto/lib/secp256k1')
const { BufferSet } = require('buffer-map')
const util = require('../utils/util')
const Amount = require('./amount')
const Network = require('../protocol/network')
const Script = require('../script/script')
const Input = require('./input')
const Output = require('./output')
const Outpoint = require('./outpoint')
const consensus = require('../protocol/consensus')
const policy = require('../protocol/policy')
const { encoding } = bio
const { hashType } = Script

/**
 * TX
 * A static transaction object.
 * @alias module:primitives.TX
 * @property {Number} version
 * @property {Input[]} inputs
 * @property {Output[]} outputs
 * @property {Number} locktime
 */

class TX extends bio.Struct {
  /**
   * Create a transaction.
   * @constructor
   * @param {Object?} options
   */

  constructor (options) {
    super()

    this.version = 0
    this.inputs = []
    this.outputs = []
    this.locktime = 0

    this.mutable = false

    this._hash = null
    this._wdhash = null
    this._whash = null

    this._raw = null
    this._sizes = null

    this._hashPrevouts = null
    this._hashSequence = null
    this._hashOutputs = null

    if (options) { this.fromOptions(options) }
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions (options) {
    assert(options, 'TX data is required.')

    if (options.version != null) {
      assert((options.version >>> 0) === options.version,
        'Version must be a uint32.')
      this.version = options.version
    }

    if (options.inputs) {
      assert(Array.isArray(options.inputs), 'Inputs must be an array.')
      for (const input of options.inputs) { this.inputs.push(new Input(input)) }
    }

    if (options.outputs) {
      assert(Array.isArray(options.outputs), 'Outputs must be an array.')
      for (const output of options.outputs) { this.outputs.push(new Output(output)) }
    }

    if (options.locktime != null) {
      assert((options.locktime >>> 0) === options.locktime,
        'Locktime must be a uint32.')
      this.locktime = options.locktime
    }

    return this
  }

  /**
   * Inject properties from tx.
   * Used for cloning.
   * @private
   * @param {TX} tx
   * @returns {TX}
   */

  inject (tx) {
    this.version = tx.version

    for (const input of tx.inputs) { this.inputs.push(input.clone()) }

    for (const output of tx.outputs) { this.outputs.push(output.clone()) }

    this.locktime = tx.locktime

    return this
  }

  /**
   * Clear any cached values.
   */

  refresh () {
    this._hash = null
    this._wdhash = null
    this._whash = null

    this._raw = null
    this._sizes = null

    this._hashPrevouts = null
    this._hashSequence = null
    this._hashOutputs = null

    return this
  }

  /**
   * Hash the transaction with the non-witness serialization.
   * @returns {Hash} hash
   */

  hash () {
    if (this.mutable) { return this.left() }

    if (!this._hash) { this._hash = this.left() }

    return this._hash
  }

  /**
   * Hash the transaction with the witness
   * serialization, return the wtxid (normal
   * hash if no witness is present, all zeroes
   * if coinbase).
   * @returns {Hash} hash
   */

  witnessHash () {
    if (this.mutable) { return this.root() }

    if (!this._whash) { this._whash = this.root() }

    return this._whash
  }

  /**
   * Calculate the virtual size of the transaction.
   * Note that this is cached.
   * @returns {Number} vsize
   */

  getVirtualSize () {
    const scale = consensus.WITNESS_SCALE_FACTOR
    return (this.getWeight() + scale - 1) / scale | 0
  }

  /**
   * Calculate the virtual size of the transaction
   * (weighted against bytes per sigop cost).
   * @param {Number} sigops - Sigops cost.
   * @returns {Number} vsize
   */

  getSigopsSize (sigops) {
    const scale = consensus.WITNESS_SCALE_FACTOR
    const bytes = policy.BYTES_PER_SIGOP
    const weight = Math.max(this.getWeight(), sigops * bytes)
    return (weight + scale - 1) / scale | 0
  }

  /**
   * Calculate the weight of the transaction.
   * Note that this is cached.
   * @returns {Number} weight
   */

  getWeight () {
    const { base, witness } = this.getSizes()
    const total = base + witness
    return base * (consensus.WITNESS_SCALE_FACTOR - 1) + total
  }

  /**
   * Calculate the real size of the transaction
   * with the witness included.
   * @returns {Number} size
   */

  getSize () {
    const { base, witness } = this.getSizes()
    return base + witness
  }

  /**
   * Calculate the size of the transaction
   * without the witness.
   * with the witness included.
   * @returns {Number} size
   */

  getBaseSize () {
    const { base } = this.getSizes()
    return base
  }

  /**
   * Test whether the transaction has a non-empty witness.
   * @returns {Boolean}
   */

  hasWitness () {
    for (const { witness } of this.inputs) {
      if (witness.items.length > 0) { return true }
    }

    return false
  }

  /**
   * Get the signature hash of the transaction for signing verifying.
   * @param {Number} index - Index of input being signed/verified.
   * @param {Script} prev - Previous output script or redeem script
   * (in the case of witnesspubkeyhash, this should be the generated
   * p2pkh script).
   * @param {Amount} value - Previous output value.
   * @param {SighashType} type - Sighash type.
   * @returns {Buffer} Signature hash.
   */

  signatureHash (index, prev, value, type) {
    assert(index >= 0 && index < this.inputs.length)
    assert(prev instanceof Script)
    assert(typeof value === 'number')
    assert(typeof type === 'number')

    let input = this.inputs[index]
    let prevouts = consensus.ZERO_HASH
    let sequences = consensus.ZERO_HASH
    let outputs = consensus.ZERO_HASH

    if (type & hashType.NOINPUT) { input = new Input() }

    if (!(type & hashType.ANYONECANPAY)) {
      if (this._hashPrevouts) {
        prevouts = this._hashPrevouts
      } else {
        const bw = bio.pool(this.inputs.length * 36)

        for (const input of this.inputs) { input.prevout.write(bw) }

        prevouts = blake2b.digest(bw.render())

        if (!this.mutable) { this._hashPrevouts = prevouts }
      }
    }

    if (!(type & hashType.ANYONECANPAY) &&
        (type & 0x1f) !== hashType.SINGLE &&
        (type & 0x1f) !== hashType.SINGLEREVERSE &&
        (type & 0x1f) !== hashType.NONE) {
      if (this._hashSequence) {
        sequences = this._hashSequence
      } else {
        const bw = bio.pool(this.inputs.length * 4)

        for (const input of this.inputs) { bw.writeU32(input.sequence) }

        sequences = blake2b.digest(bw.render())

        if (!this.mutable) { this._hashSequence = sequences }
      }
    }

    if ((type & 0x1f) !== hashType.SINGLE &&
        (type & 0x1f) !== hashType.SINGLEREVERSE &&
        (type & 0x1f) !== hashType.NONE) {
      if (this._hashOutputs) {
        outputs = this._hashOutputs
      } else {
        let size = 0

        for (const output of this.outputs) { size += output.getSize() }

        const bw = bio.pool(size)

        for (const output of this.outputs) { output.write(bw) }

        outputs = blake2b.digest(bw.render())

        if (!this.mutable) { this._hashOutputs = outputs }
      }
    } else if ((type & 0x1f) === hashType.SINGLE) {
      if (index < this.outputs.length) {
        const output = this.outputs[index]
        outputs = blake2b.digest(output.encode())
      }
    } else if ((type & 0x1f) === hashType.SINGLEREVERSE) {
      if (index < this.outputs.length) {
        const output = this.outputs[(this.outputs.length - 1) - index]
        outputs = blake2b.digest(output.encode())
      }
    }

    const size = 156 + prev.getVarSize()
    const bw = bio.pool(size)

    bw.writeU32(this.version)
    bw.writeBytes(prevouts)
    bw.writeBytes(sequences)
    bw.writeHash(input.prevout.hash)
    bw.writeU32(input.prevout.index)
    bw.writeVarBytes(prev.encode())
    bw.writeU64(value)
    bw.writeU32(input.sequence)
    bw.writeBytes(outputs)
    bw.writeU32(this.locktime)
    bw.writeU32(type)

    return blake2b.digest(bw.render())
  }

  /**
   * Verify signature.
   * @param {Number} index
   * @param {Script} prev
   * @param {Amount} value
   * @param {Buffer} sig
   * @param {Buffer} key
   * @returns {Boolean}
   */

  checksig (index, prev, value, sig, key) {
    if (sig.length === 0) { return false }

    const type = sig[sig.length - 1]
    const hash = this.signatureHash(index, prev, value, type)

    return secp256k1.verify(hash, sig.slice(0, -1), key)
  }

  /**
   * Create a signature suitable for inserting into scriptSigs/witnesses.
   * @param {Number} index - Index of input being signed.
   * @param {Script} prev - Previous output script or redeem script
   * (in the case of witnesspubkeyhash, this should be the generated
   * p2pkh script).
   * @param {Amount} value - Previous output value.
   * @param {Buffer} key
   * @param {SighashType} type
   * @returns {Buffer} Signature in DER format.
   */

  signature (index, prev, value, key, type) {
    if (type == null) { type = hashType.ALL }

    const hash = this.signatureHash(index, prev, value, type)
    const sig = secp256k1.sign(hash, key)
    const bw = bio.write(65)

    bw.writeBytes(sig)
    bw.writeU8(type)

    return bw.render()
  }

  /**
   * Test whether the transaction is a coinbase
   * by examining the inputs.
   * @returns {Boolean}
   */

  isCoinbase () {
    return this.inputs.length > 0 && this.inputs[0].prevout.isNull()
  }

  /**
   * Calculate the fee for the transaction.
   * @param {CoinView} view
   * @returns {Amount} fee (zero if not all coins are available).
   */

  getFee (view) {
    if (!this.hasCoins(view)) { return 0 }

    return this.getInputValue(view) - this.getOutputValue()
  }

  /**
   * Calculate the total input value.
   * @param {CoinView} view
   * @returns {Amount} value
   */

  getInputValue (view) {
    let total = 0

    for (const { prevout } of this.inputs) {
      const coin = view.getOutput(prevout)

      if (!coin) { return 0 }

      total += coin.value
    }

    return total
  }

  /**
   * Calculate the total output value.
   * @returns {Amount} value
   */

  getOutputValue () {
    let total = 0

    for (const output of this.outputs) { total += output.value }

    return total
  }

  /**
   * Get all input addresses.
   * @private
   * @param {CoinView} view
   * @returns {Array} [addrs, table]
   */

  _getInputAddresses (view) {
    const table = new BufferSet()
    const addrs = []

    if (this.isCoinbase()) { return [addrs, table] }

    for (const input of this.inputs) {
      const coin = view ? view.getOutputFor(input) : null
      const addr = input.getAddress(coin)

      if (!addr) { continue }

      const hash = addr.getHash()

      if (!table.has(hash)) {
        table.add(hash)
        addrs.push(addr)
      }
    }

    return [addrs, table]
  }

  /**
   * Get all output addresses.
   * @private
   * @returns {Array} [addrs, table]
   */

  _getOutputAddresses () {
    const table = new BufferSet()
    const addrs = []

    for (const output of this.outputs) {
      const addr = output.getAddress()

      if (!addr) { continue }

      const hash = addr.getHash()

      if (!table.has(hash)) {
        table.add(hash)
        addrs.push(addr)
      }
    }

    return [addrs, table]
  }

  /**
   * Get all addresses.
   * @private
   * @param {CoinView} view
   * @returns {Array} [addrs, table]
   */

  _getAddresses (view) {
    const [addrs, table] = this._getInputAddresses(view)
    const output = this.getOutputAddresses()

    for (const addr of output) {
      const hash = addr.getHash()

      if (!table.has(hash)) {
        table.add(hash)
        addrs.push(addr)
      }
    }

    return [addrs, table]
  }

  /**
   * Get all input addresses.
   * @param {CoinView|null} view
   * @returns {Address[]} addresses
   */

  getInputAddresses (view) {
    const [addrs] = this._getInputAddresses(view)
    return addrs
  }

  /**
   * Get all output addresses.
   * @returns {Address[]} addresses
   */

  getOutputAddresses () {
    const [addrs] = this._getOutputAddresses()
    return addrs
  }

  /**
   * Get all addresses.
   * @param {CoinView|null} view
   * @returns {Address[]} addresses
   */

  getAddresses (view) {
    const [addrs] = this._getAddresses(view)
    return addrs
  }

  /**
   * Get all input address hashes.
   * @param {CoinView|null} view
   * @returns {Hash[]} hashes
   */

  getInputHashes (view) {
    const [, table] = this._getInputAddresses(view)
    return table.toArray()
  }

  /**
   * Get all output address hashes.
   * @returns {Hash[]} hashes
   */

  getOutputHashes () {
    const [, table] = this._getOutputAddresses()
    return table.toArray()
  }

  /**
   * Get all address hashes.
   * @param {CoinView|null} view
   * @returns {Hash[]} hashes
   */

  getHashes (view) {
    const [, table] = this._getAddresses(view)
    return table.toArray()
  }

  /**
   * Test whether the transaction has
   * all coins available.
   * @param {CoinView} view
   * @returns {Boolean}
   */

  hasCoins (view) {
    if (this.inputs.length === 0) { return false }

    for (const { prevout } of this.inputs) {
      if (!view.hasEntry(prevout)) { return false }
    }

    return true
  }

  /**
   * Calculate sigops.
   * @param {CoinView} view
   * @returns {Number}
   */

  getSigops (view) {
    if (this.isCoinbase()) { return 0 }

    let total = 0

    for (const input of this.inputs) {
      const coin = view.getOutputFor(input)

      if (!coin) { continue }

      total += coin.address.getSigops(input.witness)
    }

    return total
  }

  getModifiedSize (size) {
    if (size == null) { size = this.getVirtualSize() }

    for (const input of this.inputs) {
      const offset = 45 + Math.min(100, input.witness.getSize())
      if (size > offset) { size -= offset }
    }

    return size
  }

  getMinFee (size, rate) {
    if (size == null) { size = this.getVirtualSize() }

    return policy.getMinFee(size, rate)
  }

  getRoundFee (size, rate) {
    if (size == null) { size = this.getVirtualSize() }

    return policy.getRoundFee(size, rate)
  }

  getRate (view, size) {
    const fee = this.getFee(view)

    if (fee < 0) { return 0 }

    if (size == null) { size = this.getVirtualSize() }

    return policy.getRate(size, fee)
  }

  getPrevout () {
    if (this.isCoinbase()) { return [] }

    const prevout = new BufferSet()

    for (const input of this.inputs) { prevout.add(input.prevout.hash) }

    return prevout.toArray()
  }

  /**
   * Test a transaction against a bloom filter.
   * @param {BloomFilter} filter
   * @returns {Boolean}
   */

  test (filter) {
    let found = false

    if (filter.test(this.hash())) { found = true }

    for (let i = 0; i < this.outputs.length; i++) {
      const { address, covenant } = this.outputs[i]

      if (filter.test(address.hash) || covenant.test(filter)) {
        const prevout = Outpoint.fromTX(this, i)
        filter.add(prevout.encode())
        found = true
      }
    }

    if (found) { return found }

    for (const { prevout } of this.inputs) {
      if (filter.test(prevout.encode())) { return true }
    }

    return false
  }

  /**
   * Get little-endian tx hash.
   * @returns {Hash}
   */

  txid () {
    return this.hash().toString('hex')
  }

  /**
   * Get little-endian wtx hash.
   * @returns {Hash}
   */

  wtxid () {
    return this.witnessHash().toString('hex')
  }

  /**
   * Create outpoint from output index.
   * @param {Number} index
   * @returns {Outpoint}
   */

  outpoint (index) {
    return new Outpoint(this.hash(), index)
  }

  /**
   * Get input from index.
   * @param {Number} index
   * @returns {Input|null}
   */

  input (index) {
    if (index >= this.inputs.length) { return null }
    return this.inputs[index]
  }

  /**
   * Get output from index.
   * @param {Number} index
   * @returns {Output|null}
   */

  output (index) {
    if (index >= this.outputs.length) { return null }
    return this.outputs[index]
  }

  /**
   * Get covenant from index.
   * @param {Number} index
   * @returns {Covenant|null}
   */

  covenant (index) {
    if (index >= this.outputs.length) { return null }
    return this.outputs[index].covenant
  }

  /**
   * Inspect the transaction and return a more
   * user-friendly representation of the data.
   * @param {CoinView} view
   * @param {ChainEntry} entry
   * @param {Number} index
   * @returns {Object}
   */

  format (view, entry, index) {
    let rate = 0
    let fee = 0
    let height = -1
    let block = null
    let time = 0
    let date = null

    if (view) {
      fee = this.getFee(view)
      rate = this.getRate(view)

      // Rate can exceed 53 bits in testing.
      if (!Number.isSafeInteger(rate)) { rate = 0 }
    }

    if (entry) {
      height = entry.height
      block = entry.hash.toString('hex')
      time = entry.time
      date = util.date(time)
    }

    if (index == null) { index = -1 }

    return {
      hash: this.txid(),
      witnessHash: this.wtxid(),
      size: this.getSize(),
      virtualSize: this.getVirtualSize(),
      value: Amount.coin(this.getOutputValue()),
      fee: Amount.coin(fee),
      rate: Amount.coin(rate),
      minFee: Amount.coin(this.getMinFee()),
      height: height,
      block: block,
      time: time,
      date: date,
      index: index,
      version: this.version,
      inputs: this.inputs.map((input) => {
        const coin = view ? view.getOutputFor(input) : null
        return input.format(coin)
      }),
      outputs: this.outputs,
      locktime: this.locktime
    }
  }

  /**
   * Convert the transaction to an object suitable
   * for JSON serialization.
   * @param {Network} network
   * @param {CoinView} view
   * @param {ChainEntry} entry
   * @param {Number} index
   * @returns {Object}
   */

  getJSON (network, view, entry, index) {
    let rate, fee, height, block, time, date

    if (view) {
      fee = this.getFee(view)
      rate = this.getRate(view)

      // Rate can exceed 53 bits in testing.
      if (!Number.isSafeInteger(rate)) { rate = 0 }
    }

    if (entry) {
      height = entry.height
      block = entry.hash.toString('hex')
      time = entry.time
      date = util.date(time)
    }

    network = Network.get(network)

    return {
      hash: this.txid(),
      witnessHash: this.wtxid(),
      fee: fee,
      rate: rate,
      mtime: util.now(),
      height: height,
      block: block,
      time: time,
      date: date,
      index: index,
      version: this.version,
      inputs: this.inputs.map((input) => {
        const coin = view ? view.getCoinFor(input) : null
        const path = view ? view.getPathFor(input) : null
        return input.getJSON(network, coin, path)
      }),
      outputs: this.outputs.map((output) => {
        return output.getJSON(network)
      }),
      locktime: this.locktime,
      hex: this.toHex()
    }
  }

  /**
   * Inject properties from a json object.
   * @private
   * @param {Object} json
   */

  fromJSON (json) {
    assert(json, 'TX data is required.')
    assert((json.version >>> 0) === json.version, 'Version must be a uint32.')
    assert(Array.isArray(json.inputs), 'Inputs must be an array.')
    assert(Array.isArray(json.outputs), 'Outputs must be an array.')
    assert((json.locktime >>> 0) === json.locktime,
      'Locktime must be a uint32.')

    this.version = json.version

    for (const input of json.inputs) { this.inputs.push(Input.fromJSON(input)) }

    for (const output of json.outputs) { this.outputs.push(Output.fromJSON(output)) }

    this.locktime = json.locktime

    return this
  }

  /**
   * Inject properties from serialized
   * buffer reader (witness serialization).
   * @private
   * @param {BufferReader} br
   */

  read (br) {
    br.start()

    this.version = br.readU32()

    const inCount = br.readVarint()

    for (let i = 0; i < inCount; i++) { this.inputs.push(Input.read(br)) }

    const outCount = br.readVarint()

    for (let i = 0; i < outCount; i++) { this.outputs.push(Output.read(br)) }

    this.locktime = br.readU32()

    const start = br.offset

    for (let i = 0; i < inCount; i++) {
      const input = this.inputs[i]
      input.witness.read(br)
    }

    const witness = br.offset - start

    if (!this.mutable) {
      const raw = br.endData()
      const base = raw.length - witness
      this._raw = raw
      this._sizes = new Sizes(base, witness)
    } else {
      br.end()
    }

    return this
  }

  /**
   * Calculate the real size of the transaction
   * with the witness included.
   * @returns {Sizes}
   */

  getSizes () {
    if (this._sizes) { return this._sizes }

    let base = 0
    let witness = 0

    base += 4
    base += encoding.sizeVarint(this.inputs.length)

    for (const input of this.inputs) {
      base += 40
      witness += input.witness.getVarSize()
    }

    base += encoding.sizeVarint(this.outputs.length)

    for (const output of this.outputs) { base += output.getSize() }

    base += 4

    const sizes = new Sizes(base, witness)

    if (!this.mutable) { this._sizes = sizes }

    return sizes
  }

  /**
   * Serialize transaction with witness. Calculates the witness
   * size as it is framing (exposed on return value as `witness`).
   * @private
   * @param {BufferWriter} bw
   * @returns {Sizes}
   */

  write (bw) {
    if (this._raw) {
      bw.writeBytes(this._raw)
      return bw
    }

    bw.writeU32(this.version)

    bw.writeVarint(this.inputs.length)

    for (const input of this.inputs) { input.write(bw) }

    bw.writeVarint(this.outputs.length)

    for (const output of this.outputs) { output.write(bw) }

    bw.writeU32(this.locktime)

    for (const input of this.inputs) { input.witness.write(bw) }

    return bw
  }

  /**
   * Serialize transaction.
   * @returns {Buffer}
   */

  encode () {
    if (this.mutable) { return super.encode() }

    if (!this._raw) { this._raw = super.encode() }

    return this._raw
  }

  /**
   * Calculate left hash.
   * @returns {Buffer}
   */

  left () {
    return this.hashes()[0]
  }

  /**
   * Calculate right hash.
   * @returns {Buffer}
   */

  right () {
    return this.hashes()[1]
  }

  /**
   * Calculate root hash.
   * @returns {Buffer}
   */

  root () {
    return this.hashes()[2]
  }

  /**
   * Calculate all three transaction hashes.
   * @private
   * @returns {Buffer[]}
   */

  hashes () {
    if (this._hash && this._wdhash && this._whash) { return [this._hash, this._wdhash, this._whash] }

    const { base, witness } = this.getSizes()
    const raw = this.encode()

    assert(raw.length === base + witness)

    // Normal data.
    const ndata = raw.slice(0, base)

    // Witness data.
    const wdata = raw.slice(base, base + witness)

    // Left = HASH(normal-data) = normal txid
    const hash = blake2b.digest(ndata)

    // Right = HASH(witness-data)
    const wdhash = blake2b.digest(wdata)

    // WTXID = HASH(normal-txid || witness-data-hash)
    const whash = blake2b.root(hash, wdhash)

    if (!this.mutable) {
      this._hash = hash
      this._wdhash = wdhash
      this._whash = whash
    }

    return [hash, wdhash, whash]
  }

  /**
   * Test whether an object is a TX.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isTX (obj) {
    return obj instanceof TX
  }
}

/*
 * Helpers
 */

class Sizes {
  constructor (base, witness) {
    this.base = base
    this.witness = witness
  }
}

/*
 * Expose
 */

module.exports = TX
