const hdkey = require('hdkey')
const bip39 = require('bip39')
const secp256k1 = require('secp256k1')
const blake2b = require('bcrypto/lib/blake2b')
const sha3 = require('bcrypto/lib/sha3')

const Tx = require('./primitives/tx')
const Outpoint = require('./primitives/outpoint')
const Output = require('./primitives/output')
const Input = require('./primitives/input')
const Script = require('./script/script')
const Witness = require('./script/witness')
const Address = require('./primitives/address')
const { verifyString, types, createBlind } = require('./rule')

class HandshakeJS {
  constructor ({ privateKey, publicKey, mnemonic, seed, path, network }) {
    this._publicKey = publicKey
    this._privateKey = privateKey
    this._mnemonic = mnemonic
    this._seed = seed
    this._path = path
    this._network = network

    this.getAddress = this.getAddress.bind(this)
    this.generateTransaction = this.generateTransaction.bind(this)
    this.send = this.send.bind(this)
    this.openName = this.openName.bind(this)
    this.bidName = this.bidName.bind(this)
    this.hashName = this.hashName.bind(this)
    this.generateNonce = this.generateNonce.bind(this)
  }

  static fromMnemonic (mnemonic, path = 'm\'/44\'/5353\'/0\'/0/0', network) {
    const seed = bip39.mnemonicToSeedSync(mnemonic)
    const keyPair = hdkey.fromMasterSeed(seed).derive(path)

    const { privateKey, publicKey } = keyPair
    return new this({ privateKey, publicKey, mnemonic, seed, path, network })
  }

  static fromMasterSeed (seed, path = 'm\'/44\'/5353\'/0\'/0/0', network) {
    const keyPair = hdkey.fromMasterSeed(seed).derive(path)

    const { privateKey, publicKey } = keyPair
    return new this({ privateKey, publicKey, seed, path, network })
  }

  static fromPrivateKey (privateKey, network) {
    const publicKey = secp256k1.publicKeyCreate(privateKey, true)
    return new this({ privateKey, publicKey, network })
  }

  getAddress (path) {
    if (path && this._seed) {
      const keyPair = hdkey.fromMasterSeed(this._seed).derive(path)
      return Address.fromPubkey(keyPair.publicKey).toString(this._network)
    }

    return Address.fromPubkey(this._publicKey).toString(this._network)
  }

  send (utxos, address, amount, fee, changeAddress) {
    const inputAmount = utxos.reduce((acc, cur) => acc + cur.value, 0)
    const changeAmount = inputAmount - fee - amount

    const selfAddress = this.getAddress()
    const outputs = [
      Output.fromScript(Address.fromString(address), amount),
      Output.fromScript(Address.fromString(changeAddress || selfAddress), changeAmount)
    ]

    return this.generateTransaction(utxos, outputs)
  }

  hashName (name) {
    if (Buffer.isBuffer(name)) {
      return sha3.digest(name)
    }
    const NAME_BUFFER = Buffer.allocUnsafe(63)
    const slab = NAME_BUFFER
    const written = slab.write(name, 0, slab.length, 'ascii')
    const buf = slab.slice(0, written)
    return sha3.digest(buf)
  };

  generateNonce (nameHash, address, value) {
    const hi = (value * (1 / 0x100000000)) >>> 0
    const lo = value >>> 0
    const index = (hi ^ lo) & 0x7fffffff
    // console.log(index)
    const { publicKey } = hdkey
      .fromMasterSeed(this._seed)
      .derive(`m'/44'/5353'/0'/${index}`)

    return blake2b.multi(address.hash, publicKey, nameHash)
  }

  openName (name, utxos, fee, changeAddress) {
    const rawName = Buffer.from(name, 'ascii')
    const nameHash = this.hashName(rawName)
    const addr = this.getAddress()

    const output = new Output()
    output.address = addr
    output.value = 0
    output.covenant.type = types.OPEN
    output.covenant.pushHash(nameHash)
    output.covenant.pushU32(0)
    output.covenant.push(rawName)

    const inputAmount = utxos.reduce((acc, cur) => acc + cur.value, 0)
    const changeAmount = inputAmount - fee

    const outputs = [
      Output.fromScript(Address.fromString(changeAddress || addr), changeAmount),
      output
    ]

    return this.generateTransaction(utxos, outputs)
  }

  bidName (name, value, lockup, start, utxos, fee, changeAddress) {
    if (!verifyString(name)) { throw new Error('Invalid name.') }

    const rawName = Buffer.from(name, 'ascii')
    const nameHash = this.hashName(rawName)
    const addr = this.getAddress()

    const nonce = this.generateNonce(nameHash, Address.fromString(addr), value)
    const blind = createBlind(value, nonce)

    const output = new Output()
    output.address = addr
    output.value = lockup
    output.covenant.type = types.BID
    output.covenant.pushHash(nameHash)
    output.covenant.pushU32(start)
    output.covenant.push(rawName)
    output.covenant.pushHash(blind)

    const inputAmount = utxos.reduce((acc, cur) => acc + cur.value, 0)
    const changeAmount = inputAmount - fee - value

    const outputs = [
      output,
      Output.fromScript(Address.fromString(changeAddress || addr), changeAmount)
    ]

    return this.generateTransaction(utxos, outputs)
  }

  generateTransaction (utxos, outputs) {
    const inputs = utxos.map(utxo => {
      const outpoint = new Outpoint(Buffer.from(utxo.hash, 'hex'), utxo.index)
      return Input.fromOutpoint(outpoint)
    })

    const transaction = new Tx({
      inputs,
      outputs
    })

    const pkh = blake2b.digest(this._publicKey, 20)
    const script = Script.fromPubkeyhash(pkh)

    transaction.inputs.forEach((i, index) => {
      const txin = utxos[index]
      const sig = transaction.signature(index, script, txin.value, this._privateKey)
      i.witness = Witness.fromItems([sig, this._publicKey])
    })

    const raw = transaction.encode()
    const txid = transaction.txid()

    return {
      hex: raw.toString('hex'),
      txid
    }
  }
}


HandshakeJS.hashStringToAddress = function (str) {
  const Addr = Address.fromHash(Buffer.from(str, 'hex'))
  return Addr.toString()
}

HandshakeJS.Tx = Tx
HandshakeJS.Address = Address

module.exports = HandshakeJS
