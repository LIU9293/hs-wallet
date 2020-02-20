# Handshake-js

> This library is like a subset of hsd which generate raw handshake transactions

### Usage

* Get address with a mnemonic

``` javascript
const handshake = require('hs-wallet')
const mnemonic = '*** *** ***'

const wallet = handshake.fromMnemonic(mnemonic)
const address = wallet.getAddress()
```

* Send fund

```javascript
const utxo = {
  hash: '1ad8539d27fae6bd217ace51f0e23da8eddf121a48e4ac39ca4bff4f1c0c6f8c',
  index: 0,
  value: 1 * 1e6
}

const transaction = wallet.send([utxo], toAddress, amount /* 0.5 * 1e6 */, fee /* 0.01 * 1e6 */)
const { txid, hex } = transaction
// then call rpc - sendrawtransaction with hex
```

* Bid name

```javascript
const utxo = {
  hash: '1ad8539d27fae6bd217ace51f0e23da8eddf121a48e4ac39ca4bff4f1c0c6f8c',
  index: 0,
  value: 1 * 1e6
}

const transaction = wallet.bidName(
  'wltx',       // name want to bid
  0.1 * 1e6,    // value
  0.1 * 1e6,    // lock value, must >= value
  2842,         // current block height
  [utxo],       // utxo set
  0.05 * 1e6,    // transaction fee
)

const { txid, hex } = transaction
// then call rpc - sendrawtransaction with hex
```