import VM from '../../'

import Account from '@ethereumjs/account'
import { Block, BlockHeader } from '@ethereumjs/block'
import Blockchain from '@ethereumjs/blockchain'
import { toBuffer, setLengthLeft } from 'ethereumjs-util'

const testData = require('./test-data')
const level = require('level')

async function main() {
  const hardfork = testData.network.toLowerCase()
  const validatePow = true
  const validateBlocks = true

  const blockchain = new Blockchain({
    hardfork,
    validatePow,
    validateBlocks,
  })

  // When verifying PoW, setting this cache improves the
  // performance of subsequent runs of this script.
  if (validatePow) {
    blockchain.ethash!.cacheDB = level('./.cachedb')
  }

  const vm = new VM({ blockchain, hardfork })

  await setupPreConditions(vm, testData)

  await setGenesisBlock(blockchain, hardfork)

  await putBlocks(blockchain, hardfork, testData)

  await vm.runBlockchain(blockchain)

  const blockchainHead = await vm.blockchain.getHead()

  console.log('--- Finished processing the BlockChain ---')
  console.log('New head:', '0x' + blockchainHead.hash().toString('hex'))
  console.log('Expected:', testData.lastblockhash)
}

async function setupPreConditions(vm: VM, testData: any) {
  await vm.stateManager.checkpoint()

  for (const address of Object.keys(testData.pre)) {
    const acctData = testData.pre[address]
    const account = new Account({
      nonce: acctData.nonce,
      balance: acctData.balance,
    })

    const addressBuf = Buffer.from(address.slice(2), 'hex')
    await vm.stateManager.putAccount(addressBuf, account)

    for (const hexStorageKey of Object.keys(acctData.storage)) {
      const val = Buffer.from(acctData.storage[hexStorageKey], 'hex')
      const storageKey = setLengthLeft(Buffer.from(hexStorageKey, 'hex'), 32)

      await vm.stateManager.putContractStorage(addressBuf, storageKey, val)
    }

    const codeBuf = Buffer.from(acctData.code.slice(2), 'hex')

    await vm.stateManager.putContractCode(addressBuf, codeBuf)
  }

  await vm.stateManager.commit()
}

async function setGenesisBlock(blockchain: any, hardfork: string) {
  const header = new BlockHeader(testData.genesisBlockHeader, { hardfork })
  const genesisBlock = new Block([header.raw, [], []], { hardfork })
  await blockchain.putGenesis(genesisBlock)
}

async function putBlocks(blockchain: any, hardfork: string, testData: any) {
  for (const blockData of testData.blocks) {
    const block = new Block(toBuffer(blockData.rlp), { hardfork })
    await blockchain.putBlock(block)
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err)
    process.exit(1)
  })
