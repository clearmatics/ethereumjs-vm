import BN = require('bn.js')
import libff = require('libff.js')
import { PrecompileInput } from './types'
import { OOGResult, ExecResult } from '../evm'

var bls12_377 = libff.bls12_377

// For BLS12-377, the convention for encoding elements of Fq as EVM
// words is as follows.  One Fq element is an array of 2 EVM
// (big-endian) words, where the first word represents the highest
// order 256 bits of the element value (0-padded on the left)
//
// Hence, an uncompressed G1 curve point requires 4 words, and an
// uncompressed G2 curve point (defined over Fq2) requires 8 words.

/// BLS12_377_ECADD precompiled contract entry point.  Accepts two
/// BLS12-377 curve points A and B in a single array, and returns A +
/// B (where + is the group operation).
export function bls12_377_ecadd_pc(opts: PrecompileInput): ExecResult {
  // TODO: gas
  // const gasUsed = new BN(opts._common.param('gasPrices', 'bw6_ecadd'))
  const gasUsed = new BN(0x8000)

  const inputData = opts.data
  console.log(
    'bls12_377_ecadd_pc: inputData (' + inputData.length + '): ' + inputData.toString('hex'),
  )

  if (inputData.length != 2 * bls12_377.g1_bytes) {
    console.log(
      'bls12_377_ecadd_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        2 * bls12_377.g1_bytes +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const a = inputData.slice(0, bls12_377.g1_bytes)
  const b = inputData.slice(bls12_377.g1_bytes)
  const out = Buffer.alloc(bls12_377.g1_bytes)
  if (!bls12_377.ecadd(a, b, out)) {
    console.log('bls12_377_ecadd_pc: libff_bls12_377_ecadd failed')
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  return { gasUsed, returnValue: out }
}

/// BLS12_377_ECMUL precompiled contract entry point. Input data should be
/// an array with a curve point followed by a scalar.
export function bls12_377_ecmul_pc(opts: PrecompileInput): ExecResult {
  // TODO: gas
  // const gasUsed = new BN(opts._common.param('gasPrices', 'bls12_377_ecmul'))
  const gasUsed = new BN(0x8000)

  const inputData = opts.data
  console.log(
    'bls12_377_ecmull_pc: inputData (' + inputData.length + '): ' + inputData.toString('hex'),
  )

  if (inputData.length != bls12_377.g1_bytes + bls12_377.fr_bytes) {
    console.log(
      'bls12_377_ecmul_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        bls12_377.g1_bytes +
        bls12_377.fr_bytes +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const point = inputData.slice(0, bls12_377.g1_bytes)
  const scalar = inputData.slice(bls12_377.g1_bytes)
  const out = Buffer.alloc(bls12_377.g1_bytes)
  if (!bls12_377.ecmul(point, scalar, out)) {
    console.log('bls12_377_ecmul_pc: libff_bls12_377_ecmul failed')
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  return { gasUsed, returnValue: out }
}

/// BLS12_377_ECPAIRING precompiled contract entry point. Input data should
/// be a 4 pairs, each containing a G1 point followed by a G2 point.
export function bls12_377_ecpairing_pc(opts: PrecompileInput): ExecResult {
  // TODO: gas
  // const gasUsed = new BN(opts._common.param('gasPrices', 'bls12_377_ecpairing'))
  const gasUsed = new BN(0x8000)

  const inputData = opts.data
  console.log(
    'bls12_377_ecpairing_pc: inputData (' + inputData.length + '): ' + inputData.toString('hex'),
  )

  if (inputData.length != 4 * (bls12_377.g1_bytes + bls12_377.g2_bytes)) {
    console.log(
      'bls12_377_ecpairing_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        4 * (bls12_377.g1_bytes + bls12_377.g2_bytes) +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const pairSize = bls12_377.g1_bytes + bls12_377.g2_bytes
  const points: Buffer[] = [
    inputData.slice(0 * pairSize, 0 * pairSize + bls12_377.g1_bytes),
    inputData.slice(0 * pairSize + bls12_377.g1_bytes, 0 * pairSize + pairSize),

    inputData.slice(1 * pairSize, 1 * pairSize + bls12_377.g1_bytes),
    inputData.slice(1 * pairSize + bls12_377.g1_bytes, 1 * pairSize + pairSize),

    inputData.slice(2 * pairSize, 2 * pairSize + bls12_377.g1_bytes),
    inputData.slice(2 * pairSize + bls12_377.g1_bytes, 2 * pairSize + pairSize),

    inputData.slice(3 * pairSize, 3 * pairSize + bls12_377.g1_bytes),
    inputData.slice(3 * pairSize + bls12_377.g1_bytes, 3 * pairSize + pairSize),
  ]
  const output = Buffer.alloc(32)
  output[31] = bls12_377.ecpairing(points) ? 1 : 0

  console.log('bls12_377_ecpairing_pc: libff_bls12_377_ecpairing returned ' + output[31])
  return { gasUsed, returnValue: output }
}
