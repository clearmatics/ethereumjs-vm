import BN = require('bn.js')
import libff = require('libff.js')
import { PrecompileInput } from './types'
import { OOGResult, ExecResult } from '../evm'

var bw6_761 = libff.bw6_761

// For BW6-761, the convention for encoding elements of Fq as EVM
// words is as follows.  One Fq element is an array of 3 EVM
// (big-endian) words, where the first word represents the highest
// order 256 bits of the element value (0-padded on the left)
//
// Hence, an uncompressed curve point requires 6 words.

/// BW6_ECADD precompiled contract entry point.  Accepts two BW6-761
/// curve points A and B in a single array, and returns A + B (where +
/// is the group operation).
export function bw6_761_ecadd_pc(opts: PrecompileInput): ExecResult {
  // TODO: gas
  // const gasUsed = new BN(opts._common.param('gasPrices', 'bw6_ecadd'))
  const gasUsed = new BN(0x8000)

  const inputData = opts.data
  console.log('bw6_ecadd_pc: inputData (' + inputData.length + '): ' + inputData.toString('hex'))

  if (inputData.length != 2 * bw6_761.g1_bytes) {
    console.log(
      'bw6_ecadd_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        2 * bw6_761.g1_bytes +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const a = inputData.slice(0, bw6_761.g1_bytes)
  const b = inputData.slice(bw6_761.g1_bytes)
  const out = Buffer.alloc(bw6_761.g1_bytes)
  if (!bw6_761.ecadd(a, b, out)) {
    console.log('bw6_ecadd_pc: libff_bw6_ecadd failed')
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  return { gasUsed, returnValue: out }
}

/// BW6_761_ECMUL precompiled contract entry point. Input data should be
/// an array with a curve point followed by a scalar.
export function bw6_761_ecmul_pc(opts: PrecompileInput): ExecResult {
  // TODO: gas
  // const gasUsed = new BN(opts._common.param('gasPrices', 'bw6_761_ecmul'))
  const gasUsed = new BN(0x8000)

  const inputData = opts.data
  console.log(
    'bw6_761_ecmul_pc: inputData (' + inputData.length + '): ' + inputData.toString('hex'),
  )

  if (inputData.length != bw6_761.g1_bytes + bw6_761.fr_bytes) {
    console.log(
      'bw6_761_ecmul_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        bw6_761.g1_bytes +
        bw6_761.fr_bytes +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const point = inputData.slice(0, bw6_761.g1_bytes)
  const scalar = inputData.slice(bw6_761.g1_bytes)
  const out = Buffer.alloc(bw6_761.g1_bytes)
  if (!bw6_761.ecmul(point, scalar, out)) {
    console.log('bw6_761_ecmul_pc: libff_bw6_761_ecmul failed')
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  return { gasUsed, returnValue: out }
}

/// BW6_761_ECPAIRING precompiled contract entry point. Input data should
/// be a 4 pairs, each containing a G1 point followed by a G2 point.
export function bw6_761_ecpairing_pc(opts: PrecompileInput): ExecResult {
  // TODO: gas
  // const gasUsed = new BN(opts._common.param('gasPrices', 'bw6_761_ecpairing'))
  const gasUsed = new BN(0x8000)

  const inputData = opts.data
  console.log(
    'bw6_761_ecpairing_pc: inputData (' + inputData.length + '): ' + inputData.toString('hex'),
  )

  if (inputData.length != 4 * (bw6_761.g1_bytes + bw6_761.g2_bytes)) {
    console.log(
      'bw6_761_ecpairing_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        4 * (bw6_761.g1_bytes + bw6_761.g2_bytes) +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const points: Buffer[] = [0, 1, 2, 3, 4, 5, 6, 7].map((i: number) =>
    inputData.slice(i * bw6_761.g1_bytes, (i + 1) * bw6_761.g1_bytes),
  )
  const output = Buffer.alloc(32)
  output[31] = bw6_761.ecpairing(points) ? 1 : 0

  console.log('bw6_761_ecpairing_pc: libff_bw6_761_ecpairing returned ' + output[31])
  return { gasUsed, returnValue: output }
}
