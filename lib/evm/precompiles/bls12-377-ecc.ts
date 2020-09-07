import BN = require('bn.js')
import { PrecompileInput } from './types'
import { OOGResult, ExecResult } from '../evm'

const bls12_377_fr_bytes = 2 * 32
const bls12_377_fq_bytes = 3 * 32
const bls12_377_g1_bytes = 2 * bls12_377_fq_bytes
const bls12_377_g2_bytes = 2 * bls12_377_fq_bytes

// TODO: Replace these with libff-node calls
function libff_bls12_377_ecadd(pointA: Buffer, pointB: Buffer, output: Buffer): boolean {
  console.log('libff_bls12_761_ecadd: A     : ' + pointA.toString('hex'))
  console.log('libff_bls12_761_ecadd: B     : ' + pointB.toString('hex'))
  console.log('libff_bls12_761_ecadd: output: ' + output.toString('hex'))

  output.write(
    '00000000000000000000000000000000010c65c0fb9e6c6ef4cbb27fdc55a07e474df11c564bd91e3fa162c32b7fc3dabba5fc508cfdd8938fb4a30f7de5ad9c000000000000000000000000000000000149a58ced619866b242313876fe2df3188f33b77566a9ddc966ff4d4d5c42d515be862c348f51cc91f1c45a74110ba6',
    'hex',
  )
  return true
}

function libff_bls12_377_ecmul(point: Buffer, scalar: Buffer, output: Buffer): boolean {
  console.log('libff_bls12_377_ecmul: point  : ' + point.toString('hex'))
  console.log('libff_bls12_377_ecmul: scalar : ' + scalar.toString('hex'))
  console.log('libff_bls12_377_ecmul: output : ' + output.toString('hex'))

  output.write(
    '00000000000000000000000000000000018aff632c0048f5afb5c07fd197a44a127c829be3ff6170c6cebc1154bc72633b45de2ac855e0da30cebfa33672e7f30000000000000000000000000000000000be8218b8b1ba93705bf17a910274768383d037cf28b27f9b084d9efb929cc7ff8ad0f1567f8b0edb78c769fed58756',
    'hex',
  )

  return true
}

function libff_bls12_377_ecpairing(points: Buffer[]): boolean {
  console.log('libff_bls12_377_ecpairing: points:')
  points.forEach(buf => console.log(' ' + buf.toString('hex')))

  const finalByte = points[7][bls12_377_g2_bytes - 1]
  console.log('libff_bls12_377_ecpairing: finalByte: ' + finalByte.toString(16))

  return finalByte == 0x41
}

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

  if (inputData.length != 2 * bls12_377_g1_bytes) {
    console.log(
      'bls12_377_ecadd_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        2 * bls12_377_g1_bytes +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const a = inputData.slice(0, bls12_377_g1_bytes)
  const b = inputData.slice(bls12_377_g1_bytes)
  const out = Buffer.alloc(bls12_377_g1_bytes)
  if (!libff_bls12_377_ecadd(a, b, out)) {
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

  if (inputData.length != bls12_377_g1_bytes + bls12_377_fr_bytes) {
    console.log(
      'bls12_377_ecmul_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        bls12_377_g1_bytes +
        bls12_377_fr_bytes +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const point = inputData.slice(0, bls12_377_g1_bytes)
  const scalar = inputData.slice(bls12_377_g1_bytes)
  const out = Buffer.alloc(bls12_377_g1_bytes)
  if (!libff_bls12_377_ecmul(point, scalar, out)) {
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

  if (inputData.length != 4 * (bls12_377_g1_bytes + bls12_377_g2_bytes)) {
    console.log(
      'bls12_377_ecpairing_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        4 * (bls12_377_g1_bytes + bls12_377_g2_bytes) +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const pairSize = bls12_377_g1_bytes + bls12_377_g2_bytes
  const points: Buffer[] = [
    inputData.slice(0 * pairSize, 0 * pairSize + bls12_377_g1_bytes),
    inputData.slice(0 * pairSize + bls12_377_g1_bytes, 0 * pairSize + pairSize),

    inputData.slice(1 * pairSize, 1 * pairSize + bls12_377_g1_bytes),
    inputData.slice(1 * pairSize + bls12_377_g1_bytes, 1 * pairSize + pairSize),

    inputData.slice(2 * pairSize, 2 * pairSize + bls12_377_g1_bytes),
    inputData.slice(2 * pairSize + bls12_377_g1_bytes, 2 * pairSize + pairSize),

    inputData.slice(3 * pairSize, 3 * pairSize + bls12_377_g1_bytes),
    inputData.slice(3 * pairSize + bls12_377_g1_bytes, 3 * pairSize + pairSize),
  ]
  const output = Buffer.alloc(32)
  output[31] = libff_bls12_377_ecpairing(points) ? 1 : 0

  console.log('bls12_377_ecpairing_pc: libff_bls12_377_ecpairing returned ' + output[31])
  return { gasUsed, returnValue: output }
}
