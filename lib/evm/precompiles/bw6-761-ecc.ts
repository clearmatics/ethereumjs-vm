import BN = require('bn.js')
import { PrecompileInput } from './types'
import { OOGResult, ExecResult } from '../evm'

const bw6_761_fr_bytes = 2 * 32
const bw6_761_fq_bytes = 3 * 32
const bw6_761_g1_bytes = 2 * bw6_761_fq_bytes
const bw6_761_g2_bytes = 2 * bw6_761_fq_bytes

// TODO: Replace these with libff-node calls
function libff_bw6_761_ecadd(pointA: Buffer, pointB: Buffer, output: Buffer): boolean {
  console.log('libff_bw6_761_ecadd: A     : ' + pointA.toString('hex'))
  console.log('libff_bw6_761_ecadd: B     : ' + pointB.toString('hex'))
  console.log('libff_bw6_761_ecadd: output: ' + output.toString('hex'))

  output.write(
    '00760cbf3c77666f2cba2ffb4401e3830697a50fe7a46c2f977b37cb5426a6b6cc8b6490bff2cf4562cb257e40f125d63f2a6253191df6dfed26c3e04ea99fd31ce4f347362471546de61475ea28dfaffae215beca593115e51f11d5590ce44300e01244b4533b8aef899bbc446a8b772a20b1cbd837226f41667505467dcbc76606a730e8f55a651e3e5ffb15f213d2def6835ab538138092a86d1b27f56c42483645bdf02337291594523fe6f46a7890e31fc1a527a3fffd21fb31e735da5e',
    'hex',
  )
  return true
}

function libff_bw6_761_ecmul(point: Buffer, scalar: Buffer, output: Buffer): boolean {
  console.log('libff_bw6_761_ecmul: point  : ' + point.toString('hex'))
  console.log('libff_bw6_761_ecmul: scalar : ' + scalar.toString('hex'))
  console.log('libff_bw6_761_ecmul: output : ' + output.toString('hex'))

  output.write(
    '00c7c9438e7e51aa9360612e3cedb297517ebd7a071571b771d86f68c9ec1b280cbcccffdb49ce6e9f77adfa85aae465d0d3c60eec959a99e296042bb6522505a25a4b9ac5a5d224d1ed2c9f6644ab31d68796d3cdf6f3b8ece3f7d4b4054f4500c928123944451fa0883338f0b276d15d9611296f0e7a91917dbfd26ee41ef9d78804ff89c3227e0551f137336da94c2fdffae9278891edf276515b2290d5b128bb85601e4ec30ad02d4029376847c58934f3708b6f7e23142602a313f68c33',
    'hex',
  )
  return true
}

function libff_bw6_761_ecpairing(points: Buffer[]): boolean {
  console.log('libff_bw6_761_ecpairing: points:')
  points.forEach(buf => console.log(' ' + buf.toString('hex')))

  const finalByte = points[7][bw6_761_g2_bytes - 1]
  console.log('libff_bw6_761_ecpairing: finalByte: ' + finalByte.toString(16))

  return finalByte == 0x41
}

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

  if (inputData.length != 2 * bw6_761_g1_bytes) {
    console.log(
      'bw6_ecadd_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        2 * bw6_761_g1_bytes +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const a = inputData.slice(0, bw6_761_g1_bytes)
  const b = inputData.slice(bw6_761_g1_bytes)
  const out = Buffer.alloc(bw6_761_g1_bytes)
  if (!libff_bw6_761_ecadd(a, b, out)) {
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

  if (inputData.length != bw6_761_g1_bytes + bw6_761_fr_bytes) {
    console.log(
      'bw6_761_ecmul_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        bw6_761_g1_bytes +
        bw6_761_fr_bytes +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const point = inputData.slice(0, bw6_761_g1_bytes)
  const scalar = inputData.slice(bw6_761_g1_bytes)
  const out = Buffer.alloc(bw6_761_g1_bytes)
  if (!libff_bw6_761_ecmul(point, scalar, out)) {
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

  if (inputData.length != 4 * (bw6_761_g1_bytes + bw6_761_g2_bytes)) {
    console.log(
      'bw6_761_ecpairing_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        4 * (bw6_761_g1_bytes + bw6_761_g2_bytes) +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const points: Buffer[] = [0, 1, 2, 3, 4, 5, 6, 7].map((i: number) =>
    inputData.slice(i * bw6_761_g1_bytes, (i + 1) * bw6_761_g1_bytes),
  )
  const output = Buffer.alloc(32)
  output[31] = libff_bw6_761_ecpairing(points) ? 1 : 0

  console.log('bw6_761_ecpairing_pc: libff_bw6_761_ecpairing returned ' + output[31])
  return { gasUsed, returnValue: output }
}
