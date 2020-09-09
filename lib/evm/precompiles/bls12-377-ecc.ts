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
//
// Gas prices (hard-coded here to keep this change as encapsulated as
// possible for now), are based on the NATIVE data sizes compared to
// the existing alt_bn128 operations for now.  (G1 and G2 are
// approximately 1.5 times the size of alt_bn128).  Proper cost
// estimates are required to get accurate fair prices.
//
// ----------+---------------------+---------------------------------
// Operation | Price               | Calculation
// ----------+---------------------+---------------------------------
// ECADD     |                 225 | (= 150 * 1.5)
// ECMUL     |               9,000 | (= 6,000 * 1.5)
// ECPAIRING | 77,500 + k * 51,000 | (~ (45,000 + k * 34,000) * 1.5)
// ----------+---------------------+---------------------------------

// Size of scalar Fr element as represented in evm words
const FR_EVM_SIZE = 32

// Size of Fq element as represented in evm words
const FQ_EVM_SIZE = 2 * 32

// Size of G1 element as represented in evm words
const G1_EVM_SIZE = 2 * FQ_EVM_SIZE

// Size of G2 element as represented in evm words
const G2_EVM_SIZE = 4 * FQ_EVM_SIZE

// Size of G1,G2 pair
const G1G2_PAIR_EVM_SIZE = G1_EVM_SIZE + G2_EVM_SIZE

// Offset of the start of an fq number within a double evm word.
const FQ_EVM_START_OFFSET = FQ_EVM_SIZE - bls12_377.fq_bytes

// TODO: Abstract some of this buffer code behind iterators

// Convert an Fq element in evm words to a buffer suitable for
// libff.js.
function fq_evm_to_ff(
  fq_evm: Buffer,
  fq_evm_offset: number,
  fq_ff: Buffer,
  fq_ff_offset: number,
): void {
  const src_start = fq_evm_offset + FQ_EVM_START_OFFSET
  fq_evm.copy(fq_ff, fq_ff_offset, src_start, src_start + bls12_377.fq_bytes)
}

// Convert Fq element from libff into some evm words.
function fq_ff_to_evm(
  fq_ff_buffer: Buffer,
  fq_ff_offset: number,
  fq_evm_buffer: Buffer,
  fq_evm_offset: number,
): void {
  fq_ff_buffer.copy(
    fq_evm_buffer,
    fq_evm_offset + FQ_EVM_START_OFFSET,
    fq_ff_offset,
    fq_ff_offset + bls12_377.fq_bytes,
  )
}

// Extract a scalar in ff rperesentation from a buffer of evm words.
function fr_evm_to_ff(evm_buffer: Buffer, fr_evm_offset: number): Buffer {
  return evm_buffer.slice(fr_evm_offset, fr_evm_offset + bls12_377.fr_bytes)
}

// Convert a G1 element in evm words into an ff buffer
function g1_evm_to_ff(evm_buffer: Buffer, g1_evm_offset: number): Buffer {
  var out_g1 = Buffer.alloc(bls12_377.g1_bytes)
  fq_evm_to_ff(evm_buffer, g1_evm_offset, out_g1, 0)
  fq_evm_to_ff(evm_buffer, g1_evm_offset + FQ_EVM_SIZE, out_g1, bls12_377.fq_bytes)
  return out_g1
}

// Convert a G1 element in an ff buffer to evm representation
function g1_ff_to_evm(
  g1_ff_buffer: Buffer,
  g1_ff_offset: number,
  g1_evm_buffer: Buffer,
  g1_evm_offset: number,
): void {
  fq_ff_to_evm(g1_ff_buffer, g1_ff_offset, g1_evm_buffer, g1_evm_offset)
  fq_ff_to_evm(
    g1_ff_buffer,
    g1_ff_offset + bls12_377.fq_bytes,
    g1_evm_buffer,
    g1_evm_offset + FQ_EVM_SIZE,
  )
}

// Convert a G1 element in evm words into an ff buffer
function g2_evm_to_ff(evm_buffer: Buffer, g2_evm_offset: number): Buffer {
  var out_g2 = Buffer.alloc(bls12_377.g2_bytes)
  fq_evm_to_ff(evm_buffer, g2_evm_offset + 0 * FQ_EVM_SIZE, out_g2, 0 * bls12_377.fq_bytes)
  fq_evm_to_ff(evm_buffer, g2_evm_offset + 1 * FQ_EVM_SIZE, out_g2, 1 * bls12_377.fq_bytes)
  fq_evm_to_ff(evm_buffer, g2_evm_offset + 2 * FQ_EVM_SIZE, out_g2, 2 * bls12_377.fq_bytes)
  fq_evm_to_ff(evm_buffer, g2_evm_offset + 3 * FQ_EVM_SIZE, out_g2, 3 * bls12_377.fq_bytes)
  return out_g2
}

/// BLS12_377_ECADD precompiled contract entry point.  Accepts two
/// BLS12-377 curve points A and B in a single array, and returns A +
/// B (where + is the group operation).
export function bls12_377_ecadd_pc(opts: PrecompileInput): ExecResult {
  const gasUsed = new BN(225)
  if (opts.gasLimit.lt(gasUsed)) {
    return OOGResult(opts.gasLimit)
  }

  const inputData = opts.data
  if (inputData.length != 2 * G1_EVM_SIZE) {
    console.log(
      'bls12_377_ecadd_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        2 * bls12_377.g1_bytes +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const a_ff = g1_evm_to_ff(inputData, 0)
  const b_ff = g1_evm_to_ff(inputData, G1_EVM_SIZE)
  const out_ff = Buffer.alloc(bls12_377.g1_bytes)
  if (!bls12_377.ecadd(a_ff, b_ff, out_ff)) {
    console.log('bls12_377_ecadd_pc: libff_bls12_377_ecadd failed')
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const out_evm = Buffer.alloc(G1_EVM_SIZE)
  g1_ff_to_evm(out_ff, 0, out_evm, 0)
  return { gasUsed, returnValue: out_evm }
}

/// BLS12_377_ECMUL precompiled contract entry point. Input data should be
/// an array with a curve point followed by a scalar.
export function bls12_377_ecmul_pc(opts: PrecompileInput): ExecResult {
  const gasUsed = new BN(9000)
  if (opts.gasLimit.lt(gasUsed)) {
    return OOGResult(opts.gasLimit)
  }

  const inputData = opts.data

  if (inputData.length != G1_EVM_SIZE + FR_EVM_SIZE) {
    console.log(
      'bls12_377_ecmul_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        G1_EVM_SIZE +
        FR_EVM_SIZE +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const point_ff = g1_evm_to_ff(inputData, 0)
  const scalar_ff = fr_evm_to_ff(inputData, G1_EVM_SIZE)
  const out_ff = Buffer.alloc(bls12_377.g1_bytes)
  if (!bls12_377.ecmul(point_ff, scalar_ff, out_ff)) {
    console.log('bls12_377_ecmul_pc: libff_bls12_377_ecmul failed')
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const out_evm = Buffer.alloc(G1_EVM_SIZE)
  g1_ff_to_evm(out_ff, 0, out_evm, 0)
  return { gasUsed, returnValue: out_evm }
}

/// BLS12_377_ECPAIRING precompiled contract entry point. Input data should
/// be k pairs, each containing a G1 point followed by a G2 point.
/// TODO: k is currently hard-coded to 4.
export function bls12_377_ecpairing_pc(opts: PrecompileInput): ExecResult {
  const k = 4
  const gasUsed = new BN(77500 + k * 51000)
  if (opts.gasLimit.lt(gasUsed)) {
    return OOGResult(opts.gasLimit)
  }

  const inputData = opts.data
  if (inputData.length != k * G1G2_PAIR_EVM_SIZE) {
    console.log(
      'bls12_377_ecpairing_pc: invalid input length (' +
        inputData.length +
        ', expected ' +
        k * G1G2_PAIR_EVM_SIZE +
        ')',
    )
    return { gasUsed, returnValue: Buffer.alloc(0) }
  }

  const points: Buffer[] = [
    g1_evm_to_ff(inputData, 0 * G1G2_PAIR_EVM_SIZE),
    g2_evm_to_ff(inputData, 0 * G1G2_PAIR_EVM_SIZE + G1_EVM_SIZE),
    g1_evm_to_ff(inputData, 1 * G1G2_PAIR_EVM_SIZE),
    g2_evm_to_ff(inputData, 1 * G1G2_PAIR_EVM_SIZE + G1_EVM_SIZE),
    g1_evm_to_ff(inputData, 2 * G1G2_PAIR_EVM_SIZE),
    g2_evm_to_ff(inputData, 2 * G1G2_PAIR_EVM_SIZE + G1_EVM_SIZE),
    g1_evm_to_ff(inputData, 3 * G1G2_PAIR_EVM_SIZE),
    g2_evm_to_ff(inputData, 3 * G1G2_PAIR_EVM_SIZE + G1_EVM_SIZE),
  ]

  const out_evm = Buffer.alloc(32)
  out_evm[31] = bls12_377.ecpairing(points) ? 1 : 0
  return { gasUsed, returnValue: out_evm }
}
