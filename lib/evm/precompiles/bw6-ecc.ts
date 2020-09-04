import BN = require('bn.js')
import { PrecompileInput } from './types'
import { OOGResult, ExecResult } from '../evm'

const fq_bytes = 3*32
const g1_bytes = 2*fq_bytes


// TODO: Replace these with libff-node calls
function libff_bw6_ecadd(
    pointA: Buffer,
    pointB: Buffer,
    output: Buffer): boolean
{
    console.log("libff_bw6_ecadd: A: " + pointA.toString('hex'))
    console.log("libff_bw6_ecadd: B: " + pointB.toString('hex'))
    console.log("libff_bw6_ecadd: output: " + output.toString('hex'))

    output.write(
        "00760cbf3c77666f2cba2ffb4401e3830697a50fe7a46c2f977b37cb5426a6b6cc8b6490bff2cf4562cb257e40f125d63f2a6253191df6dfed26c3e04ea99fd31ce4f347362471546de61475ea28dfaffae215beca593115e51f11d5590ce44300e01244b4533b8aef899bbc446a8b772a20b1cbd837226f41667505467dcbc76606a730e8f55a651e3e5ffb15f213d2def6835ab538138092a86d1b27f56c42483645bdf02337291594523fe6f46a7890e31fc1a527a3fffd21fb31e735da5e", 'hex');
    return true;
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
///
/// INPUT: [ A[0], A[1], A[2], B[0], B[1], B[2] ]  (2 * 6 words = 192 bytes)
/// OUTPUT [ result[0], result[1], result[2] ]
export function bw6_ecadd_pc(opts: PrecompileInput): ExecResult {

    // TODO: gas
    // const gasUsed = new BN(opts._common.param('gasPrices', 'ecRecover'))
    const gasUsed = new BN(0x8000)

    const inputData = opts.data

    console.log("bw6_ecadd_pc: inputData (" + inputData.length + "): " + inputData.toString('hex'))

    if (inputData.length != (2 * g1_bytes)) {
        console.log(
            "bw6_ecadd_pc: invalid input length (" + inputData.length +
            ", expetced " + 2*g1_bytes + ")")
        return { gasUsed, returnValue: Buffer.alloc(0) }
    }

    const a = inputData.slice(0, g1_bytes)
    const b = inputData.slice(g1_bytes)
    const out = Buffer.alloc(g1_bytes)
    if (!libff_bw6_ecadd(a, b, out)) {
        console.log("bw6_ecadd_pc: libff_bw6_ecadd failed")
        return { gasUsed, returnValue: Buffer.alloc(0) }
    }

    return { gasUsed, returnValue: out }
}

// export function bw6_ecadd_pc(opts: PrecompileInput): ExecResult {
//     const gasUsed = new BN(opts._common.param('gasPrices', 'ecRecover'))

//     var out = Buffer.alloc(32);
//     out[31] = 0xc6;
//     return {
//         gasUsed,
//         returnValue: out,
//     }
// }
