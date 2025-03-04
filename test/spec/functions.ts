import {
	PublicKey,
	SecretKey,
	Signature,
	type SignatureSet,
	verify as VERIFY,
	aggregatePublicKeys,
	aggregateSignatures,
	aggregateVerify,
	fastAggregateVerify,
	verifyMultipleAggregateSignatures,
} from "../../src/index.ts";
import {fromHex} from "../utils/helpers.ts";
import {type CodeError} from "../utils/types.ts";
import {G2_POINT_AT_INFINITY} from "./utils.js";

export const testFnByName: Record<string, (data: any) => any> = {
	sign,
	eth_aggregate_pubkeys: ethAggregatePubkeys,
	aggregate,
	verify,
	aggregate_verify,
	fast_aggregate_verify,
	eth_fast_aggregate_verify: ethFastAggregateVerify,
	batch_verify: batchVerify,
	deserialization_G1: deserializationG1,
	deserialization_G2: deserializationG2,
};

function catchBLSTError(e: unknown): boolean {
	if ((e as CodeError).code?.startsWith("BLST")) return false;
	throw e;
}

/**
 * ```
 * input: List[BLS Signature] -- list of input BLS signatures
 * output: BLS Signature -- expected output, single BLS signature or empty.
 * ```
 */
function aggregate(input: string[]): string | null {
	return aggregateSignatures(input.map((hex) => Signature.fromHex(hex))).toHex();
}

/**
 * ```
 * input:
 *   pubkeys: List[BLS Pubkey] -- the pubkeys
 *   messages: List[bytes32] -- the messages
 *   signature: BLS Signature -- the signature to verify against pubkeys and messages
 * output: bool  --  true (VALID) or false (INVALID)
 * ```
 */
function aggregate_verify(input: {
	pubkeys: string[];
	messages: string[];
	signature: string;
}): boolean {
	const {pubkeys, messages, signature} = input;
	try {
		return aggregateVerify(
			messages.map(fromHex),
			pubkeys.map((hex) => PublicKey.fromHex(hex)),
			Signature.fromHex(signature)
		);
	} catch (e) {
		return catchBLSTError(e);
	}
}

/**
 * ```
 * input: List[BLS Signature] -- list of input BLS signatures
 * output: BLS Signature -- expected output, single BLS signature or empty.
 * ```
 */
function ethAggregatePubkeys(input: string[]): string | null {
	return aggregatePublicKeys(input.map((hex) => PublicKey.fromHex(hex, true))).toHex();
}

/**
 * ```
 * input:
 *   pubkeys: List[BLS Pubkey] -- list of input BLS pubkeys
 *   message: bytes32 -- the message
 *   signature: BLS Signature -- the signature to verify against pubkeys and message
 * output: bool  --  true (VALID) or false (INVALID)
 * ```
 */
function ethFastAggregateVerify(input: {
	pubkeys: string[];
	message: string;
	signature: string;
}): boolean {
	const {pubkeys, message, signature} = input;

	if (pubkeys.length === 0 && signature === G2_POINT_AT_INFINITY) {
		return true;
	}

	try {
		return fastAggregateVerify(
			fromHex(message),
			pubkeys.map((hex) => PublicKey.fromHex(hex, true)),
			Signature.fromHex(signature)
		);
	} catch (e) {
		return catchBLSTError(e);
	}
}

/**
 * ```
 * input:
 *   pubkeys: List[BLS Pubkey] -- list of input BLS pubkeys
 *   message: bytes32 -- the message
 *   signature: BLS Signature -- the signature to verify against pubkeys and message
 * output: bool  --  true (VALID) or false (INVALID)
 * ```
 */
function fast_aggregate_verify(input: {
	pubkeys: string[];
	message: string;
	signature: string;
}): boolean {
	const {pubkeys, message, signature} = input;

	try {
		return fastAggregateVerify(
			fromHex(message),
			pubkeys.map((hex) => PublicKey.fromHex(hex, true)),
			Signature.fromHex(signature)
		);
	} catch (e) {
		return catchBLSTError(e);
	}
}

/**
 * input:
 *   privkey: bytes32 -- the private key used for signing
 *   message: bytes32 -- input message to sign (a hash)
 * output: BLS Signature -- expected output, single BLS signature or empty.
 */
function sign(input: {privkey: string; message: string}): string | null {
	const {privkey, message} = input;
	return SecretKey.fromHex(privkey).sign(fromHex(message)).toHex();
}

/**
 * input:
 *   pubkey: bytes48 -- the pubkey
 *   message: bytes32 -- the message
 *   signature: bytes96 -- the signature to verify against pubkey and message
 * output: bool  -- VALID or INVALID
 */
function verify(input: {
	pubkey: string;
	message: string;
	signature: string;
}): boolean {
	const {pubkey, message, signature} = input;
	try {
		return VERIFY(fromHex(message), PublicKey.fromHex(pubkey), Signature.fromHex(signature));
	} catch (e) {
		return catchBLSTError(e);
	}
}

/**
 * ```
 * input:
 *   pubkeys: List[bytes48] -- the pubkeys
 *   messages: List[bytes32] -- the messages
 *   signatures: List[bytes96] -- the signatures to verify against pubkeys and messages
 * output: bool  -- VALID or INVALID
 * ```
 * https://github.com/ethereum/bls12-381-tests/blob/master/formats/batch_verify.md
 */
function batchVerify(input: {
	pubkeys: string[];
	messages: string[];
	signatures: string[];
}): boolean | null {
	const length = input.pubkeys.length;
	if (input.messages.length !== length && input.signatures.length !== length) {
		throw new Error("Invalid spec test. Must have same number in each array. Check spec yaml file");
	}
	const sets: SignatureSet[] = [];
	try {
		for (let i = 0; i < length; i++) {
			sets.push({
				msg: fromHex(input.messages[i]),
				pk: PublicKey.fromHex(input.pubkeys[i]),
				sig: Signature.fromHex(input.signatures[i]),
			});
		}
		return verifyMultipleAggregateSignatures(sets);
	} catch (e) {
		return catchBLSTError(e);
	}
}

/**
 * ```
 * input: pubkey: bytes48 -- the pubkey
 * output: bool  -- VALID or INVALID
 * ```
 * https://github.com/ethereum/bls12-381-tests/blob/master/formats/deserialization_G1.md
 */
function deserializationG1(input: {pubkey: string}): boolean {
	try {
		PublicKey.fromHex(input.pubkey, true);
		return true;
	} catch (e) {
		return catchBLSTError(e);
	}
}

/**
 * ```
 * input: signature: bytes92 -- the signature
 * output: bool  -- VALID or INVALID
 * ```
 * https://github.com/ethereum/bls12-381-tests/blob/master/formats/deserialization_G2.md
 */
function deserializationG2(input: {signature: string}): boolean {
	try {
		Signature.fromHex(input.signature, true);
		return true;
	} catch (e) {
		return catchBLSTError(e);
	}
}
