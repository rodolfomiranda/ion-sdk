/// <reference types="node" />
/**
 * Class that performs hashing operations using the multihash format.
 */
export default class Multihash {
    /**
     * Hashes the content using the hashing algorithm specified.
     * @param hashAlgorithmInMultihashCode The hashing algorithm to use. If not given, latest supported hashing algorithm will be used.
     * @returns A multihash buffer.
     */
    static hash(content: Buffer, hashAlgorithmInMultihashCode: number): Buffer;
    /**
     * Hashes the content using the hashing algorithm specified as a generic (non-multihash) hash.
     * @param hashAlgorithmInMultihashCode The hashing algorithm to use. If not given, latest supported hashing algorithm will be used.
     * @returns A multihash buffer.
     */
    static hashAsNonMultihashBuffer(content: Buffer, hashAlgorithmInMultihashCode: number): Buffer;
    /**
     * Canonicalize the given content, then double hashes the result using the latest supported hash algorithm, then encodes the multihash.
     * Mainly used for testing purposes.
     */
    static canonicalizeThenHashThenEncode(content: object, hashAlgorithmInMultihashCode: number): string;
    /**
     * Canonicalize the given content, then double hashes the result using the latest supported hash algorithm, then encodes the multihash.
     * Mainly used for testing purposes.
     */
    static canonicalizeThenDoubleHashThenEncode(content: object, hashAlgorithmInMultihashCode: number): string;
    /**
     * Hashes the content using the hashing algorithm specified then codes the multihash buffer.
     * @param hashAlgorithmInMultihashCode The hashing algorithm to use.
     */
    static hashThenEncode(content: Buffer, hashAlgorithmInMultihashCode: number): string;
    /**
     * Checks if the given encoded hash is a multihash computed using the configured hashing algorithm.
     */
    static validateEncodedHashComputedUsingSupportedHashAlgorithm(encodedMultihash: string, inputContextForErrorLogging: string): void;
}
