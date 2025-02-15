"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto-js");
const Encoder_1 = require("./Encoder");
const ErrorCode_1 = require("./ErrorCode");
const IonError_1 = require("./IonError");
const IonSdkConfig_1 = require("./IonSdkConfig");
const JsonCanonicalizer_1 = require("./JsonCanonicalizer");
const multihashes = require('multihashes');
/**
 * Class that performs hashing operations using the multihash format.
 */
class Multihash {
    /**
     * Hashes the content using the hashing algorithm specified.
     * @param hashAlgorithmInMultihashCode The hashing algorithm to use. If not given, latest supported hashing algorithm will be used.
     * @returns A multihash buffer.
     */
    static hash(content, hashAlgorithmInMultihashCode) {
        const conventionalHash = this.hashAsNonMultihashBuffer(content, hashAlgorithmInMultihashCode);
        const multihash = multihashes.encode(conventionalHash, hashAlgorithmInMultihashCode);
        return multihash;
    }
    /**
     * Hashes the content using the hashing algorithm specified as a generic (non-multihash) hash.
     * @param hashAlgorithmInMultihashCode The hashing algorithm to use. If not given, latest supported hashing algorithm will be used.
     * @returns A multihash buffer.
     */
    static hashAsNonMultihashBuffer(content, hashAlgorithmInMultihashCode) {
        let hash;
        switch (hashAlgorithmInMultihashCode) {
            case 18: // SHA256
                // hash = crypto.createHash('sha256').update(content).digest();
                hash = crypto.SHA256(content.toString());
                break;
            default:
                throw new IonError_1.default(ErrorCode_1.default.MultihashUnsupportedHashAlgorithm, `Hash algorithm defined in multihash code ${hashAlgorithmInMultihashCode} is not supported.`);
        }
        return Buffer.from(hash.toString());
    }
    /**
     * Canonicalize the given content, then double hashes the result using the latest supported hash algorithm, then encodes the multihash.
     * Mainly used for testing purposes.
     */
    static canonicalizeThenHashThenEncode(content, hashAlgorithmInMultihashCode) {
        const canonicalizedStringBuffer = JsonCanonicalizer_1.default.canonicalizeAsBuffer(content);
        const multihashEncodedString = Multihash.hashThenEncode(canonicalizedStringBuffer, hashAlgorithmInMultihashCode);
        return multihashEncodedString;
    }
    /**
     * Canonicalize the given content, then double hashes the result using the latest supported hash algorithm, then encodes the multihash.
     * Mainly used for testing purposes.
     */
    static canonicalizeThenDoubleHashThenEncode(content, hashAlgorithmInMultihashCode) {
        const contentBuffer = JsonCanonicalizer_1.default.canonicalizeAsBuffer(content);
        // Double hash.
        const intermediateHashBuffer = Multihash.hashAsNonMultihashBuffer(contentBuffer, hashAlgorithmInMultihashCode);
        const multihashEncodedString = Multihash.hashThenEncode(intermediateHashBuffer, hashAlgorithmInMultihashCode);
        return multihashEncodedString;
    }
    /**
     * Hashes the content using the hashing algorithm specified then codes the multihash buffer.
     * @param hashAlgorithmInMultihashCode The hashing algorithm to use.
     */
    static hashThenEncode(content, hashAlgorithmInMultihashCode) {
        const multihashBuffer = Multihash.hash(content, hashAlgorithmInMultihashCode);
        const multihashEncodedString = Encoder_1.default.encode(multihashBuffer);
        return multihashEncodedString;
    }
    /**
     * Checks if the given encoded hash is a multihash computed using the configured hashing algorithm.
     */
    static validateEncodedHashComputedUsingSupportedHashAlgorithm(encodedMultihash, inputContextForErrorLogging) {
        let multihash;
        const multihashBuffer = Encoder_1.default.decodeAsBuffer(encodedMultihash, inputContextForErrorLogging);
        try {
            multihash = multihashes.decode(multihashBuffer);
        }
        catch (_a) {
            throw new IonError_1.default(ErrorCode_1.default.MultihashStringNotAMultihash, `Given ${inputContextForErrorLogging} string '${encodedMultihash}' is not a multihash after decoding.`);
        }
        const hashAlgorithmInMultihashCode = IonSdkConfig_1.default.hashAlgorithmInMultihashCode;
        if (hashAlgorithmInMultihashCode !== multihash.code) {
            throw new IonError_1.default(ErrorCode_1.default.MultihashUnsupportedHashAlgorithm, `Given ${inputContextForErrorLogging} uses unsupported multihash algorithm with code ${multihash.code}, ` +
                `should use ${hashAlgorithmInMultihashCode} or change IonSdkConfig to desired hashing algorithm.`);
        }
    }
}
exports.default = Multihash;
//# sourceMappingURL=Multihash.js.map