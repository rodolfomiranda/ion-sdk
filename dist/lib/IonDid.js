"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Encoder_1 = require("./Encoder");
const IonRequest_1 = require("./IonRequest");
const IonSdkConfig_1 = require("./IonSdkConfig");
const JsonCanonicalizer_1 = require("./JsonCanonicalizer");
const Multihash_1 = require("./Multihash");
/**
 * Class containing DID related operations.
 */
class IonDid {
    /**
     * Creates a long-form DID.
     * @param input.document The initial state to be associate with the ION DID to be created using a `replace` document patch action.
     */
    static createLongFormDid(input) {
        const createRequest = IonRequest_1.default.createCreateRequest(input);
        const didUniqueSuffix = IonDid.computeDidUniqueSuffix(createRequest.suffixData);
        // Add the network portion if not configured for mainnet.
        let shortFormDid;
        if (IonSdkConfig_1.default.network === undefined || IonSdkConfig_1.default.network === 'mainnet') {
            shortFormDid = `did:ion:${didUniqueSuffix}`;
        }
        else {
            shortFormDid = `did:ion:${IonSdkConfig_1.default.network}:${didUniqueSuffix}`;
        }
        const initialState = {
            suffixData: createRequest.suffixData,
            delta: createRequest.delta
        };
        // Initial state must be canonicalized as per spec.
        const canonicalizedInitialStateBuffer = JsonCanonicalizer_1.default.canonicalizeAsBuffer(initialState);
        const encodedCanonicalizedInitialStateString = Encoder_1.default.encode(canonicalizedInitialStateBuffer);
        const longFormDid = `${shortFormDid}:${encodedCanonicalizedInitialStateString}`;
        return longFormDid;
    }
    /**
     * Computes the DID unique suffix given the encoded suffix data string.
     */
    static computeDidUniqueSuffix(suffixData) {
        const canonicalizedStringBuffer = JsonCanonicalizer_1.default.canonicalizeAsBuffer(suffixData);
        const multihash = Multihash_1.default.hash(canonicalizedStringBuffer, IonSdkConfig_1.default.hashAlgorithmInMultihashCode);
        const encodedMultihash = Encoder_1.default.encode(multihash);
        return encodedMultihash;
    }
}
exports.default = IonDid;
//# sourceMappingURL=IonDid.js.map