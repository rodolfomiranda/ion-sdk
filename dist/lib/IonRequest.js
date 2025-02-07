"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const URI = require("uri-js");
const ErrorCode_1 = require("./ErrorCode");
const InputValidator_1 = require("./InputValidator");
const IonError_1 = require("./IonError");
const IonSdkConfig_1 = require("./IonSdkConfig");
const JsonCanonicalizer_1 = require("./JsonCanonicalizer");
const Multihash_1 = require("./Multihash");
const OperationKeyType_1 = require("./enums/OperationKeyType");
const OperationType_1 = require("./enums/OperationType");
const PatchAction_1 = require("./enums/PatchAction");
/**
 * Class containing operations related to ION requests.
 */
class IonRequest {
    /**
     * Creates an ION DID create request.
     * @param input.document The initial state to be associate with the ION DID to be created using a `replace` document patch action.
     */
    static createCreateRequest(input) {
        const recoveryKey = input.recoveryKey;
        const updateKey = input.updateKey;
        const didDocumentKeys = input.document.publicKeys;
        const services = input.document.services;
        // Validate recovery and update public keys.
        InputValidator_1.default.validateEs256kOperationKey(recoveryKey, OperationKeyType_1.default.Public);
        InputValidator_1.default.validateEs256kOperationKey(updateKey, OperationKeyType_1.default.Public);
        // Validate all given DID Document keys.
        IonRequest.validateDidDocumentKeys(didDocumentKeys);
        // Validate all given service.
        IonRequest.validateServices(services);
        const hashAlgorithmInMultihashCode = IonSdkConfig_1.default.hashAlgorithmInMultihashCode;
        const patches = [{
                action: PatchAction_1.default.Replace,
                document: input.document
            }];
        const delta = {
            updateCommitment: Multihash_1.default.canonicalizeThenDoubleHashThenEncode(updateKey, hashAlgorithmInMultihashCode),
            patches
        };
        IonRequest.validateDeltaSize(delta);
        const deltaHash = Multihash_1.default.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);
        const suffixData = {
            deltaHash,
            recoveryCommitment: Multihash_1.default.canonicalizeThenDoubleHashThenEncode(recoveryKey, hashAlgorithmInMultihashCode)
        };
        const operationRequest = {
            type: OperationType_1.default.Create,
            suffixData: suffixData,
            delta: delta
        };
        return operationRequest;
    }
    static createDeactivateRequest(input) {
        return __awaiter(this, void 0, void 0, function* () {
            // Validate DID suffix
            IonRequest.validateDidSuffix(input.didSuffix);
            // Validates recovery public key
            InputValidator_1.default.validateEs256kOperationKey(input.recoveryPublicKey, OperationKeyType_1.default.Public);
            const hashAlgorithmInMultihashCode = IonSdkConfig_1.default.hashAlgorithmInMultihashCode;
            const revealValue = Multihash_1.default.canonicalizeThenHashThenEncode(input.recoveryPublicKey, hashAlgorithmInMultihashCode);
            const dataToBeSigned = {
                didSuffix: input.didSuffix,
                recoveryKey: input.recoveryPublicKey
            };
            const compactJws = yield input.signer.sign({ alg: 'ES256K' }, dataToBeSigned);
            return {
                type: OperationType_1.default.Deactivate,
                didSuffix: input.didSuffix,
                revealValue: revealValue,
                signedData: compactJws
            };
        });
    }
    static createRecoverRequest(input) {
        return __awaiter(this, void 0, void 0, function* () {
            // Validate DID suffix
            IonRequest.validateDidSuffix(input.didSuffix);
            // Validate recovery public key
            InputValidator_1.default.validateEs256kOperationKey(input.recoveryPublicKey, OperationKeyType_1.default.Public);
            // Validate next recovery public key
            InputValidator_1.default.validateEs256kOperationKey(input.nextRecoveryPublicKey, OperationKeyType_1.default.Public);
            // Validate next update public key
            InputValidator_1.default.validateEs256kOperationKey(input.nextUpdatePublicKey, OperationKeyType_1.default.Public);
            // Validate all given DID Document keys.
            IonRequest.validateDidDocumentKeys(input.document.publicKeys);
            // Validate all given service.
            IonRequest.validateServices(input.document.services);
            const hashAlgorithmInMultihashCode = IonSdkConfig_1.default.hashAlgorithmInMultihashCode;
            const revealValue = Multihash_1.default.canonicalizeThenHashThenEncode(input.recoveryPublicKey, hashAlgorithmInMultihashCode);
            const patches = [{
                    action: PatchAction_1.default.Replace,
                    document: input.document
                }];
            const nextUpdateCommitmentHash = Multihash_1.default.canonicalizeThenDoubleHashThenEncode(input.nextUpdatePublicKey, hashAlgorithmInMultihashCode);
            const delta = {
                patches,
                updateCommitment: nextUpdateCommitmentHash
            };
            const deltaHash = Multihash_1.default.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);
            const nextRecoveryCommitmentHash = Multihash_1.default.canonicalizeThenDoubleHashThenEncode(input.nextRecoveryPublicKey, hashAlgorithmInMultihashCode);
            const dataToBeSigned = {
                recoveryCommitment: nextRecoveryCommitmentHash,
                recoveryKey: input.recoveryPublicKey,
                deltaHash: deltaHash
            };
            const compactJws = yield input.signer.sign({ alg: 'ES256K' }, dataToBeSigned);
            return {
                type: OperationType_1.default.Recover,
                didSuffix: input.didSuffix,
                revealValue: revealValue,
                delta: delta,
                signedData: compactJws
            };
        });
    }
    static createUpdateRequest(input) {
        return __awaiter(this, void 0, void 0, function* () {
            // Validate DID suffix
            IonRequest.validateDidSuffix(input.didSuffix);
            // Validate update public key
            InputValidator_1.default.validateEs256kOperationKey(input.updatePublicKey, OperationKeyType_1.default.Public);
            // Validate next update public key
            InputValidator_1.default.validateEs256kOperationKey(input.nextUpdatePublicKey, OperationKeyType_1.default.Public);
            // Validate all given service.
            IonRequest.validateServices(input.servicesToAdd);
            // Validate all given DID Document keys.
            IonRequest.validateDidDocumentKeys(input.publicKeysToAdd);
            // Validate all given service id to remove.
            if (input.idsOfServicesToRemove !== undefined) {
                for (const id of input.idsOfServicesToRemove) {
                    InputValidator_1.default.validateId(id);
                }
            }
            // Validate all given public key id to remove.
            if (input.idsOfPublicKeysToRemove !== undefined) {
                for (const id of input.idsOfPublicKeysToRemove) {
                    InputValidator_1.default.validateId(id);
                }
            }
            const patches = [];
            // Create patches for add services
            const servicesToAdd = input.servicesToAdd;
            if (servicesToAdd !== undefined && servicesToAdd.length > 0) {
                const patch = {
                    action: PatchAction_1.default.AddServices,
                    services: servicesToAdd
                };
                patches.push(patch);
            }
            // Create patches for remove services
            const idsOfServicesToRemove = input.idsOfServicesToRemove;
            if (idsOfServicesToRemove !== undefined && idsOfServicesToRemove.length > 0) {
                const patch = {
                    action: PatchAction_1.default.RemoveServices,
                    ids: idsOfServicesToRemove
                };
                patches.push(patch);
            }
            // Create patches for adding public keys
            const publicKeysToAdd = input.publicKeysToAdd;
            if (publicKeysToAdd !== undefined && publicKeysToAdd.length > 0) {
                const patch = {
                    action: PatchAction_1.default.AddPublicKeys,
                    publicKeys: publicKeysToAdd
                };
                patches.push(patch);
            }
            // Create patch for removing public keys
            const idsOfPublicKeysToRemove = input.idsOfPublicKeysToRemove;
            if (idsOfPublicKeysToRemove !== undefined && idsOfPublicKeysToRemove.length > 0) {
                const patch = {
                    action: PatchAction_1.default.RemovePublicKeys,
                    ids: idsOfPublicKeysToRemove
                };
                patches.push(patch);
            }
            const hashAlgorithmInMultihashCode = IonSdkConfig_1.default.hashAlgorithmInMultihashCode;
            const revealValue = Multihash_1.default.canonicalizeThenHashThenEncode(input.updatePublicKey, hashAlgorithmInMultihashCode);
            const nextUpdateCommitmentHash = Multihash_1.default.canonicalizeThenDoubleHashThenEncode(input.nextUpdatePublicKey, hashAlgorithmInMultihashCode);
            const delta = {
                patches,
                updateCommitment: nextUpdateCommitmentHash
            };
            const deltaHash = Multihash_1.default.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);
            const dataToBeSigned = {
                updateKey: input.updatePublicKey,
                deltaHash: deltaHash
            };
            const compactJws = yield input.signer.sign({ alg: 'ES256K' }, dataToBeSigned);
            return {
                type: OperationType_1.default.Update,
                didSuffix: input.didSuffix,
                revealValue,
                delta,
                signedData: compactJws
            };
        });
    }
    static validateDidSuffix(didSuffix) {
        Multihash_1.default.validateEncodedHashComputedUsingSupportedHashAlgorithm(didSuffix, 'didSuffix');
    }
    static validateDidDocumentKeys(publicKeys) {
        if (publicKeys === undefined) {
            return;
        }
        // Validate each public key.
        const publicKeyIdSet = new Set();
        for (const publicKey of publicKeys) {
            if (Array.isArray(publicKey.publicKeyJwk)) {
                throw new IonError_1.default(ErrorCode_1.default.DidDocumentPublicKeyMissingOrIncorrectType, `DID Document key 'publicKeyJwk' property is not a non-array object.`);
            }
            InputValidator_1.default.validateId(publicKey.id);
            // 'id' must be unique across all given keys.
            if (publicKeyIdSet.has(publicKey.id)) {
                throw new IonError_1.default(ErrorCode_1.default.DidDocumentPublicKeyIdDuplicated, `DID Document key with ID '${publicKey.id}' already exists.`);
            }
            publicKeyIdSet.add(publicKey.id);
            InputValidator_1.default.validatePublicKeyPurposes(publicKey.purposes);
        }
    }
    static validateServices(services) {
        if (services !== undefined && services.length !== 0) {
            const serviceIdSet = new Set();
            for (const service of services) {
                IonRequest.validateService(service);
                if (serviceIdSet.has(service.id)) {
                    throw new IonError_1.default(ErrorCode_1.default.DidDocumentServiceIdDuplicated, 'Service id has to be unique');
                }
                serviceIdSet.add(service.id);
            }
        }
    }
    static validateService(service) {
        InputValidator_1.default.validateId(service.id);
        const maxTypeLength = 30;
        if (service.type.length > maxTypeLength) {
            const errorMessage = `Service endpoint type length ${service.type.length} exceeds max allowed length of ${maxTypeLength}.`;
            throw new IonError_1.default(ErrorCode_1.default.ServiceTypeTooLong, errorMessage);
        }
        // Throw error if `serviceEndpoint` is an array.
        if (Array.isArray(service.serviceEndpoint)) {
            const errorMessage = 'Service endpoint value cannot be an array.';
            throw new IonError_1.default(ErrorCode_1.default.ServiceEndpointCannotBeAnArray, errorMessage);
        }
        if (typeof service.serviceEndpoint === 'string') {
            const uri = URI.parse(service.serviceEndpoint);
            if (uri.error !== undefined) {
                throw new IonError_1.default(ErrorCode_1.default.ServiceEndpointStringNotValidUri, `Service endpoint string '${service.serviceEndpoint}' is not a URI.`);
            }
        }
    }
    static validateDeltaSize(delta) {
        const deltaBuffer = JsonCanonicalizer_1.default.canonicalizeAsBuffer(delta);
        if (deltaBuffer.length > IonSdkConfig_1.default.maxCanonicalizedDeltaSizeInBytes) {
            const errorMessage = `Delta of ${deltaBuffer.length} bytes exceeded limit of ${IonSdkConfig_1.default.maxCanonicalizedDeltaSizeInBytes} bytes.`;
            throw new IonError_1.default(ErrorCode_1.default.DeltaExceedsMaximumSize, errorMessage);
        }
    }
}
exports.default = IonRequest;
//# sourceMappingURL=IonRequest.js.map