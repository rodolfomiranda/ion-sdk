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
const secp256k1_key_pair_1 = require("@transmute/secp256k1-key-pair");
const ed25519_key_pair_1 = require("@transmute/ed25519-key-pair");
const InputValidator_1 = require("./InputValidator");
const randomBytes = require('randombytes');
/**
 * Class containing operations related to keys used in ION.
 */
class IonKey {
    /**
     * Generates SECP256K1 key pair to be used in an operation.
     * Mainly used for testing.
     * @returns [publicKey, privateKey]
     */
    static generateEs256kDidDocumentKeyPair(input) {
        return __awaiter(this, void 0, void 0, function* () {
            const id = input.id;
            const purposes = input.purposes;
            InputValidator_1.default.validateId(id);
            InputValidator_1.default.validatePublicKeyPurposes(purposes);
            const [publicKey, privateKey] = yield IonKey.generateEs256kKeyPair();
            const publicKeyModel = {
                id,
                type: 'EcdsaSecp256k1VerificationKey2019',
                publicKeyJwk: publicKey
            };
            // Only add the `purposes` property If given `purposes` array has at least an entry.
            if (purposes !== undefined && purposes.length > 0) {
                publicKeyModel.purposes = purposes;
            }
            return [publicKeyModel, privateKey];
        });
    }
    /**
     * Generates SECP256K1 key pair for ION operation use.
     * @returns [publicKey, privateKey]
     */
    static generateEs256kOperationKeyPair() {
        return __awaiter(this, void 0, void 0, function* () {
            const keyPair = yield IonKey.generateEs256kKeyPair();
            return keyPair;
        });
    }
    static generateEs256kKeyPair() {
        return __awaiter(this, void 0, void 0, function* () {
            const keyPair = yield secp256k1_key_pair_1.Secp256k1KeyPair.generate({
                secureRandom: () => randomBytes(32)
            });
            const exportedKeypair = yield keyPair.export({
                type: 'JsonWebKey2020',
                privateKey: true
            });
            const { publicKeyJwk, privateKeyJwk } = exportedKeypair;
            return [publicKeyJwk, privateKeyJwk];
        });
    }
    /**
     * Generates Ed25519 key pair to be used in an operation.
     * Mainly used for testing.
     * @returns [publicKey, privateKey]
     */
    static generateEd25519DidDocumentKeyPair(input) {
        return __awaiter(this, void 0, void 0, function* () {
            const id = input.id;
            const purposes = input.purposes;
            InputValidator_1.default.validateId(id);
            InputValidator_1.default.validatePublicKeyPurposes(purposes);
            const [publicKey, privateKey] = yield IonKey.generateEd25519KeyPair();
            const publicKeyModel = {
                id,
                type: 'JsonWebKey2020',
                publicKeyJwk: publicKey
            };
            // Only add the `purposes` property If given `purposes` array has at least an entry.
            if (purposes !== undefined && purposes.length > 0) {
                publicKeyModel.purposes = purposes;
            }
            return [publicKeyModel, privateKey];
        });
    }
    /**
     * Generates Ed25519 key pair for ION operation use.
     * @returns [publicKey, privateKey]
     */
    static generateEd25519OperationKeyPair() {
        return __awaiter(this, void 0, void 0, function* () {
            const keyPair = yield IonKey.generateEd25519KeyPair();
            return keyPair;
        });
    }
    static generateEd25519KeyPair() {
        return __awaiter(this, void 0, void 0, function* () {
            const keyPair = yield ed25519_key_pair_1.Ed25519KeyPair.generate({
                secureRandom: () => randomBytes(32)
            });
            const exportedKeypair = yield keyPair.export({
                type: 'JsonWebKey2020',
                privateKey: true
            });
            const { publicKeyJwk, privateKeyJwk } = exportedKeypair;
            return [publicKeyJwk, privateKeyJwk];
        });
    }
    static isJwkEs256k(key) {
        return key.crv === 'secp256k1' && key.kty === 'EC';
    }
    ;
    static isJwkEd25519(key) {
        return key.crv === 'Ed25519' && key.kty === 'OKP';
    }
    ;
}
exports.default = IonKey;
//# sourceMappingURL=IonKey.js.map