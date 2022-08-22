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
const InputValidator_1 = require("./InputValidator");
const jose_ld_1 = require("@transmute/jose-ld");
const OperationKeyType_1 = require("./enums/OperationKeyType");
const secp256k1_key_pair_1 = require("@transmute/secp256k1-key-pair");
/**
 * An ISigner implementation that uses a given local private key.
 */
class LocalSigner {
    constructor(privateKey) {
        this.privateKey = privateKey;
        InputValidator_1.default.validateEs256kOperationKey(privateKey, OperationKeyType_1.default.Private);
    }
    /**
     * Creates a new local signer using the given private key.
     */
    static create(privateKey) {
        return new LocalSigner(privateKey);
    }
    sign(header, content) {
        return __awaiter(this, void 0, void 0, function* () {
            const publicKeyJwk = Object.assign(Object.assign({}, this.privateKey), { d: undefined });
            const key = yield secp256k1_key_pair_1.Secp256k1KeyPair.from({
                type: 'JsonWebKey2020',
                publicKeyJwk,
                privateKeyJwk: this.privateKey
            });
            const signer = key.signer();
            const jwsSigner = yield jose_ld_1.JWS.createSigner(signer, 'ES256K', {
                detached: false,
                header
            });
            const compactJws = yield jwsSigner.sign({ data: content });
            return compactJws;
        });
    }
}
exports.default = LocalSigner;
//# sourceMappingURL=LocalSigner.js.map