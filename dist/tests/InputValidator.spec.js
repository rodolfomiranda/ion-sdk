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
const InputValidator_1 = require("../lib/InputValidator");
const OperationKeyType_1 = require("../lib/enums/OperationKeyType");
describe('IonKey', () => __awaiter(void 0, void 0, void 0, function* () {
    describe('validateEs256kOperationKey', () => {
        it('should throw if given private key does not have d', () => {
            const publicKey = require('./vectors/inputs/jwkEs256k1Public.json');
            try {
                InputValidator_1.default.validateEs256kOperationKey(publicKey, OperationKeyType_1.default.Private);
                fail();
            }
            catch (e) {
                expect(e.message).toEqual(`JwkEs256kHasIncorrectLengthOfD: SECP256K1 JWK 'd' property must be 43 bytes.`);
            }
        });
        it('should throw if given private key d value is not the correct length', () => {
            const privateKey = require('./vectors/inputs/jwkEs256k1Private.json');
            const privateKeyClone = Object.assign({}, privateKey); // Make a copy so this test does not affect other tests.
            privateKeyClone.d = 'abc';
            try {
                InputValidator_1.default.validateEs256kOperationKey(privateKeyClone, OperationKeyType_1.default.Private);
                fail();
            }
            catch (e) {
                expect(e.message).toEqual(`JwkEs256kHasIncorrectLengthOfD: SECP256K1 JWK 'd' property must be 43 bytes.`);
            }
        });
    });
}));
//# sourceMappingURL=InputValidator.spec.js.map