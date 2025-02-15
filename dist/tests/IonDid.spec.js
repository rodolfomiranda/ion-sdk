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
const jwkEs256k1Public = require("./vectors/inputs/jwkEs256k1Public.json");
const jwkEs256k2Public = require("./vectors/inputs/jwkEs256k2Public.json");
const publicKeyModel1 = require("./vectors/inputs/publicKeyModel1.json");
const service1 = require("./vectors/inputs/service1.json");
const index_1 = require("../lib/index");
const ErrorCode_1 = require("../lib/ErrorCode");
const IonNetwork_1 = require("../lib/enums/IonNetwork");
const JasmineIonErrorValidator_1 = require("./JasmineIonErrorValidator");
const base64_1 = require("@waiting/base64");
describe('IonDid', () => __awaiter(void 0, void 0, void 0, function* () {
    afterEach(() => {
        index_1.IonSdkConfig.network = undefined;
    });
    describe('createLongFormDid()', () => __awaiter(void 0, void 0, void 0, function* () {
        it('vector test - should create a long-form DID correctly.', () => __awaiter(void 0, void 0, void 0, function* () {
            const recoveryKey = jwkEs256k1Public;
            const updateKey = jwkEs256k2Public;
            const didDocumentKeys = [publicKeyModel1];
            const services = [service1];
            const document = {
                publicKeys: didDocumentKeys,
                services
            };
            const longFormDid = index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document });
            const expectedMethodSpecificId = 'did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ';
            expect(longFormDid).toEqual(expectedMethodSpecificId);
        }));
        it('should not generate invalid JSON when `services` and/or `publicKeys` in given document are `undefined`.', () => __awaiter(void 0, void 0, void 0, function* () {
            const recoveryKey = jwkEs256k1Public;
            const updateKey = jwkEs256k2Public;
            const document = {
                publicKeys: undefined,
                services: undefined
            };
            const longFormDid = index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document });
            const indexOfLastColon = longFormDid.lastIndexOf(':');
            const encodedInitialState = longFormDid.substring(indexOfLastColon + 1);
            // Making sure the encoded initial state is still parsable as JSON.
            const initialState = base64_1.b64urlDecode(encodedInitialState);
            JSON.parse(initialState);
        }));
        it('should not include network segment in DID if SDK network is set to mainnet.', () => __awaiter(void 0, void 0, void 0, function* () {
            index_1.IonSdkConfig.network = IonNetwork_1.default.Mainnet;
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const longFormDid = index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document: {} });
            expect(longFormDid.indexOf('mainnet')).toBeLessThan(0);
        }));
        it('should include network segment as "test" in DID if SDK network testnet.', () => __awaiter(void 0, void 0, void 0, function* () {
            index_1.IonSdkConfig.network = IonNetwork_1.default.Testnet;
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const longFormDid = index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document: {} });
            const didSegments = longFormDid.split(':');
            expect(didSegments.length).toEqual(5);
            expect(didSegments[2]).toEqual('test');
        }));
        it('should throw error if given operation key contains unexpected property.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            updateKey.d = 'notAllowedPropertyInPublicKey'; // 'd' is only allowed in private key.
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document: {} }), ErrorCode_1.default.PublicKeyJwkEs256kHasUnexpectedProperty);
        }));
        it('should throw error if given operation key contains incorrect crv value.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            updateKey.crv = 'wrongValue';
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document: {} }), ErrorCode_1.default.JwkEs256kMissingOrInvalidCrv);
        }));
        it('should throw error if given operation key contains incorrect kty value.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            updateKey.kty = 'wrongValue';
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document: {} }), ErrorCode_1.default.JwkEs256kMissingOrInvalidKty);
        }));
        it('should throw error if given operation key contains invalid x length.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            updateKey.x = 'wrongValueLength';
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document: {} }), ErrorCode_1.default.JwkEs256kHasIncorrectLengthOfX);
        }));
        it('should throw error if given operation key contains invalid y length.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            updateKey.y = 'wrongValueLength';
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document: {} }), ErrorCode_1.default.JwkEs256kHasIncorrectLengthOfY);
        }));
        it('should throw error if given DID Document JWK is an array.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const [anyDidDocumentKey] = yield index_1.IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [index_1.IonPublicKeyPurpose.Authentication] });
            anyDidDocumentKey.publicKeyJwk = ['invalid object type'];
            const document = { publicKeys: [anyDidDocumentKey] };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.DidDocumentPublicKeyMissingOrIncorrectType);
        }));
        it('should throw error if given DID Document keys with the same ID.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const [anyDidDocumentKey1] = yield index_1.IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [index_1.IonPublicKeyPurpose.AssertionMethod] });
            const [anyDidDocumentKey2] = yield index_1.IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [index_1.IonPublicKeyPurpose.Authentication] }); // Key ID duplicate.
            const didDocumentKeys = [anyDidDocumentKey1, anyDidDocumentKey2];
            const document = { publicKeys: didDocumentKeys };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.DidDocumentPublicKeyIdDuplicated);
        }));
        it('should throw error if given DID Document key ID exceeds maximum length.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const [anyDidDocumentKey] = yield index_1.IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [index_1.IonPublicKeyPurpose.Authentication] });
            anyDidDocumentKey.id = 'superDuperLongDidDocumentKeyIdentifierThatExceedsMaximumLength'; // Overwrite with super long string.
            const document = { publicKeys: [anyDidDocumentKey] };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.IdTooLong);
        }));
        it('should throw error if given service endpoint ID exceeds maximum length.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const services = [{
                    id: 'superDuperLongServiceIdValueThatExceedsMaximumAllowedLength',
                    type: 'anyType',
                    serviceEndpoint: 'http://any.endpoint'
                }];
            const document = { services };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.IdTooLong);
        }));
        it('should throw error if given service endpoint ID is a duplicate.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const services = [
                {
                    id: 'id',
                    type: 'anyType',
                    serviceEndpoint: 'http://any.endpoint'
                },
                {
                    id: 'id',
                    type: 'otherType',
                    serviceEndpoint: 'http://any.other.endpoint'
                }
            ];
            const document = { services };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.DidDocumentServiceIdDuplicated);
        }));
        it('should throw error if given service endpoint ID is not using Base64URL characters', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const services = [{
                    id: 'notAllBase64UrlChars!',
                    type: 'anyType',
                    serviceEndpoint: 'http://any.endpoint'
                }];
            const document = { services };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.IdNotUsingBase64UrlCharacterSet);
        }));
        it('should throw error if given service endpoint type exceeds maximum length.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const services = [{
                    id: 'anyId',
                    type: 'superDuperLongServiceTypeValueThatExceedsMaximumAllowedLength',
                    serviceEndpoint: 'http://any.endpoint'
                }];
            const document = { services };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.ServiceTypeTooLong);
        }));
        it('should throw error if given service endpoint value is an array', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const document = {
                services: [{
                        id: 'anyId',
                        type: 'anyType',
                        serviceEndpoint: []
                    }]
            };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.ServiceEndpointCannotBeAnArray);
        }));
        it('should allow object as service endpoint value.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const document = {
                services: [{
                        id: 'anyId',
                        type: 'anyType',
                        serviceEndpoint: { value: 'someValue' } // `object` based endpoint value.
                    }]
            };
            const longFormDid = index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document });
            expect(longFormDid).toBeDefined();
        }));
        it('should throw error if given service endpoint string is not a URL.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            const document = {
                services: [{
                        id: 'anyId',
                        type: 'anyType',
                        serviceEndpoint: 'http://' // Invalid URI.
                    }]
            };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.ServiceEndpointStringNotValidUri);
        }));
        it('should throw error if resulting delta property exceeds maximum size.', () => __awaiter(void 0, void 0, void 0, function* () {
            const [recoveryKey] = yield index_1.IonKey.generateEs256kOperationKeyPair();
            const updateKey = recoveryKey;
            // Add many keys so that 'delta' property size exceeds max limit.
            const [anyDidDocumentKey1] = yield index_1.IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId1', purposes: [index_1.IonPublicKeyPurpose.Authentication] });
            const [anyDidDocumentKey2] = yield index_1.IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId2', purposes: [index_1.IonPublicKeyPurpose.Authentication] });
            const [anyDidDocumentKey3] = yield index_1.IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId3', purposes: [index_1.IonPublicKeyPurpose.Authentication] });
            const [anyDidDocumentKey4] = yield index_1.IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId4', purposes: [index_1.IonPublicKeyPurpose.Authentication] });
            const didDocumentKeys = [anyDidDocumentKey1, anyDidDocumentKey2, anyDidDocumentKey3, anyDidDocumentKey4];
            const document = {
                publicKeys: didDocumentKeys
            };
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => index_1.IonDid.createLongFormDid({ recoveryKey, updateKey, document }), ErrorCode_1.default.DeltaExceedsMaximumSize);
        }));
    }));
}));
//# sourceMappingURL=IonDid.spec.js.map