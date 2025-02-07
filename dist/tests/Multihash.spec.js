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
const ErrorCode_1 = require("../lib/ErrorCode");
const JasmineIonErrorValidator_1 = require("./JasmineIonErrorValidator");
const Multihash_1 = require("../lib/Multihash");
describe('Multihash', () => __awaiter(void 0, void 0, void 0, function* () {
    describe('hashAsNonMultihashBuffer()', () => __awaiter(void 0, void 0, void 0, function* () {
        it('should throw error if hash algorithm given is unsupported.', () => __awaiter(void 0, void 0, void 0, function* () {
            JasmineIonErrorValidator_1.default.expectIonErrorToBeThrown(() => Multihash_1.default.hashAsNonMultihashBuffer(Buffer.from('anyThing'), 999), ErrorCode_1.default.MultihashUnsupportedHashAlgorithm);
        }));
    }));
}));
//# sourceMappingURL=Multihash.spec.js.map