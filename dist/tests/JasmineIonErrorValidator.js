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
const IonError_1 = require("../lib/IonError");
/**
 * Encapsulates the helper functions for the tests.
 */
class JasmineIonErrorValidator {
    /**
     * Fails the current spec if the execution of the function does not throw the expected IonError.
     *
     * @param functionToExecute The function to execute.
     * @param expectedErrorCode The expected error code.
     */
    static expectIonErrorToBeThrown(functionToExecute, expectedErrorCode) {
        let validated = false;
        try {
            functionToExecute();
        }
        catch (e) {
            if (e instanceof IonError_1.default) {
                expect(e.code).toEqual(expectedErrorCode);
                validated = true;
            }
        }
        if (!validated) {
            fail(`Expected error '${expectedErrorCode}' did not occur.`);
        }
    }
    /**
     * Fails the current spec if the execution of the function does not throw the expected IonError.
     *
     * @param functionToExecute The function to execute.
     * @param expectedErrorCode The expected error code.
     */
    static expectIonErrorToBeThrownAsync(functionToExecute, expectedErrorCode) {
        return __awaiter(this, void 0, void 0, function* () {
            let validated = false;
            try {
                yield functionToExecute();
            }
            catch (e) {
                if (e instanceof IonError_1.default) {
                    expect(e.code).toEqual(expectedErrorCode);
                    validated = true;
                }
            }
            if (!validated) {
                fail(`Expected error '${expectedErrorCode}' did not occur.`);
            }
        });
    }
}
exports.default = JasmineIonErrorValidator;
//# sourceMappingURL=JasmineIonErrorValidator.js.map