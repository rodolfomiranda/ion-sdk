"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * A class that represents an ION error.
 */
class IonError extends Error {
    constructor(code, message) {
        super(`${code}: ${message}`);
        this.code = code;
        // NOTE: Extending 'Error' breaks prototype chain since TypeScript 2.1.
        // The following line restores prototype chain.
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
exports.default = IonError;
//# sourceMappingURL=IonError.js.map