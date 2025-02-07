"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const base64_1 = require("@waiting/base64");
const ErrorCode_1 = require("./ErrorCode");
const IonError_1 = require("./IonError");
/**
 * Class that encodes binary blobs into strings.
 * Note that the encode/decode methods may change underlying encoding scheme.
 */
class Encoder {
    /**
     * Encodes given Buffer into a Base64URL string.
     */
    static encode(content) {
        const encodedContent = base64_1.b64toURLSafe(base64_1.b64fromBuffer(content));
        return encodedContent;
    }
    /**
     * Decodes the given Base64URL string into a Buffer.
     */
    static decodeAsBuffer(encodedContent, inputContextForErrorLogging) {
        if (!Encoder.isBase64UrlString(encodedContent)) {
            throw new IonError_1.default(ErrorCode_1.default.EncodedStringIncorrectEncoding, `Given ${inputContextForErrorLogging} must be base64url string.`);
        }
        // Turns the encoded string to regular base 64 and then decode as buffer
        return Buffer.from(base64_1.b64fromURLSafe(encodedContent), 'base64');
    }
    /**
     * Tests if the given string is a Base64URL string.
     */
    static isBase64UrlString(input) {
        // NOTE:
        // /<expression>/ denotes regex.
        // ^ denotes beginning of string.
        // $ denotes end of string.
        // + denotes one or more characters.
        const isBase64UrlString = /^[A-Za-z0-9_-]+$/.test(input);
        return isBase64UrlString;
    }
}
exports.default = Encoder;
//# sourceMappingURL=Encoder.js.map