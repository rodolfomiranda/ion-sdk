/// <reference types="node" />
/**
 * Class that encodes binary blobs into strings.
 * Note that the encode/decode methods may change underlying encoding scheme.
 */
export default class Encoder {
    /**
     * Encodes given Buffer into a Base64URL string.
     */
    static encode(content: Buffer): string;
    /**
     * Decodes the given Base64URL string into a Buffer.
     */
    static decodeAsBuffer(encodedContent: string, inputContextForErrorLogging: string): Buffer;
    /**
     * Tests if the given string is a Base64URL string.
     */
    static isBase64UrlString(input: string): boolean;
}
