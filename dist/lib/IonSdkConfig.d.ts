import IonNetwork from './enums/IonNetwork';
/**
 * Global configuration of the SDK.
 */
export default class IonSdkConfig {
    /**
     * Default hash algorithm used when hashing is performed.
     */
    static hashAlgorithmInMultihashCode: number;
    /**
     * Maximum bytes for canonicalized delta.
     */
    static maxCanonicalizedDeltaSizeInBytes: number;
    /**
     * Network name in ION DID, okay to leave as `undefined` if mainnet.
     */
    static network: IonNetwork | undefined;
}
