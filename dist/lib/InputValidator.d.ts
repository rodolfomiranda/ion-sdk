import IonPublicKeyPurpose from './enums/IonPublicKeyPurpose';
import JwkEs256k from './models/JwkEs256k';
import OperationKeyType from './enums/OperationKeyType';
/**
 * Class containing input validation methods.
 */
export default class InputValidator {
    /**
     * Validates the schema of a ES256K JWK key.
     */
    static validateEs256kOperationKey(operationKeyJwk: JwkEs256k, operationKeyType: OperationKeyType): void;
    /**
     * Validates an `id` property (in `IonPublicKeyModel` and `IonServiceModel`).
     */
    static validateId(id: string): void;
    /**
     * Validates the given public key purposes.
     */
    static validatePublicKeyPurposes(purposes?: IonPublicKeyPurpose[]): void;
}
