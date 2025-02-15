import ISigner from './interfaces/ISigner';
import IonCreateRequestModel from './models/IonCreateRequestModel';
import IonDeactivateRequestModel from './models/IonDeactivateRequestModel';
import IonDocumentModel from './models/IonDocumentModel';
import IonPublicKeyModel from './models/IonPublicKeyModel';
import IonRecoverRequestModel from './models/IonRecoverRequestModel';
import IonServiceModel from './models/IonServiceModel';
import IonUpdateRequestModel from './models/IonUpdateRequestModel';
import JwkEs256k from './models/JwkEs256k';
/**
 * Class containing operations related to ION requests.
 */
export default class IonRequest {
    /**
     * Creates an ION DID create request.
     * @param input.document The initial state to be associate with the ION DID to be created using a `replace` document patch action.
     */
    static createCreateRequest(input: {
        recoveryKey: JwkEs256k;
        updateKey: JwkEs256k;
        document: IonDocumentModel;
    }): IonCreateRequestModel;
    static createDeactivateRequest(input: {
        didSuffix: string;
        recoveryPublicKey: JwkEs256k;
        signer: ISigner;
    }): Promise<IonDeactivateRequestModel>;
    static createRecoverRequest(input: {
        didSuffix: string;
        recoveryPublicKey: JwkEs256k;
        nextRecoveryPublicKey: JwkEs256k;
        nextUpdatePublicKey: JwkEs256k;
        document: IonDocumentModel;
        signer: ISigner;
    }): Promise<IonRecoverRequestModel>;
    static createUpdateRequest(input: {
        didSuffix: string;
        updatePublicKey: JwkEs256k;
        nextUpdatePublicKey: JwkEs256k;
        signer: ISigner;
        servicesToAdd?: IonServiceModel[];
        idsOfServicesToRemove?: string[];
        publicKeysToAdd?: IonPublicKeyModel[];
        idsOfPublicKeysToRemove?: string[];
    }): Promise<IonUpdateRequestModel>;
    private static validateDidSuffix;
    private static validateDidDocumentKeys;
    private static validateServices;
    private static validateService;
    private static validateDeltaSize;
}
