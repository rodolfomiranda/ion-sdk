import IonDocumentModel from './models/IonDocumentModel';
import JwkEs256k from './models/JwkEs256k';
/**
 * Class containing DID related operations.
 */
export default class IonDid {
    /**
     * Creates a long-form DID.
     * @param input.document The initial state to be associate with the ION DID to be created using a `replace` document patch action.
     */
    static createLongFormDid(input: {
        recoveryKey: JwkEs256k;
        updateKey: JwkEs256k;
        document: IonDocumentModel;
    }): string;
    /**
     * Computes the DID unique suffix given the encoded suffix data string.
     */
    private static computeDidUniqueSuffix;
}
