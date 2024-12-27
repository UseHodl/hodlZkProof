/**
 * @typedef {Object} ZKProof
 * @property {string} commitment - The Pedersen commitment.
 * @property {string} proof - The cryptographic proof of the commitment.
 * @property {string} publicSignal - A public signal (encoded user ID in base64).
 */
/**
 * Type definition for ZKProof.
 */
type ZKProof = {
    commitment: string;
    proof: string;
    publicSignal: string;
};
/**
 * Generates a zero-knowledge proof based on the transaction hash, user ID, and secret.
 *
 * @param {string} txHash - Transaction hash for the value being proven.
 * @param {string} userId - User ID (public signal).
 * @param {string} secret - User's secret (private data derived locally, never shared).
 * @returns {ZKProof} The zero-knowledge proof object.
 *
 * JSON Format Example for Return:
 * {
 *   "commitment": "string", // The encoded Pedersen commitment in hexadecimal.
 *   "proof": "string", // The cryptographic proof in DER format.
 *   "publicSignal": "string" // The base64-encoded user ID.
 * }
 */
export declare function generateProof(txHash: string, userId: string, secret: string): ZKProof;
/**
 * Verifies a zero-knowledge proof.
 *
 * @param {ZKProof} proof - The zero-knowledge proof object to verify.
 * @param {string} txHash - The transaction hash for the value being proven.
 * @param {string} expectedUserId - The expected user ID for verification.
 * @returns {boolean} Whether the proof is valid or not.
 *
 * JSON Format Example for Input:
 * {
 *   "proof": {
 *     "commitment": "string", // The hexadecimal commitment.
 *     "proof": "string", // The cryptographic proof in DER format.
 *     "publicSignal": "string" // The base64-encoded user ID.
 *   },
 *   "txHash": "string", // The transaction hash being verified.
 *   "expectedUserId": "string" // The user ID to match against the proof's public signal.
 * }
 *
 * JSON Format Example for Output:
 * {
 *   "isValid": true // Boolean indicating if the proof is valid.
 * }
 */
export declare function verifyProof(proof: ZKProof, txHash: string, expectedUserId: string): boolean;
export {};
