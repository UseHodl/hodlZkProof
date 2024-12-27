"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateProof = generateProof;
exports.verifyProof = verifyProof;
var elliptic_1 = require("elliptic");
var crypto_js_1 = require("crypto-js");
var buffer_1 = require("buffer");
var curve = new elliptic_1.ec("secp256k1");
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
function generateProof(txHash, userId, secret) {
    var G = curve.g; // Generator point.
    var H = curve.g.mul((0, crypto_js_1.SHA256)(userId).toString()); // H = G * Hash(userId).
    var s = curve.genKeyPair().getPrivate(); // Random private key.
    var v = BigInt("0x" + txHash); // Convert transaction hash to BigInt.
    var commitment = G.mul(s).add(H.mul(v)); // C = sG + vH.
    // Generate a cryptographic proof using the commitment, transaction hash, and user ID.
    var message = (0, crypto_js_1.SHA256)(commitment.encode("hex") + txHash + userId).toString();
    var keyPair = curve.keyFromPrivate(secret); // Convert secret to KeyPair.
    var proof = curve.sign(message, keyPair); // Signature of the message using the user's secret.
    // Ensure the secret is a valid private key or mnemonic.
    if (!keyPair.validate().result) {
        throw new Error("Invalid secret provided.");
    }
    return {
        commitment: commitment.encode("hex"), // The commitment as a hexadecimal string.
        proof: proof.toDER("hex"), // The proof encoded in DER format (hexadecimal).
        publicSignal: buffer_1.Buffer.from(userId).toString("base64"), // Base64-encoded user ID as the public signal.
    };
}
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
function verifyProof(proof, txHash, expectedUserId) {
    try {
        var G = curve.g; // Generator point.
        var H = curve.g.mul((0, crypto_js_1.SHA256)(expectedUserId).toString()); // H = G * Hash(expectedUserId).
        // Reconstruct the commitment from the proof.
        var commitment = curve.keyFromPublic(buffer_1.Buffer.from(proof.commitment, "hex"));
        // Verify the proof by recalculating the message and validating the signature.
        var message = (0, crypto_js_1.SHA256)(proof.commitment + txHash + expectedUserId).toString();
        var isValid = curve.verify(message, proof.proof, commitment);
        // Decode the public signal and ensure it matches the expected user ID.
        var decodedUserId = buffer_1.Buffer.from(proof.publicSignal, "base64").toString();
        return isValid && decodedUserId === expectedUserId;
    }
    catch (error) {
        console.error("Proof verification failed:", error);
        return false;
    }
}
