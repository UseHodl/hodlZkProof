import { ec as EC } from "elliptic";
import { SHA256 } from "crypto-js";
import { Buffer } from "buffer";

const curve = new EC("secp256k1");

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
export function generateProof(
  txHash: string,
  userId: string,
  secret: string
): ZKProof {
  const G = curve.g; // Generator point.
  const H = curve.g.mul(SHA256(userId).toString()); // H = G * Hash(userId).

  const s = curve.genKeyPair().getPrivate(); // Random private key.
  const v = BigInt("0x" + txHash); // Convert transaction hash to BigInt.
  const commitment = G.mul(s).add(H.mul(v)); // C = sG + vH.

  // Generate a cryptographic proof using the commitment, transaction hash, and user ID.
  const message = SHA256(commitment.encode("hex") + txHash + userId).toString();
  const keyPair = curve.keyFromPrivate(secret); // Convert secret to KeyPair.
  const proof = curve.sign(message, keyPair); // Signature of the message using the user's secret.
  // Ensure the secret is a valid private key or mnemonic.
  if (!keyPair.validate().result) {
    throw new Error("Invalid secret provided.");
  }
  return {
    commitment: commitment.encode("hex"), // The commitment as a hexadecimal string.
    proof: proof.toDER("hex"), // The proof encoded in DER format (hexadecimal).
    publicSignal: Buffer.from(userId).toString("base64"), // Base64-encoded user ID as the public signal.
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
export function verifyProof(
  proof: ZKProof,
  txHash: string,
  expectedUserId: string
): boolean {
  try {
    const G = curve.g; // Generator point.
    const H = curve.g.mul(SHA256(expectedUserId).toString()); // H = G * Hash(expectedUserId).

    // Reconstruct the commitment from the proof.
    const commitment = curve.keyFromPublic(
      Buffer.from(proof.commitment, "hex")
    );

    // Verify the proof by recalculating the message and validating the signature.
    const message = SHA256(
      proof.commitment + txHash + expectedUserId
    ).toString();
    const isValid = curve.verify(message, proof.proof, commitment);

    // Decode the public signal and ensure it matches the expected user ID.
    const decodedUserId = Buffer.from(proof.publicSignal, "base64").toString();
    return isValid && decodedUserId === expectedUserId;
  } catch (error) {
    console.error("Proof verification failed:", error);
    return false;
  }
}
