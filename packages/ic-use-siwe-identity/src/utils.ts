import type { DerEncodedPublicKey, Signature } from "@dfinity/agent";

/**
 * Converts a Uint8Array or number array to a Signature object.
 */
export function asSignature(signature: Uint8Array | number[]): Signature {
  const arrayBuffer: ArrayBuffer = (signature as Uint8Array).buffer;
  const s: Signature = arrayBuffer as Signature;
  s.__signature__ = undefined;
  return s;
}

/**
 * Converts a Uint8Array or number array to a DerEncodedPublicKey object.
 */
export function asDerEncodedPublicKey(
  publicKey: Uint8Array | number[]
): DerEncodedPublicKey {
  const arrayBuffer: ArrayBuffer = (publicKey as Uint8Array).buffer;
  const pk: DerEncodedPublicKey = arrayBuffer as DerEncodedPublicKey;
  pk.__derEncodedPublicKey__ = undefined;
  return pk;
}
