import { Vault } from '../../index';

export declare function createPiiVeilTransformStream(
  vault: Vault
): TransformStream<string | Uint8Array, string | Uint8Array>;
