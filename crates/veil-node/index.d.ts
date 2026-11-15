export interface NodeRedactOutput {
  text: string;
  spansFound: number;
  vaultJson: string;
}

export interface NodeDetectedSpan {
  kind: string;
  start: number;
  end: number;
  original: string;
}

export type RedactionMode = 'placeholder' | 'synthetic' | 'mask';

export declare class VeilStreamingRestorer {
  constructor(vaultJson: string);
  pushChunk(chunk: string): string;
  finish(): string;
}

export declare class VeilNode {
  constructor(mode?: RedactionMode, secretKey?: string);
  static fromPolicyJson(policyJson: string): VeilNode;
  addCustomRule(name: string, pattern: string): void;
  addAllowlist(entry: string): void;
  addSensitiveJsonKey(key: string): void;
  redact(text: string): NodeRedactOutput;
  restore(sanitizedText: string, vaultJson: string): string;
  encryptVault(vaultJson: string, passphrase: string): string;
  decryptVault(encryptedJson: string, passphrase: string): string;
  redactJson(jsonStr: string): NodeRedactOutput;
  scan(text: string): Array<NodeDetectedSpan>;
}
