import * as crypto from 'crypto';
import { Schemes, SignatureScheme } from "./SignatureScheme"

export class SignatureObject {
  scheme: SignatureScheme
  value: string

  constructor(scheme: SignatureScheme, value: string) {
    this.scheme = scheme
    this.value = value
  }

  static createSignatureObject(scheme: SignatureScheme, timestamp: number, payload: Buffer, secret: string): SignatureObject {
    const value = scheme.sign(timestamp, payload, secret)
    return new SignatureObject(
      scheme,
      value
    )
  }

  static parse(value: string): SignatureObject {
    const parts = value.split('=');
    if (parts.length !== 2) {
      throw new Error('invalid signature format')
    }

    const [versionStr, signature] = parts;
    if (versionStr[0] !== 'v') {
      throw new Error('invalid signature format')
    }

    const version = parseInt(versionStr.replace('v', ''), 10);
    if (!version) {
      throw new Error('signature scheme version must be an integer')
    }

    const scheme = Schemes.find(version)
    if (!scheme) {
      throw new Error(`invalid signature scheme version ${version}`)
    }

    return new SignatureObject(scheme, signature)
  }

  verify(payload: Buffer, secret: string, timestamp: number): boolean {
    if (!this.scheme) {
      return false
    }

    const freshSig = SignatureObject.createSignatureObject(this.scheme, timestamp, payload, secret);
    if (!this.equals(freshSig)) {
      return false
    }

    return true
  }

  toString() {
    return `v${this.scheme.version()}=${this.value}`
  }

  equals(sig: SignatureObject): boolean {
    try {
      return crypto.timingSafeEqual(Buffer.from(this.value, "utf8"), Buffer.from(sig.value, "utf8"));
    } catch {
      return false;
    }
  }
}
