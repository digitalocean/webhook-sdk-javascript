import { Schemes, SignatureScheme } from "./SignatureScheme";
import * as crypto from 'crypto';
import { SignatureObject } from "./SignatureObject";

export const DEFAULT_SIGNATURE_TOLERANCE = 300; // seconds (5mins)

/**
 * Properties used to create the Signature 
 * 
 */
export interface CreateSignatureOptions {
  /**
   * Unix timestamp in ms
   */
  timestamp: number,

  /**
   * The payload data to be signed
   */
  payload: Buffer;

  /**
   * One or more secrets used to sign the payload.
   */
  secrets: string[];

  /**
   * If set, only the provided schemes will be used to sign the payload. By default all registered schemes are used to sign the payload.
   */
  schemes?: SignatureScheme[]
}

export interface VerifySignatureOptions {
  /**
   * tolerance configures the maximum allowed signature age in seconds. Signatures older than this time window will fail validation.
   * If unset, defaults DEFAULT_SIGNATURE_TOLERANCE.
   */
  tolerance?: number

  /**
   * ignoreTolerance skips checking if the signature timestamp is within the allowed tolerance.
   */
  ignoreTolerance?: boolean

  /**
   * Optional override of Date.now
   */
  now?: () => number,

  /**
   * UntrustedSchemes is a list of signature schemes that are untrusted.
   */
  untrustedSchemes?: SignatureScheme[]
}

export class Signature {
  protected timestamp: number;
  protected signatureObjects: SignatureObject[];

  private constructor(timestamp: number, signatureObjects: SignatureObject[]) {
    this.timestamp = timestamp;
    this.signatureObjects = signatureObjects;
  }

  /**
   * Creates a new Signature
   *
   * @param {CreateSignatureOptions} params
   * @return {*}  {Signature}
   * @memberof Signature
   */
  static createSignature(params: CreateSignatureOptions): Signature {
    const {
      timestamp,
      payload,
      secrets,
      schemes = Schemes.schemes
    } = params;

    const signatures: SignatureObject[] = [];
    schemes.forEach(scheme => {
      secrets.forEach((secret) => {
        const s = SignatureObject.createSignatureObject(scheme, timestamp, payload, secret)
        signatures.push(s)
      })
    })

    return new Signature(
      timestamp,
      signatures
    )
  }

  /**
   * Parses a signature from its string representation. 
   * 
   * @param {string} value the string representation of the signature in format `t=xxxxxxx,v1=xxxxxxx,v2=xxxxx`, where is the timestamp, vN is the scheme version used to generate the signature.  
   * @return {*}  {Signature}
   */
  static parse(value: string): Signature {
    const signatures: SignatureObject[] = [];
    let timestamp: number | undefined = undefined;

    const pairs = value.split(',');
    pairs.forEach((pair, index) => {

      const parts = pair.split('=');
      if (parts.length !== 2) {
        throw new Error(`invalid signature`)
      }

      const [k, v] = parts;
      if (k === 't') {
        if (timestamp) {
          throw new Error('timestamp cannot be specified multiple times')
        }

        const ts = parseInt(v, 10);
        if (!ts) {
          throw new Error('timestamp must be an integer')
        }
        timestamp = ts
      } else {
        let sig = SignatureObject.parse(pair)
        signatures.push(sig)
      }
    })

    if (!timestamp) {
      throw new Error('missing timestamp')
    }

    return new Signature(timestamp, signatures)
  }

  /**
   * Verifies the given signature payload. Verification passes if at least of the signatures in the package are valid. Otherwise it will throw an error. 
   *
   * @param {Buffer} payload
   * @param {string} secret
   * @param {VerifySignatureOptions} [opts]
   * @memberof Signature
   */
  verify(payload: Buffer, secret: string, opts?: VerifySignatureOptions) {
    const now = opts?.now ? opts.now() : Date.now();
    const tolerance = opts?.tolerance ?? DEFAULT_SIGNATURE_TOLERANCE
    const untrustedSchemes = opts?.untrustedSchemes ?? []

    if (!opts?.ignoreTolerance) {
      if ((now - this.timestamp) > (tolerance * 1000)) {
        throw new Error('signature has expired')
      }
    }

    if (this.signatureObjects.length === 0) {
      throw new Error('payload not signed')
    }

    for (let sig of this.signatureObjects) {
      try {
        for (let scheme of untrustedSchemes) {
          // If the scheme is untrusted, we throw an error so we can continue the outer loop in the catch clause.
          if (scheme.version() === sig.scheme.version()) {
            throw new Error('untrusted')
          }
        }
      } catch (error) {
        continue
      }

      const valid = sig.verify(payload, secret, this.timestamp);
      if (valid) {
        return
      }
    }

    throw new Error('no valid signature')
  }

  /**
   * Returns the string representation of the signature package.
   *
   * @return {*} string
   * @memberof Signature
   */
  toString(): string {
    let values: string[] = [];
    values.push(`t=${this.timestamp}`);
    this.signatureObjects.forEach(s => {
      values.push(s.toString())
    })
    return values.join(',')
  }

  /**
   * Compares two signatures for equality without leaking timing information.
   *
   * @param {Signature} sig
   * @return {*} boolean
   * @memberof Signature
   */
  equals(sig: Signature): boolean {
    try {
      return crypto.timingSafeEqual(Buffer.from(this.toString(), "utf8"), Buffer.from(sig.toString(), "utf8"));
    } catch (error) {
      return false;
    }
  }

}