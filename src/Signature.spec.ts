import { DEFAULT_SIGNATURE_TOLERANCE, Signature } from "./Signature";
import { Schemes, SignatureScheme, SignatureSchemeV1 } from "./SignatureScheme";

const testPayload = Buffer.from('it is wednesday my dudes 🕷️');
const testSecret = 'du-TY1GUFGk';

const FakeSignatureScheme: SignatureScheme = {
  sign(t: number, payload: Buffer, secret: string): string {
    return `${t}:${secret}:(${payload.length})`
  },
  version() {
    return 1337
  }
}

describe('Signature.makeSignature', () => {
  it('makes a signature from a payload', () => {
    const timestamp = 946720800;
    const sig = Signature.createSignature({
      timestamp,
      payload: testPayload,
      secrets: [testSecret]
    })
    expect(sig.toString()).toBe(
      `t=946720800,v1=b70100cf2943bec15996e3ae9392d0dcaf21f285fa81969108185d47b292dfa2`
    )
  })

  it('makes a signature using multiple secrets and versions', () => {
    Schemes.register(FakeSignatureScheme);
    const timestamp = 946720800;
    const sig = Signature.createSignature({
      timestamp,
      payload: testPayload,
      secrets: [testSecret, "some-secret"]
    })
    expect(sig.toString()).toBe(
      `t=946720800,v1=b70100cf2943bec15996e3ae9392d0dcaf21f285fa81969108185d47b292dfa2,v1=b3218d58417e81cf347b439091b9ede800b2e1555f90fee81ac94f67c249da26,v1337=946720800:du-TY1GUFGk:(32),v1337=946720800:some-secret:(32)`
    )
    Schemes.unregister(FakeSignatureScheme.version());
  })
});

describe('Signature.parse', () => {
  it('can parse a signature', () => {
    Schemes.register(FakeSignatureScheme);

    const timestamp = 946720800;
    const v1Sig1 = Signature.parse("t=946720800,v1=b70100cf2943bec15996e3ae9392d0dcaf21f285fa81969108185d47b292dfa2")
    expect(Signature.createSignature({
      schemes: [SignatureSchemeV1],
      timestamp,
      payload: testPayload,
      secrets: [testSecret]
    }).equals(v1Sig1)).toBeTruthy()

    const v1Sig2 = Signature.parse("t=946720800,v1=b3218d58417e81cf347b439091b9ede800b2e1555f90fee81ac94f67c249da26")
    expect(Signature.createSignature({
      schemes: [SignatureSchemeV1],
      timestamp,
      payload: testPayload,
      secrets: ["some-secret"]
    }).equals(v1Sig2)).toBeTruthy()

    const v1337s1 = Signature.parse("t=946720800,v1337=946720800:du-TY1GUFGk:(32)")
    expect(Signature.createSignature({
      timestamp,
      schemes: [FakeSignatureScheme],
      payload: testPayload,
      secrets: [testSecret]
    }).equals(v1337s1)).toBeTruthy()

    const v1337s2 = Signature.parse("t=946720800,v1337=946720800:some-secret:(32)")
    expect(Signature.createSignature({
      timestamp,
      schemes: [FakeSignatureScheme],
      payload: testPayload,
      secrets: ['some-secret']
    }).equals(v1337s2)).toBeTruthy()

    Schemes.unregister(FakeSignatureScheme.version());
  })

  it('throws an error is signature is invalid', () => {
    const errorMap = {
      "🐌": "invalid signature",
      "v999=🐌": "invalid signature scheme version 999",
      "v1=b70100cf2943bec15996e3ae9392d0dcaf21f285fa81969108185d47b292dfa2": "missing timestamp",
      "t=🐌": "timestamp must be an integer",
      "t=123,v1=b70100cf2943bec15996e3ae9392d0dcaf21f285fa81969108185d47b292dfa2,t=341": "timestamp cannot be specified multiple times",
    }

    Object.entries(errorMap).forEach(([sig, error]) => {
      expect(() => Signature.parse(sig)).toThrowError(error)
    })
  })
})

describe('Signature.validate', () => {
  it('validates a signature payload', () => {
    Schemes.register(FakeSignatureScheme);
    const timestamp = 946720800;

    const nowWithinTolerance = () => {
      return timestamp + DEFAULT_SIGNATURE_TOLERANCE
    }

    const sig = Signature.createSignature({
      timestamp,
      payload: testPayload,
      secrets: [testSecret, "some-secret"]
    })

    // valid: happy path
    expect(() => sig.verify(testPayload, testSecret, { now: nowWithinTolerance })).not.toThrow()

    // invalid: expired signature
    expect(() => sig.verify(testPayload, testSecret, { now: () => Date.now() + DEFAULT_SIGNATURE_TOLERANCE })).toThrowError('signature has expired')

    // invalid: expired signature w/ custom tolerance
    expect(() => sig.verify(testPayload, testSecret, {
      tolerance: 3,
      now: () => timestamp + (5 * 1000)
    })).toThrowError('signature has expired')

    // valid: expired signature w/ ignore tolerance
    expect(() => sig.verify(testPayload, testSecret, {
      ignoreTolerance: true,
      now: () => timestamp + (5 * 1000)
    })).not.toThrow()

    // invalid: signature signed by unknown secret
    expect(() => sig.verify(testPayload, 'other-secret', {
      now: nowWithinTolerance
    })).toThrow('no valid signature')

    // invalid: signature signed by unknown secret
    expect(() => sig.verify(Buffer.from('other-payload'), 'other-secret', {
      now: nowWithinTolerance
    })).toThrow('no valid signature')

    // invalid: signature signed by untrusted scheme
    expect(() => sig.verify(testPayload, testSecret, {
      now: nowWithinTolerance,
      untrustedSchemes: Schemes.schemes
    })).toThrow('no valid signature')

    // valid: only one of the schemes is untrusted
    expect(() => sig.verify(testPayload, testSecret, {
      now: nowWithinTolerance,
      untrustedSchemes: [FakeSignatureScheme]
    })).not.toThrow()

    Schemes.unregister(FakeSignatureScheme.version());

  })
})