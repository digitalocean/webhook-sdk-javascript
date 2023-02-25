import * as crypto from 'crypto';

export interface SignatureScheme {
  sign(t: number, payload: Buffer, secret: string): string
  version(): number
}

export const SignatureSchemeV1: SignatureScheme = {
  sign(t: number, payload: Buffer, secret: string): string {
    const mac = crypto.createHmac('sha256', secret)
    mac.update(Buffer.from(`${t}`))
    mac.update(Buffer.from(`.`))
    mac.update(Buffer.from(payload))
    return mac.digest('hex')
  },
  version() {
    return 1
  }
}

export const Schemes = {
  schemes: [SignatureSchemeV1],
  find: function (version: number) {
    return this.schemes.find((s) => s.version() === version)
  },
  register: function (scheme: SignatureScheme) {
    if (this.find(scheme.version())) {
      return
    }
    this.schemes.push(scheme)
  },
  unregister: function (version: number) {
    this.schemes = this.schemes.filter(s => s.version() !== version)
  }
}
