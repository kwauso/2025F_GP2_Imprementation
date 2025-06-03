import { CompactSign, exportJWK, generateKeyPair, importJWK } from 'jose'
import { AuthzSignatureKeyProvider } from './provider.types'
import { ProofJwtHeader } from '../credential.types'
import { Jwk } from '../jwk.type'
import { JwtPayload } from '../jwt.types'
import { raise } from '../errors'

export type AuthzSignatureKeyProviderOptions = {
  alg?: string
}

export const authzSignatureKey = (
  options?: AuthzSignatureKeyProviderOptions
): AuthzSignatureKeyProvider => {
  const alg = options?.alg ?? 'ES256'

  return {
    kind: 'authz-signature-key-provider',
    name: 'default-authz-signature-key-provider',
    single: false,

    async generate() {
      const { publicKey, privateKey } = await generateKeyPair(alg, {
        extractable: true,
      })
      const publicJwk = await exportJWK(publicKey)
      const privateJwk = await exportJWK(privateKey)
      return {
        publicKey: { ...publicJwk, alg },
        privateKey: { ...privateJwk, alg },
      }
    },

    async sign(privateKey: Jwk, keyAlg: string, jwtPayload: JwtPayload, jwtHeader: ProofJwtHeader) {
      try {
        const key = await importJWK(privateKey, keyAlg)
        const signer = new CompactSign(new TextEncoder().encode(JSON.stringify(jwtPayload)))
        signer.setProtectedHeader({ ...jwtHeader })
        const jws = await signer.sign(key)
        const [, , signature] = jws.split('.')
        return signature
      } catch (error) {
        throw raise('INTERNAL_SERVER_ERROR', { message: `sign error: ${error}` })
      }
    },

    canHandle(keyAlg: string): boolean {
      return keyAlg === alg
    },
  }
}
