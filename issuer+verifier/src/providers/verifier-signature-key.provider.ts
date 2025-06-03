import { calculateJwkThumbprint, CompactSign, exportJWK, generateKeyPair } from 'jose'
import { VerifierSignatureKeyProvider } from './provider.types'
import { ProofJwtHeader } from '../credential.types'
import { JwtPayload } from '../jwt.types'
import { raise } from '../errors'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import { ClientId } from '../client-id.types'

export type VerifierSignatureKeyProviderOptions = {
  alg?: string
}

export const verifierSignatureKey = (
  options?: VerifierSignatureKeyProviderOptions
): VerifierSignatureKeyProvider & WithProviderRegistry => {
  const alg = options?.alg ?? 'ES256'

  return {
    kind: 'verifier-signature-key-provider',
    name: 'default-verifier-signature-key-provider',
    single: false,

    ...withProviderRegistry,

    async generate() {
      const { publicKey, privateKey } = await generateKeyPair(alg, {
        extractable: true,
      })
      const publicJwk = await exportJWK(publicKey)
      const privateJwk = await exportJWK(privateKey)
      const kid = await calculateJwkThumbprint(publicJwk)
      return {
        publicKey: { ...publicJwk, alg, kid },
        privateKey: { ...privateJwk, alg },
      }
    },
    async sign(
      verifierId: ClientId,
      keyAlg: string,
      jwtPayload: JwtPayload,
      jwtHeader: ProofJwtHeader
    ) {
      try {
        const keyStore$ = this.providers.get('verifier-signature-key-store-provider')
        const privateKey = await keyStore$.fetchPrivate(verifierId, keyAlg)
        if (!privateKey) {
          throw raise('AUTHZ_VERIFIER_KEY_NOT_FOUND', {
            message: 'Verifier private key not found.',
          })
        }
        const signer = new CompactSign(new TextEncoder().encode(JSON.stringify(jwtPayload)))
        signer.setProtectedHeader({ ...jwtHeader })
        const jws = await signer.sign(privateKey)
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
