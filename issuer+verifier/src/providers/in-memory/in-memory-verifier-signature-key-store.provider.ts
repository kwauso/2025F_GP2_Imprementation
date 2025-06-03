import { importJWK, importPKCS8, importSPKI } from 'jose'
import { TmpVerifierSignatureKeyPair } from '../../signature-key.types'
import { VerifierSignatureKeyStoreProvider } from '../provider.types'

export const inMemoryVerifierSignatureKeyStore = (): VerifierSignatureKeyStoreProvider => {
  const map = new Map<string, TmpVerifierSignatureKeyPair[]>()

  return {
    kind: 'verifier-signature-key-store-provider',
    name: 'in-memory-verifier-signature-key-store-provider',
    single: true,

    async save(verifier, pairs) {
      const current = map.get(verifier) ?? []
      const values = current.filter((c) => !pairs.some((p) => c.declaredAlg === p.declaredAlg))
      map.set(verifier, [...values, ...pairs])
    },

    async fetch(verifier, alg) {
      const pairs = map.get(verifier)
      if (!pairs) return null
      const value = pairs.find((c) => c.declaredAlg === alg) ?? null
      if (value) {
        const publicKey = value.publicKey
        if (publicKey && value.format === 'jwk' && typeof publicKey !== 'string') {
          const key = await importJWK(publicKey, value.declaredAlg)
          return key instanceof Uint8Array ? null : key
        }
        if (publicKey && typeof publicKey === 'string') {
          const key = await importSPKI(publicKey, value.declaredAlg)
          return key
        }
      }
      return null
    },

    async fetchPrivate(verifier, alg) {
      const pairs = map.get(verifier)
      if (!pairs) return null
      const value = pairs.find((c) => c.declaredAlg === alg) ?? null
      if (value) {
        const privateKey = value.privateKey
        if (privateKey && value.format === 'jwk' && typeof privateKey !== 'string') {
          const key = await importJWK(privateKey, value.declaredAlg)
          return key instanceof Uint8Array ? null : key
        }
        if (privateKey && typeof privateKey === 'string') {
          const key = await importPKCS8(privateKey, value.declaredAlg)
          return key
        }
      }
      return null
    },
  }
}
