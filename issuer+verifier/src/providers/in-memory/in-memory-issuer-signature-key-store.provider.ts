import { CredentialIssuer } from '../../credential-issuer.types'
import { SignatureKeyPair } from '../../signature-key.types'
import { IssuerSignatureKeyStoreProvider } from '../provider.types'

export const inMemoryIssuerSignatureKeyStore = (): IssuerSignatureKeyStoreProvider => {
  const map = new Map<CredentialIssuer, SignatureKeyPair[]>()

  return {
    kind: 'issuer-signature-key-store-provider',
    name: 'in-memory-issuer-signature-key-store-provider',
    single: true,

    async save(issuer, pairs) {
      const current = map.get(issuer) ?? []
      const values = current.filter(
        (c) => !pairs.some((p) => c.privateKey.alg === p.privateKey.alg)
      )
      map.set(issuer, [...values, ...pairs])
    },

    async fetch(issuer) {
      return map.get(issuer) ?? []
    },
  }
}
