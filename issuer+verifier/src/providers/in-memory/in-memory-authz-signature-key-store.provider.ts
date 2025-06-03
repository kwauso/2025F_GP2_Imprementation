import { AuthorizationServerIssuer } from '../../authorization-server.types'
import { raise } from '../../errors/vcknots.error'
import { SignatureKeyPair } from '../../signature-key.types'
import { AuthzSignatureKeyStoreProvider } from '../provider.types'

export const inMemoryAuthzSignatureKeyStore = (option?: {
  key_alg?: string
}): AuthzSignatureKeyStoreProvider => {
  const map = new Map<AuthorizationServerIssuer, SignatureKeyPair>()

  return {
    kind: 'authz-signature-key-store-provider',
    name: 'in-memory-authz-signature-key-store-provider',
    single: true,

    async save(authz, pair) {
      map.set(authz, pair)
    },

    async fetch(authz) {
      return (
        map.get(authz) ??
        raise('ILLEGAL_STATE', {
          message: `Authorization server issuer has no signature key: ${authz}. Please save the signature key before fetching.`,
        })
      )
    },
  }
}
