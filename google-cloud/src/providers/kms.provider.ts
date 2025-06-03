import { KeyManagementServiceClient } from '@google-cloud/kms'
import { IssuerSignatureKeyStoreProvider } from '@trustknots/vcknots/providers'

export type CloudKmsProviderOptions = {
  projectId: string
  credentials?: {
    privateKey: string
    clientEmail: string
  }
}

export const kms = (options?: CloudKmsProviderOptions): IssuerSignatureKeyStoreProvider => {
  // @ts-ignore
  const kms = options
    ? new KeyManagementServiceClient({
        projectId: options?.projectId,
        ...(options.credentials && {
          credentials: {
            private_key: options.credentials.privateKey,
            client_email: options.credentials.clientEmail,
          },
        }),
      })
    : new KeyManagementServiceClient()
  return {
    kind: 'issuer-signature-key-store-provider',
    name: 'cloud-kms-issuer-signature-key-store-provider',
    single: true,

    async fetch(_issuer) {
      // TODO: Fetch keys from Cloud KMS and return a SignatureKeyPair[]
      return []
    },
    async save(_issuer, _pairs) {
      // TODO: Store the key in Cloud KMS
      return
    },
  }
}
