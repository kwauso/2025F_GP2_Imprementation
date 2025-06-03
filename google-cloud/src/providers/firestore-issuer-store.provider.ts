import { createHash } from 'node:crypto'
import { CredentialIssuer, CredentialIssuerMetadata } from '@trustknots/vcknots/issuer'
import { IssuerMetadataStoreProvider } from '@trustknots/vcknots/providers'
import { getFirestore } from 'firebase-admin/firestore'
import { FirestoreProviderOptions } from './firestore.provider'

export const firestoreIssuer = (
  options?: FirestoreProviderOptions
): IssuerMetadataStoreProvider => {
  const firestore = options?.app ? getFirestore(options.app) : getFirestore()
  const ns = options?.namespace ?? 'vcknots'
  const md5 = (issuer: CredentialIssuer) => createHash('md5').update(issuer).digest('base64')

  return {
    kind: 'issuer-metadata-store-provider',
    name: 'firestore-issuer-metadata-store-provider',
    single: true,

    async fetch(issuer) {
      const id = md5(issuer)
      const doc = await firestore.doc(`/${ns}/v1/issuers/${id}`).get()

      if (!doc.exists) return null

      return CredentialIssuerMetadata(doc.data())
    },
    async save(issuer) {
      const id = md5(issuer.credential_issuer)
      const docRef = firestore.doc(`${ns}/v1/issuers/${id}`)
      await docRef.set(issuer, { merge: true })
    },
  }
}
