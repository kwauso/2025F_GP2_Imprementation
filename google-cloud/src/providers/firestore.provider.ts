import { Provider } from '@trustknots/vcknots/providers'
import { App } from 'firebase-admin/app'
import { firestoreIssuer } from './firestore-issuer-store.provider'

export type FirestoreProviderOptions = {
  app?: App
  namespace?: string
}

export const firestore = (options?: FirestoreProviderOptions): Provider[] => {
  return [firestoreIssuer(options)]
}
