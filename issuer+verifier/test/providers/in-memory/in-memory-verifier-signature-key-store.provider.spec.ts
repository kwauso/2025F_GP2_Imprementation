import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { exportJWK, generateKeyPair } from 'jose'
import { ClientId } from '../../../src/client-id.types'
import { inMemoryVerifierSignatureKeyStore } from '../../../src/providers/in-memory/in-memory-verifier-signature-key-store.provider'
import type { TmpVerifierSignatureKeyPair } from '../../../src/signature-key.types'

describe('inMemoryVerifierSignatureKeyStore', () => {
  let store: ReturnType<typeof inMemoryVerifierSignatureKeyStore>
  const verifier = ClientId('https://verifier.example.com')
  let pair1: TmpVerifierSignatureKeyPair
  let pair2: TmpVerifierSignatureKeyPair

  beforeEach(async () => {
    store = inMemoryVerifierSignatureKeyStore()
    const keys1 = await generateKeyPair('ES256', { extractable: true })
    const pubKey1 = await exportJWK(keys1.publicKey)
    const privKey1 = await exportJWK(keys1.privateKey)
    pair1 = {
      format: 'jwk',
      declaredAlg: 'ES256',
      publicKey: { ...pubKey1, kid: 'kid1', alg: 'ES256' },
      privateKey: { ...privKey1, kid: 'kid1', alg: 'ES256' },
    }

    const keys2 = await generateKeyPair('ES384', { extractable: true })
    const pubKey2 = await exportJWK(keys2.publicKey)
    const privKey2 = await exportJWK(keys2.privateKey)
    pair2 = {
      format: 'jwk',
      declaredAlg: 'ES384',
      publicKey: { ...pubKey2, kid: 'kid2', alg: 'ES384' },
      privateKey: { ...privKey2, kid: 'kid2', alg: 'ES384' },
    }
  })

  it('should save and fetch key pairs for a verifier', async () => {
    await store.save(verifier, [pair1])
    const fetched = await store.fetch(verifier, 'ES256')
    assert.ok(fetched)
    assert.equal(fetched.algorithm.name, 'ECDSA')
  })

  it('should append new key pairs with different alg', async () => {
    await store.save(verifier, [pair1])
    await store.save(verifier, [pair2])
    const fetched1 = await store.fetch(verifier, 'ES256')
    const fetched2 = await store.fetch(verifier, 'ES384')
    assert.ok(fetched1)
    assert.ok(fetched2)
  })

  it('should replace key pair with same alg', async () => {
    const keys1b = await generateKeyPair('ES256', { extractable: true })
    const pubKey1b = await exportJWK(keys1b.publicKey)
    const privKey1b = await exportJWK(keys1b.privateKey)
    const pair1b: TmpVerifierSignatureKeyPair = {
      ...pair1,
      publicKey: { ...pubKey1b, kid: 'kid1b', alg: 'ES256' },
      privateKey: { ...privKey1b, kid: 'kid1b', alg: 'ES256' },
    }

    await store.save(verifier, [pair1])
    await store.save(verifier, [pair1b])
    const fetched = await store.fetch(verifier, 'ES256')
    assert.ok(fetched)
  })

  it('should return null if no key pairs saved', async () => {
    const fetched = await store.fetch(ClientId('https://unknown.example.com'), 'ES256')
    assert.strictEqual(fetched, null)
  })
})
