import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { CredentialIssuer } from '../../../src/credential-issuer.types'
import { inMemoryIssuerSignatureKeyStore } from '../../../src/providers/in-memory/in-memory-issuer-signature-key-store.provider'
import { SignatureKeyPair } from '../../../src/signature-key.types'

type InMemoryIssuerKeyStoreProvider = ReturnType<typeof inMemoryIssuerSignatureKeyStore>

describe('InMemoryIssuerKeyProvider', () => {
  let provider: InMemoryIssuerKeyStoreProvider

  // Example CredentialIssuer data for testing
  const issuer1 = CredentialIssuer('https://issuer.example.com/hoge')
  const issuer2 = CredentialIssuer('https://issuer.example.com/fuga')
  const unknownIssuer = CredentialIssuer('https://unknown.example.com/unknown')

  //  Example KeyPair data for testing
  const sampleKeyPair1: SignatureKeyPair = {
    privateKey: {
      alg: 'ES256',
      kty: 'EC',
      kid: 'issuer-key-id-1-priv',
      crv: 'P-256',
      d: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
      x: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      y: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    },
    publicKey: {
      alg: 'ES256',
      kty: 'EC',
      kid: 'issuer-key-id-1-pub',
      crv: 'P-256',
      x: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      y: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    },
  }

  const sampleKeyPair2: SignatureKeyPair = {
    privateKey: {
      alg: 'ES256',
      kty: 'RSA',
      kid: 'issuer-key-id-2-priv',
      n: 'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn',
      e: 'AQAB',
      d: 'ddddddddddddddddddddddddddddddddddddddddddd',
    },
    publicKey: {
      alg: 'ES256',
      kty: 'RSA',
      kid: 'issuer-key-id-2-pub',
      n: 'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn',
      e: 'AQAB',
    },
  }

  beforeEach(() => {
    provider = inMemoryIssuerSignatureKeyStore()
  })

  it('should save and fetch an issuer key pair', async () => {
    await provider.save(issuer1, [sampleKeyPair1])
    const fetchedKeyPair = await provider.fetch(issuer1)
    assert.deepStrictEqual(fetchedKeyPair[0].privateKey, sampleKeyPair1.privateKey)
    assert.deepStrictEqual(fetchedKeyPair[0].publicKey, sampleKeyPair1.publicKey)
  })

  it('should return empty array for privateKey and publicKey when fetching a key pair for an unknown issuer', async () => {
    const fetchedKeyPair = await provider.fetch(unknownIssuer)
    assert.equal(fetchedKeyPair.length, 0)
  })

  it('should save and fetch multiple issuer key pairs for different issuers', async () => {
    await provider.save(issuer1, [sampleKeyPair1])
    await provider.save(issuer2, [sampleKeyPair2])

    const fetchedKeyPair1 = await provider.fetch(issuer1)
    assert.deepStrictEqual(fetchedKeyPair1[0].privateKey, sampleKeyPair1.privateKey)
    assert.deepStrictEqual(fetchedKeyPair1[0].publicKey, sampleKeyPair1.publicKey)

    const fetchedKeyPair2 = await provider.fetch(issuer2)
    assert.deepStrictEqual(fetchedKeyPair2[0].privateKey, sampleKeyPair2.privateKey)
    assert.deepStrictEqual(fetchedKeyPair2[0].publicKey, sampleKeyPair2.publicKey)
  })

  it('should overwrite an existing issuer key pair when saving with the same issuer', async () => {
    await provider.save(issuer1, [sampleKeyPair1])

    const updatedKeyPair: SignatureKeyPair = {
      privateKey: { ...sampleKeyPair2.privateKey, kid: 'updated-issuer-priv-kid' },
      publicKey: { ...sampleKeyPair2.publicKey, kid: 'updated-issuer-pub-kid' },
    }
    await provider.save(issuer1, [updatedKeyPair])

    const fetchedKeyPair = await provider.fetch(issuer1)
    assert.deepEqual(fetchedKeyPair[0].privateKey, updatedKeyPair.privateKey)
    assert.deepEqual(fetchedKeyPair[0].publicKey, updatedKeyPair.publicKey)
    assert.notDeepEqual(fetchedKeyPair[0].privateKey, sampleKeyPair1.privateKey) // Verify that it differs from the original key
  })
})
