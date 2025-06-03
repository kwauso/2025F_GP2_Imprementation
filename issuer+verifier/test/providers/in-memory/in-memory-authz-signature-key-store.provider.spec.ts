import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { AuthorizationServerIssuer } from '../../../src/authorization-server.types'
import { inMemoryAuthzSignatureKeyStore } from '../../../src/providers/in-memory/in-memory-authz-signature-key-store.provider'
import { SignatureKeyPair } from '../../../src/signature-key.types'

type InMemoryAuthzKeyProvider = ReturnType<typeof inMemoryAuthzSignatureKeyStore>

describe('InMemoryAuthzKeyProvider', () => {
  let provider: InMemoryAuthzKeyProvider

  // Example AuthorizationServerIssuer data for testing
  const issuer1 = AuthorizationServerIssuer('https://authz.example.com/hoge')
  const issuer2 = AuthorizationServerIssuer('https://authz.example.com/fuga')
  const unknownIssuer = AuthorizationServerIssuer('https://unknown.example.com/unknown')

  // Example KeyPair data for testing
  const sampleKeyPair1: SignatureKeyPair = {
    privateKey: {
      alg: 'ES256',
      kty: 'EC',
      kid: 'key-id-1-priv',
      crv: 'P-256',
      d: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
      x: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      y: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    },
    publicKey: {
      alg: 'ES256',
      kty: 'EC',
      kid: 'key-id-1-pub',
      crv: 'P-256',
      x: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      y: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    },
  }

  const sampleKeyPair2: SignatureKeyPair = {
    privateKey: {
      alg: 'RS256',
      kty: 'RSA',
      kid: 'key-id-2-priv',
      n: 'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn',
      e: 'AQAB',
      d: 'ddddddddddddddddddddddddddddddddddddddddddd',
    },
    publicKey: {
      alg: 'RS256',
      kty: 'RSA',
      kid: 'key-id-2-pub',
      n: 'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn',
      e: 'AQAB',
    },
  }

  beforeEach(() => {
    provider = inMemoryAuthzSignatureKeyStore()
  })

  it('should save and fetch an authorization key pair', async () => {
    await provider.save(issuer1, sampleKeyPair1)
    const fetchedKeyPair = await provider.fetch(issuer1)
    assert.deepStrictEqual(fetchedKeyPair.privateKey, sampleKeyPair1.privateKey)
    assert.deepStrictEqual(fetchedKeyPair.publicKey, sampleKeyPair1.publicKey)
  })

  it('should throw error when fetching a key pair for an unknown issuer', async () => {
    assert.rejects(() => provider.fetch(unknownIssuer), 'ILLEGAL_STATE')
  })

  it('should save and fetch multiple authorization key pairs for different issuers', async () => {
    await provider.save(issuer1, sampleKeyPair1)
    await provider.save(issuer2, sampleKeyPair2)

    const fetchedKeyPair1 = await provider.fetch(issuer1)
    assert.deepStrictEqual(fetchedKeyPair1.privateKey, sampleKeyPair1.privateKey)
    assert.deepStrictEqual(fetchedKeyPair1.publicKey, sampleKeyPair1.publicKey)

    const fetchedKeyPair2 = await provider.fetch(issuer2)
    assert.deepStrictEqual(fetchedKeyPair2.privateKey, sampleKeyPair2.privateKey)
    assert.deepStrictEqual(fetchedKeyPair2.publicKey, sampleKeyPair2.publicKey)
  })

  it('should overwrite an existing authorization key pair when saving with the same issuer', async () => {
    await provider.save(issuer1, sampleKeyPair1)

    const updatedKeyPair: SignatureKeyPair = {
      privateKey: { ...sampleKeyPair2.privateKey, kid: 'updated-priv-kid' },
      publicKey: { ...sampleKeyPair2.publicKey, kid: 'updated-pub-kid' },
    }
    await provider.save(issuer1, updatedKeyPair)

    const fetchedKeyPair = await provider.fetch(issuer1)
    assert.deepStrictEqual(fetchedKeyPair.privateKey, updatedKeyPair.privateKey)
    assert.deepStrictEqual(fetchedKeyPair.publicKey, updatedKeyPair.publicKey)
    assert.notDeepStrictEqual(fetchedKeyPair.privateKey, sampleKeyPair1.privateKey) // Verify that it differs from the original key
  })
})
