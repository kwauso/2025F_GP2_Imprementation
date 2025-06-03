import assert from 'node:assert/strict'
import { describe, it, beforeEach } from 'node:test'
import { JwtPayload } from '../../src/jwt.types'
import { Jwk } from '../../src/jwk.type'
import { issuerSignatureKey } from '../../src/providers/issuer-signature-key.provider'
import { IssuerSignatureKeyProvider } from '../../src/providers/provider.types'
import { ProofJwtHeader } from '../../src/credential.types'
import { jwtVerify, importJWK } from 'jose'

describe('issuerSignatureKey', () => {
  let provider: IssuerSignatureKeyProvider

  beforeEach(() => {
    provider = issuerSignatureKey()
  })

  it('should have correct kind, name, and single properties', () => {
    assert.equal(provider.kind, 'issuer-signature-key-provider')
    assert.equal(provider.name, 'default-issuer-signature-key-provider')
    assert.strictEqual(provider.single, false)
  })

  describe('generate', () => {
    it('should generate an ES256 key pair by default', async () => {
      const { publicKey, privateKey } = await provider.generate()

      assert.ok(publicKey)
      assert.ok(privateKey)
      assert.equal(publicKey.alg, 'ES256')
      assert.equal(privateKey.alg, 'ES256')
      assert.equal(publicKey.kty, 'EC')
      assert.equal(publicKey.crv, 'P-256')
    })

    it('should generate a key pair with the specified algorithm', async () => {
      const es384Provider = issuerSignatureKey({ alg: 'ES384' })
      const { publicKey, privateKey } = await es384Provider.generate()

      assert.ok(publicKey)
      assert.ok(privateKey)
      assert.equal(publicKey.alg, 'ES384')
      assert.equal(privateKey.alg, 'ES384')
      assert.equal(publicKey.kty, 'EC')
      assert.equal(publicKey.crv, 'P-384')
    })
  })

  describe('sign', () => {
    let privateKey: Jwk
    let publicKey: Jwk
    let jwtPayload: JwtPayload
    const jwtHeader: ProofJwtHeader = {
      typ: 'openid4vci-proof+jwt',
      alg: 'ES256',
      kid: 'test-kid',
    }

    beforeEach(async () => {
      const keyPair = await provider.generate()
      privateKey = keyPair.privateKey
      publicKey = keyPair.publicKey

      const iat = Math.floor(Date.now() / 1000)
      jwtPayload = {
        iss: 'test-issuer',
        sub: 'test-subject',
        aud: 'test-audience',
        iat: iat,
        exp: iat + 3600,
      }
    })

    it('should sign a JWT payload and return a valid signature', async () => {
      const signature = await provider.sign(privateKey, 'ES256', jwtPayload, jwtHeader)
      assert.ok(signature)
      assert.equal(typeof signature, 'string')

      // Reconstruct the JWS to verify the signature
      const protectedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')
      const protectedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')
      const jws = `${protectedHeader}.${protectedPayload}.${signature}`

      const key = await importJWK(publicKey, 'ES256')
      const { payload } = await jwtVerify(jws, key)

      assert.deepStrictEqual(payload, jwtPayload)
    })

    it('should throw an error for invalid private key', async () => {
      const invalidKey: Jwk = { ...privateKey, d: 'invalid' }
      await assert.rejects(
        () => provider.sign(invalidKey, 'ES256', jwtPayload, jwtHeader),
        (err: Error) => {
          assert.match(err.message, /sign error/)
          return true
        }
      )
    })
  })

  describe('canHandle', () => {
    it('should return true for the configured algorithm', () => {
      assert.strictEqual(provider.canHandle('ES256'), true)
    })

    it('should return false for other algorithms', () => {
      assert.strictEqual(provider.canHandle('RS256'), false)
      assert.strictEqual(provider.canHandle('ES384'), false)
    })

    it('should handle custom algorithm correctly', () => {
      const es384Provider = issuerSignatureKey({ alg: 'ES384' })
      assert.strictEqual(es384Provider.canHandle('ES384'), true)
      assert.strictEqual(es384Provider.canHandle('ES256'), false)
    })
  })
})
