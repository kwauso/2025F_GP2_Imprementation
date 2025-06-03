import { verifiableCredentialSchema, jwtVcJsonSchema } from './credential.types'
import { z } from 'zod'

export enum ProofTypes {
  JWT = 'jwt',
}

export const jwtVpJsonHeaderSchema = z.object({
  alg: z.string(),
  typ: z.literal('JWT'),
  kid: z.string().optional(),
})

export const jwtVpJsonBodySchema = <T extends z.ZodType>(t: T) =>
  z.object({
    vp: verifiablePresentationSchema(t),
    iss: z.string().optional(), // issuer
    aud: z.string().optional(), // audience
    nbf: z.number().optional(), // issuanceDate
    exp: z.number().optional(), // expirationDate
    jti: z.string().optional(), // id of the verifiable credential
    nonce: z.string(), // TODO: we have to discuss whether this should be optional or not (not compliant with the spec)
  })

export const jwtVpJsonSchema = <T extends z.ZodType>(t: T) =>
  z.object({
    header: jwtVpJsonHeaderSchema,
    payload: jwtVpJsonBodySchema(t),
  })

export const verifiablePresentationSchema = <T extends z.ZodType>(t: T) =>
  z.object({
    '@context': z.array(z.string()).optional(),
    id: z.string().url().optional(),
    type: z.array(z.string()),
    verifiableCredential: z.array(z.string().or(verifiableCredentialSchema(jwtVcJsonSchema(t)))),
    holder: z.string().url().optional(),
    nonce: z.string().optional(),
  })

export type VerifiablePresentation<T extends Record<string, unknown> = Record<string, unknown>> =
  z.infer<ReturnType<typeof jwtVpJsonBodySchema<z.ZodType<T>>>>
export type JwtVpJson<T extends Record<string, unknown> = Record<string, unknown>> = z.infer<
  ReturnType<typeof jwtVpJsonSchema<z.ZodType<T>>>
>
