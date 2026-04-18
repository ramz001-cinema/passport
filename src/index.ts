import { createHmac } from 'node:crypto'
import { base64UrlDecode, base64UrlEncode } from './utils/base64'
import { constantTimeEqual } from './utils'

const HMAC_DOMAIN = 'PassportTokenAuth/v1'
const INTERNAL_SEP = '|'

function now() {
	return Math.floor(Date.now() / 1000)
}

function serialize(user: string, iat: string, exp: string) {
	return [HMAC_DOMAIN, user, iat, exp].join(INTERNAL_SEP)
}

function computeHmac(secretKey: string, data: string) {
	return createHmac('sha256', secretKey).update(data).digest('hex')
}

function generateToken(secretKey: string, user: string, ttl: number) {
	const issuedAt = now()
	const expiresAt = issuedAt + ttl

	const userPart = base64UrlEncode(user)
	const iatPart = base64UrlEncode(issuedAt.toString())
	const expPart = base64UrlEncode(expiresAt.toString())

	const serialized = serialize(userPart, iatPart, expPart)
	const mac = computeHmac(secretKey, serialized)

	return `${userPart}.${iatPart}.${expPart}.${mac}`
}

function verifyToken(secretKey: string, token: string) {
	const parts = token.split('.')
	if (parts.length !== 4) return { valid: false, reason: 'Invalid format' }

	const [userPart, iatPart, expPart, mac] = parts

	const serialized = serialize(userPart, iatPart, expPart)
	const expectedMac = computeHmac(secretKey, serialized)

	if (!constantTimeEqual(mac, expectedMac))
		return { valid: false, reason: 'Invalid signature' }

	const expNumber = Number(base64UrlDecode(expPart))

	if (!Number.isFinite(expNumber)) return { valid: false, reason: 'Error' }
	if (now() > expNumber) return { valid: false, reason: 'Expired' }

	return { valid: true, userId: base64UrlDecode(userPart) }
}
