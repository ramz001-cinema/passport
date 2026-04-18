import { createHmac, timingSafeEqual } from 'node:crypto'

const HMAC_DOMAIN = 'PassportTokenAuth/v1'
const INTERNAL_SEP = '|'

function base64UrlEncode(buf: Buffer | string) {
	const str = typeof buf === 'string' ? Buffer.from(buf) : buf

	return str
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '')
}

function base64UrlDecode(str: string) {
	str = str.replace(/-/g, '+').replace(/_/g, '/')

	while (str.length % 4) {
		str += '='
	}

	return Buffer.from(str, 'base64').toString()
}

function constantTimeEqual(a: string, b: string) {
	const bufA = Buffer.from(a)
	const bufB = Buffer.from(b)

	if (bufA.length !== bufB.length) return false

	return timingSafeEqual(bufA, bufB)
}

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

console.log('Passport Token Auth - Version 1.0.0')
console.log(
	'generated Token:',
	generateToken('123456789abcdef', 'user123', 3600)
)
