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
}
