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
