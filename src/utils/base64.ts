export function base64UrlEncode(buf: Buffer | string) {
	const str = typeof buf === 'string' ? Buffer.from(buf) : buf

	return str
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '')
}

export function base64UrlDecode(str: string) {
	str = str.replace(/-/g, '+').replace(/_/g, '/')

	while (str.length % 4) {
		str += '='
	}

	return Buffer.from(str, 'base64').toString()
}
