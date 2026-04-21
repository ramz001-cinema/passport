import { createHmac } from 'node:crypto'
import { base64UrlDecode, base64UrlEncode } from './utils/base64'
import { constantTimeEqual, ERROR_MESSAGES } from './utils'
import { Inject, Injectable } from '@nestjs/common'
import { PassportOptions, VerifyResult } from './interfaces'
import { PASSPORT_OPTIONS } from './constants/passport.constants'

@Injectable()
export class PassportService {
	private readonly SECRET_KEY: string

	private static readonly HMAC_DOMAIN = 'PassportTokenAuth/v1'
	private static readonly INTERNAL_SEP = '|'

	constructor(
		@Inject(PASSPORT_OPTIONS)
		private readonly options: PassportOptions
	) {
		this.SECRET_KEY = options.secretKey
	}

	private now() {
		return Math.floor(Date.now() / 1000)
	}

	private serialize(user: string, iat: string, exp: string) {
		return [PassportService.HMAC_DOMAIN, user, iat, exp].join(
			PassportService.INTERNAL_SEP
		)
	}

	private computeHmac(data: string) {
		return createHmac('sha256', this.SECRET_KEY).update(data).digest('hex')
	}

	generate(user: string, ttl: number): string {
		const issuedAt = this.now()
		const expiresAt = issuedAt + ttl

		const userPart = base64UrlEncode(user)
		const iatPart = base64UrlEncode(issuedAt.toString())
		const expPart = base64UrlEncode(expiresAt.toString())

		const serialized = this.serialize(userPart, iatPart, expPart)
		const mac = this.computeHmac(serialized)

		return `${userPart}.${iatPart}.${expPart}.${mac}`
	}

	verify(token: string): VerifyResult {
		const parts = token.split('.')
		if (parts.length !== 4)
			return { valid: false, reason: ERROR_MESSAGES.INVALID_FORMAT }

		const [userPart, iatPart, expPart, mac] = parts

		const serialized = this.serialize(userPart, iatPart, expPart)
		const expectedMac = this.computeHmac(serialized)

		if (!constantTimeEqual(mac, expectedMac))
			return { valid: false, reason: ERROR_MESSAGES.INVALID_SIGNATURE }

		const expNumber = Number(base64UrlDecode(expPart))

		if (!Number.isFinite(expNumber))
			return { valid: false, reason: ERROR_MESSAGES.TOKEN_ERROR }
		
		if (this.now() > expNumber)
			return { valid: false, reason: ERROR_MESSAGES.EXPIRED_TOKEN }

		return { valid: true, userId: base64UrlDecode(userPart) }
	}
}
