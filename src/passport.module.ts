import { DynamicModule, Global, Module } from '@nestjs/common'
import { PassportAsyncOptions, PassportOptions } from './interfaces'
import {
	createPassportOptionsProvider,
	createPassportAsyncOptionsProvider
} from './passport.provider'
import { PassportService } from './passport.service'
import { PASSPORT_OPTIONS } from './constants/passport.constants'

@Global()
@Module({})
export class PassportModule {
	public static register(options: PassportOptions): DynamicModule {
		const optionsProvider = createPassportOptionsProvider(options)

		return {
			module: PassportModule,
			providers: [optionsProvider, PassportService],
			exports: [PassportService, PASSPORT_OPTIONS]
		}
	}

	public static registerAsync(options: PassportAsyncOptions): DynamicModule {
		const optionsProvider = createPassportAsyncOptionsProvider(options)

		return {
			module: PassportModule,
			imports: options.imports || [],
			providers: [optionsProvider, PassportService],
			exports: [PassportService, PASSPORT_OPTIONS]
		}
	}
}
