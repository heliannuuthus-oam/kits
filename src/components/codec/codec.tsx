import { invoke } from "@tauri-apps/api";
import { RadioGroupProps, SelectProps } from "antd";

export interface Codecor<T> {
	encode: (encoding: T, input: Uint8Array) => Promise<string>;
	decode: (encoding: T, input: string) => Promise<Uint8Array>;
}

export type CodecRef<T> = {
	getEncoding: () => T;
	setEncoding: (encoding: T) => void;
};

export type CodecRadioProps<T> = {
	props: RadioGroupProps;
	codecor: Codecor<T>;
	getInputs: () => Record<string, string>;
	setInputs: (input: Record<string, string>) => void;
};

export type CodecSelectProps<T> = {
	props: SelectProps;
	codecor: Codecor<T>;
	getInputs: () => Record<string, string>;
	setInputs: (input: Record<string, string>) => void;
};

// ================================ text encoding start ================================
export enum TextEncoding {
	Base64 = "base64",
	Hex = "hex",
	UTF8 = "utf8",
}

export type TextCodecRef = CodecRef<TextEncoding>;
export type TextCodecRadioProps = CodecRadioProps<TextEncoding>;
export type TextCodecSelectProps = CodecSelectProps<TextEncoding>;

export class TextCodecor implements Codecor<TextEncoding> {
	encode(encoding: TextEncoding, input: Uint8Array): Promise<string> {
		switch (encoding) {
			case TextEncoding.Base64:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("base64_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case TextEncoding.Hex:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("hex_encode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case TextEncoding.UTF8:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("string_encode", {
						input: Array.from(input),
					})
						.then(resovle)
						.catch(rejects);
				});
		}
	}
	decode(encoding: TextEncoding, input: string): Promise<Uint8Array> {
		switch (encoding) {
			case TextEncoding.Base64:
				return new Promise((resolve, rejects) =>
					invoke<Uint8Array>("base64_decode", {
						input: input,
						unpadded: false,
						urlsafety: false,
					})
						.then(resolve)
						.catch(rejects)
				);
			case TextEncoding.Hex:
				return new Promise((resolve, rejects) =>
					invoke<Uint8Array>("hex_decode", {
						input: input,
						uppercase: false,
					})
						.then(resolve)
						.catch(rejects)
				);
			case TextEncoding.UTF8:
				return new Promise((resovle, rejects) => {
					invoke<Uint8Array>("string_decode", {
						input: input,
					})
						.then(resovle)
						.catch(rejects);
				});
		}
	}
}

export const textCodecor = new TextCodecor();

// ================================ text encoding end ================================

export enum Pkcs1Encoding {
	PKCS1_PEM = "pkcs1_pem",
	PKCS1_DER = "pkcs1_der",
}

export enum Sec1Encoding {
	SEC1_PEM = "sec1_pem",
	SEC1_DER = "sec1_der",
}

export enum Pkcs8Encoding {
	PKCS8_PEM = "pkcs8_pem",
	PKCS8_DER = "pkcs8_der",
}

export const RsaPkiEncoding = { ...Pkcs1Encoding, ...Pkcs8Encoding };
export type RsaPkiEncoding = typeof RsaPkiEncoding;

type PkiEncoding = Pkcs8Encoding | Sec1Encoding | Pkcs1Encoding;

export class PkiCodecor implements Codecor<PkiEncoding> {
	encode(encoding: PkiEncoding, input: Uint8Array): Promise<string> {
		switch (encoding) {
			case Pkcs8Encoding.PKCS8_PEM:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("pkcs8_pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Pkcs8Encoding.PKCS8_DER:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("pkcs8_der_encode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Pkcs1Encoding.PKCS1_PEM:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("pkcs1_pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Pkcs1Encoding.PKCS1_DER:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("pkcs1_der_encode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Sec1Encoding.SEC1_PEM:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("sec1_pem_encode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Sec1Encoding.SEC1_DER:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("pkcs1_der_encode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
		}
	}
	decode(encoding: PkiEncoding, input: string): Promise<Uint8Array> {
		switch (encoding) {
			case Pkcs8Encoding.PKCS8_PEM:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("pkcs8_pem_decode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Pkcs8Encoding.PKCS8_DER:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("pkcs8_der_decode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Pkcs1Encoding.PKCS1_PEM:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("pkcs1_pem_decode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Pkcs1Encoding.PKCS1_DER:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("pkcs1_der_decode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Sec1Encoding.SEC1_PEM:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("sec1_pem_decode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case Sec1Encoding.SEC1_DER:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("pkcs1_der_decode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
		}
	}
}

export const pkiCodecor = new PkiCodecor();

export type PkiCodecRef = CodecRef<PkiEncoding>;
export type PkiSelectProps = CodecSelectProps<PkiEncoding>;
