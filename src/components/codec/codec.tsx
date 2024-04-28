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

export enum PkiEncoding {
	PKCS1_PEM = "pkcs1_pem",
	PKCS1_DER = "pkcs1_der",
	PKCS8_PEM = "pkcs8_pem",
	PKCS8_DER = "pkcs8_der",
}

export class PkiCodecor implements Codecor<PkiEncoding> {
	encode(encoding: PkiEncoding, input: Uint8Array): Promise<string> {
		switch (encoding) {
			case PkiEncoding.PKCS8_PEM:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiEncoding.PKCS8_DER:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("der_decode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiEncoding.PKCS1_PEM:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiEncoding.PKCS1_DER:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("der_decode", {
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
			case PkiEncoding.PKCS8_PEM:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiEncoding.PKCS8_DER:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("der_decode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiEncoding.PKCS1_PEM:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiEncoding.PKCS1_DER:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("der_decode", {
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

export type PkiCodecSelectRef = CodecRef<PkiEncoding>;
export type PkiSelectProps = CodecSelectProps<PkiEncoding>;
