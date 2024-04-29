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
