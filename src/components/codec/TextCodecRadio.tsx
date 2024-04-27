import { invoke } from "@tauri-apps/api";
import { forwardRef } from "react";
import { Codec, CodecProps, CodecRef, Codecor } from "./CodecRadio";

export enum TextEncoding {
	Base64 = "base64",
	Hex = "hex",
	UTF8 = "utf8",
}

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

export type TextCodecRef = CodecRef<TextEncoding>;
export type TextProps = CodecProps<TextEncoding>;

export const TextCodec = forwardRef<TextCodecRef, TextProps>(
	({ codecor, getInputs: getInput, setInputs: setInput, props }, ref) => {
		return (
			<Codec
				ref={ref}
				codecor={codecor}
				getInputs={getInput}
				setInputs={setInput}
				props={{
					defaultValue: TextEncoding.Base64,
					options: [
						{ value: TextEncoding.UTF8, label: <span>utf-8</span> },
						{ value: TextEncoding.Base64, label: <span>base64</span> },
						{ value: TextEncoding.Hex, label: <span>hex</span> },
					],
					...props,
				}}
			></Codec>
		);
	}
);
