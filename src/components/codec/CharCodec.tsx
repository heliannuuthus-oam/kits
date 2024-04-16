import { invoke } from "@tauri-apps/api";
import { forwardRef } from "react";
import { Codec, CodecProps, CodecRef, Codecor } from "./Codec";

export enum CharFormatter {
	Base64 = "base64",
	Hex = "hex",
	UTF8 = "utf8",
}

export class CharCodecor implements Codecor<CharFormatter> {
	encode(format: CharFormatter, input: Uint8Array): Promise<string> {
		switch (format) {
			case CharFormatter.Base64:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("base64_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case CharFormatter.Hex:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("hex_encode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case CharFormatter.UTF8:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("string_encode", {
						input: Array.from(input),
					})
						.then(resovle)
						.catch(rejects);
				});
		}
	}
	decode(format: CharFormatter, input: string): Promise<Uint8Array> {
		switch (format) {
			case CharFormatter.Base64:
				return new Promise((resolve, rejects) =>
					invoke<Uint8Array>("base64_decode", {
						input: input,
						unpadded: false,
						urlsafety: false,
					})
						.then(resolve)
						.catch(rejects)
				);
			case CharFormatter.Hex:
				return new Promise((resolve, rejects) =>
					invoke<Uint8Array>("hex_decode", {
						input: input,
						uppercase: false,
					})
						.then(resolve)
						.catch(rejects)
				);
			case CharFormatter.UTF8:
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

export const charCodecor = new CharCodecor();

export type CharCodecRef = CodecRef<CharFormatter>;
export type CharProps = CodecProps<CharFormatter>;

export const CharCodec = forwardRef<CharCodecRef, CharProps>(
	({ codecor, getInput, setInput, props }, ref) => {
		return (
			<Codec
				ref={ref}
				codecor={codecor}
				getInput={getInput}
				setInput={setInput}
				props={{
					defaultValue: CharFormatter.Base64,
					options: [
						{ value: CharFormatter.UTF8, label: <span>utf-8</span> },
						{ value: CharFormatter.Base64, label: <span>base64</span> },
						{ value: CharFormatter.Hex, label: <span>hex</span> },
					],
					...props,
				}}
			></Codec>
		);
	}
);
