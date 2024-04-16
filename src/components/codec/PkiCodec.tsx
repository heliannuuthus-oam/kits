import { invoke } from "@tauri-apps/api";
import { forwardRef, useRef } from "react";
import { Codec, CodecProps, CodecRef, Codecor } from "./Codec";

enum PkiFormatter {
	PKCS1_PEM = "pkcs1_pem",
	PKCS1_DER = "pkcs1_der",
	PKCS8_PEM = "pkcs8_pem",
	PKCS8_DER = "pkcs8_der",
}

class PkiCodecor implements Codecor<PkiFormatter> {
	encode(format: PkiFormatter, input: Uint8Array): Promise<string> {
		switch (format) {
			case PkiFormatter.PKCS8_PEM:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiFormatter.PKCS8_DER:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("der_decode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiFormatter.PKCS1_PEM:
				return new Promise<string>((resovle, rejects) => {
					invoke<string>("pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiFormatter.PKCS1_DER:
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
	decode(format: PkiFormatter, input: string): Promise<Uint8Array> {
		switch (format) {
			case PkiFormatter.PKCS8_PEM:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiFormatter.PKCS8_DER:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("der_decode", {
						input: Array.from(input),
						uppercase: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiFormatter.PKCS1_PEM:
				return new Promise<Uint8Array>((resovle, rejects) => {
					invoke<Uint8Array>("pem_encode", {
						input: Array.from(input),
						unpadded: false,
						urlsafety: false,
					})
						.then(resovle)
						.catch(rejects);
				});
			case PkiFormatter.PKCS1_DER:
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

const codecor = new PkiCodecor();

type PkiCodecRef = CodecRef<PkiFormatter>;
type PkiProps = CodecProps<PkiFormatter>;

export const PkiCodec = forwardRef<PkiCodecRef, PkiProps>((props, _ref) => {
	const codecEl = useRef<PkiCodecRef>(null);

	return (
		<Codec
			ref={codecEl}
			codecor={codecor}
			getInput={props.getInput}
			setInput={props.setInput}
			props={{
				options: [
					{ value: PkiFormatter.PKCS8_PEM, label: <span>pkcs8-pem</span> },
					{ value: PkiFormatter.PKCS8_DER, label: <span>pkcs8-der</span> },
					{ value: PkiFormatter.PKCS1_PEM, label: <span>pkcs1-pem</span> },
					{ value: PkiFormatter.PKCS1_DER, label: <span>pkcs1-der</span> },
				],
			}}
		></Codec>
	);
});
