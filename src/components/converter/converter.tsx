import { invoke } from "@tauri-apps/api";
import { RadioGroupProps, SelectProps } from "antd";

export interface Converter<T> {
	convert: (
		input: Uint8Array,
		from: T,
		to: T,
		isPublic: boolean
	) => Promise<Uint8Array>;
}

export type ConvertRef<T> = {
	getEncoding: () => T;
	setEncoding: (encoding: T) => void;
};

export type ConvertRadioProps<T> = {
	props: RadioGroupProps;
	codecor: Converter<T>;
	getInputs: () => Record<string, string>;
	setInputs: (input: Record<string, string>) => void;
};

export type ConvertSelectProps<T> = {
	props: SelectProps;
	converter: Converter<T>;
	getInputs: () => Record<string, Uint8Array>;
	setInputs: (input: Record<string, Uint8Array>) => void;
};

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

export enum Pkcs {
	Pkcs1 = "pkcs1",
	Pkcs8 = "pkcs8",
	Sec1 = "sec1",
}

export enum Encoding {
	Pem = "pem",
	Der = "der",
}

export class PkcsEncodingProps {
	pkcs: Pkcs;
	encoding: Encoding;

	constructor(pkcs: Pkcs, encoding: Encoding) {
		this.pkcs = pkcs;
		this.encoding = encoding;
	}
}

export const PkcsEncodings: Record<PkcsEncoding, PkcsEncodingProps> = {
	pkcs8_pem: new PkcsEncodingProps(Pkcs.Pkcs8, Encoding.Pem),
	pkcs8_der: new PkcsEncodingProps(Pkcs.Pkcs8, Encoding.Der),
	pkcs1_pem: new PkcsEncodingProps(Pkcs.Pkcs1, Encoding.Pem),
	pkcs1_der: new PkcsEncodingProps(Pkcs.Pkcs1, Encoding.Der),
	sec1_pem: new PkcsEncodingProps(Pkcs.Sec1, Encoding.Pem),
	sec1_der: new PkcsEncodingProps(Pkcs.Sec1, Encoding.Der),
};

export const RsaPkiEncoding = { ...Pkcs1Encoding, ...Pkcs8Encoding };
export type RsaPkiEncoding = typeof RsaPkiEncoding;

type PkcsEncoding = Pkcs8Encoding | Sec1Encoding | Pkcs1Encoding;

export class PkcsConverter implements Converter<PkcsEncoding> {
	async convert(
		input: Uint8Array,
		from: PkcsEncoding,
		to: PkcsEncoding,
		isPublic: boolean
	): Promise<Uint8Array> {
		if (from === to) {
			return new Promise<Uint8Array>((resovle, _) => {
				resovle(input);
			});
		}
		let output;
		const fromData = PkcsEncodings[from];
		const toData = PkcsEncodings[to];
		console.log(fromData);
		console.log(toData);

		switch (true) {
			case fromData.pkcs === Pkcs.Pkcs8 && toData.pkcs === Pkcs.Pkcs1:
			case fromData.pkcs === Pkcs.Pkcs1 && toData.pkcs === Pkcs.Pkcs8:
			case fromData.pkcs === Pkcs.Pkcs8 && toData.pkcs === Pkcs.Pkcs8:
			case fromData.pkcs === Pkcs.Pkcs1 && toData.pkcs === Pkcs.Pkcs1:
				output = await invoke<Uint8Array>("pkcs8_pkcs1_transfer", {
					input,
					from: fromData,
					to: toData,
					isPublic,
				});
				break;
			case fromData.pkcs === Pkcs.Pkcs8 && toData.pkcs === Pkcs.Sec1:
			case fromData.pkcs === Pkcs.Sec1 && toData.pkcs === Pkcs.Pkcs8:
			case fromData.pkcs === Pkcs.Sec1 && toData.pkcs === Pkcs.Sec1:
				output = await invoke<Uint8Array>("pkcs8_sec1_transfer", {
					input,
					from,
					to,
					isPublic,
				});
				break;
			default:
				throw new Error(
					`unsupported pkcs: ${fromData.pkcs} encoding: ${fromData.encoding} convert pkcs: ${toData.pkcs} encoding: ${toData.encoding}`
				);
		}
		return output;
	}
}

export const pkcsConverter = new PkcsConverter();

export type PkcsCodecRef = ConvertRef<PkcsEncoding>;
export type PkcsCodecSelectProps = ConvertSelectProps<PkcsEncoding>;
