import { invoke } from "@tauri-apps/api";
import { RadioGroupProps, SelectProps } from "antd";
import { TextCodecor, TextEncoding } from "../codec/codec";

export interface Converter<T extends PkcsEncoding> {
	textCodecor: TextCodecor;
	convert: (
		input: Uint8Array,
		from: T,
		to: T,
		isPublic: boolean
	) => Promise<Uint8Array>;
}

export type ConvertRef<T extends PkcsEncoding> = {
	getEncoding: () => T;
	setEncoding: (encoding: T) => void;
	getTextEncoding: () => TextEncoding;
	setTextEncoding: (encoding: TextEncoding) => void;
};

export interface ConvertRadioProps<T extends PkcsEncoding>
	extends RadioGroupProps {
	converter: Converter<T>;
	getInputs: () => Record<string, string>;
	setInputs: (input: Record<string, string>) => void;
}

export interface ConvertSelectProps<T extends PkcsEncoding>
	extends SelectProps {
	converter: Converter<T>;
	getInputs: () => Record<string, string>;
	setInputs: (inputs: Record<string, string>) => void;
}

export enum CurveName {
	NIST_P256 = "nistp256",
	NIST_P384 = "nistp384",
	NIST_P521 = "nistp521",
	Secp256k1 = "secp256k1",
}

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

export type PkcsEncoding = Pkcs8Encoding | Sec1Encoding | Pkcs1Encoding;
export type RsaEncoding = Pkcs8Encoding | Pkcs1Encoding;
export type EccEncoding = Pkcs8Encoding | Sec1Encoding;

export class RsaConverter implements Converter<RsaEncoding> {
	textCodecor: TextCodecor = new TextCodecor();
	async convert(
		input: Uint8Array,
		from: RsaEncoding,
		to: RsaEncoding,
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
			default:
				throw new Error(
					`unsupported pkcs: ${fromData.pkcs} encoding: ${fromData.encoding} convert pkcs: ${toData.pkcs} encoding: ${toData.encoding}`
				);
		}
		return output;
	}
}

export class EccConverter implements Converter<EccEncoding> {
	textCodecor: TextCodecor = new TextCodecor();
	public curveName: CurveName = CurveName.NIST_P256;
	setCurveName(curveName: CurveName) {
		this.curveName = curveName;
	}

	async convert(
		input: Uint8Array,
		from: EccEncoding,
		to: EccEncoding,
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

		switch (true) {
			case fromData.pkcs === Pkcs.Pkcs8 && toData.pkcs === Pkcs.Sec1:
			case fromData.pkcs === Pkcs.Sec1 && toData.pkcs === Pkcs.Pkcs8:
			case fromData.pkcs === Pkcs.Sec1 && toData.pkcs === Pkcs.Sec1:
			case fromData.pkcs === Pkcs.Pkcs8 && toData.pkcs === Pkcs.Pkcs8:
				output = await invoke<Uint8Array>("pkcs8_sec1_transfer", {
					curveName: this.curveName,
					input,
					from: { ...fromData },
					to: { ...toData },
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

export const rsaConverter = new RsaConverter();
export const eccConverter = new EccConverter();

export type RsaConvertRef = ConvertRef<RsaEncoding>;
export type RsaConvertSelectProps = ConvertSelectProps<RsaEncoding>;

export type EccConvertRef = ConvertRef<EccEncoding>;
export type EccConvertSelectProps = ConvertSelectProps<EccEncoding>;
