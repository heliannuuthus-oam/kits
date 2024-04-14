import { Col, Row } from "antd";
import { useRef } from "react";
import AesInput from "../../components/aes/Input";
import AesOutput, { AesOutputRef } from "../../components/aes/Output";

export enum Formatter {
	Base64 = "base64",
	Hex = "hex",
	Plaintext = "plaintext",
}

export enum Mode {
	ECB = "ECB",
	CBC = "CBC",
	GCM = "GCM",
}

export enum Padding {
	Pkcs7Padding = "Pkcs7Padding",
	NoPadding = "NoPadding",
}

const AesEncryption = () => {
	const outputEl = useRef<AesOutputRef>(null);

	const setCiphertext = (ciphertext: Uint8Array) => {
		outputEl.current?.setCiphertext(ciphertext);
	};

	return (
		<Row>
			<Col span={12}>
				<AesInput setCiphertext={setCiphertext} />
			</Col>
			<Col span={12}>
				<AesOutput ref={outputEl} />
			</Col>
		</Row>
	);
};

export default AesEncryption;
