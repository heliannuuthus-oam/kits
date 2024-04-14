import { invoke } from "@tauri-apps/api";
import { writeText } from "@tauri-apps/api/clipboard";
import {
	Button,
	Col,
	Input,
	Radio,
	RadioChangeEvent,
	Row,
	Space,
	Typography,
	message,
} from "antd";
import { valueType } from "antd/es/statistic/utils";
import { forwardRef, useImperativeHandle, useState } from "react";
const { Title } = Typography;
const { TextArea } = Input;
enum Formatter {
	Base64 = "base64",
	Hex = "hex",
	Bytes = "bytes",
}

export type AesOutputRef = {
	setCiphertext: (ciphertext: Uint8Array) => void;
};

export type AesOutputProps = {};

const size = "middle";

const encode = async (
	format: Formatter,
	input: Uint8Array
): Promise<string> => {
	console.log("encoding", Array.from(input));

	switch (format) {
		case Formatter.Base64:
			return new Promise<string>((resovle, rejects) => {
				invoke<string>("base64_encode", {
					input: Array.from(input),
					unpadded: false,
					urlsafety: false,
				})
					.then(resovle)
					.catch(rejects);
			});
		case Formatter.Hex:
			return new Promise<string>((resovle, rejects) => {
				invoke<string>("hex_encode", {
					input: Array.from(input),
					uppercase: false,
				})
					.then(resovle)
					.catch(rejects);
			});
		case Formatter.Bytes:
			return new Promise<string>((resovle, _) => {
				resovle(input.join(" "));
			});
	}
};
const decode = async (
	format: Formatter,
	input: string
): Promise<Uint8Array> => {
	console.log("decoding", input);
	switch (format) {
		case Formatter.Base64:
			return new Promise((resolve, rejects) =>
				invoke<Uint8Array>("base64_decode", {
					input: input,
					unpadded: false,
					urlsafety: false,
				})
					.then(resolve)
					.catch(rejects)
			);
		case Formatter.Hex:
			return new Promise((resolve, rejects) =>
				invoke<Uint8Array>("hex_decode", {
					input: input,
					uppercase: false,
				})
					.then(resolve)
					.catch(rejects)
			);
		case Formatter.Bytes:
			return new Promise<Uint8Array>((resovle) =>
				resovle(Uint8Array.from(input.split(" ").map((letter) => +letter)))
			);
	}
};

const AesOutput = forwardRef<AesOutputRef, AesOutputProps>((_props, ref) => {
	const [format, setFormat] = useState<Formatter>(Formatter.Base64);
	const [ciphertext, setCiphertext] = useState<valueType>("");
	const [msgApi, contextHolder] = message.useMessage();

	const copy = async () => {
		await writeText(ciphertext + "");
		msgApi.success("copied");
	};

	useImperativeHandle(ref, () => ({
		setCiphertext(c: Uint8Array) {
			encode(format, c)
				.then(setCiphertext)
				.catch((err) => console.log(err));
		},
	}));

	const changeFormat = async (event: RadioChangeEvent) => {
		decode(format, ciphertext + "")
			.then((bytes) => encode(event.target.value, bytes).then(setCiphertext))
			.catch((err) => console.log(err));

		setFormat(event.target.value);
	};

	return (
		<Space
			direction="vertical"
			size="middle"
			style={{ display: "flex", width: "100%", padding: 24 }}
		>
			{contextHolder}
			<Row justify="space-between" align="middle">
				<Col>
					<Title style={{ margin: 0 }} level={5}>
						Output:
					</Title>
				</Col>
				<Col>
					<Radio.Group
						size={size}
						options={[
							{ value: Formatter.Bytes, label: <span>bytes</span> },
							{ value: Formatter.Base64, label: <span>base64</span> },
							{ value: Formatter.Hex, label: <span>hex</span> },
						]}
						onChange={changeFormat}
						value={format}
						optionType="button"
					/>
				</Col>
				<Col>
					<Button size={size} onClick={copy}>
						copy
					</Button>
				</Col>
			</Row>
			<TextArea
				style={{ width: "100%", padding: "20, 40" }}
				value={ciphertext}
				autoSize={{ minRows: 29, maxRows: 29 }}
				onChange={(e) => setCiphertext(e.target.value)}
			/>
		</Space>
	);
});
export default AesOutput;
