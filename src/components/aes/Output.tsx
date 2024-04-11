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
	setCiphertext: (ciphertext: valueType) => void;
};

export type AesOutputProps = {};

const size = "middle";

const AesOutput = forwardRef<AesOutputRef, AesOutputProps>((_props, ref) => {
	const [format, setFormat] = useState<Formatter>(Formatter.Base64);
	const [ciphertext, setCiphertext] = useState<valueType>("");
	const [msgApi, contextHolder] = message.useMessage();

	const copy = async () => {
		await writeText(ciphertext + "");
		msgApi.success("copied");
	};

	useImperativeHandle(ref, () => ({
		setCiphertext(c: valueType) {
			setCiphertext(c);
		},
	}));

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
						onChange={({ target: { value } }: RadioChangeEvent) => {
							setFormat(value);
						}}
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
