import { writeText } from "@tauri-apps/api/clipboard";
import { Button, Col, Input, Row, Space, Typography, message } from "antd";
import { valueType } from "antd/es/statistic/utils";
import { forwardRef, useImperativeHandle, useRef, useState } from "react";
import { TextCodecRef, TextEncoding, textCodecor } from "../codec/codec";
import { TextRadioCodec } from "../codec/TextCodecRadio";
const { Title } = Typography;
const { TextArea } = Input;

export type AesOutputRef = {
	setOutput: (output: Uint8Array) => void;
};

export type AesOutputProps = {};

const size = "middle";

const AesOutput = forwardRef<AesOutputRef, AesOutputProps>((_props, ref) => {
	const [output, setOutput] = useState<valueType>("");
	const [msgApi, msgContextHolder] = message.useMessage();
	const codecEl = useRef<TextCodecRef>(null);

	const copy = async () => {
		await writeText(output + "");
		msgApi.success("copied");
	};

	useImperativeHandle(ref, () => ({
		setOutput(out: Uint8Array) {
			textCodecor
				.encode(codecEl.current?.getEncoding() || TextEncoding.Base64, out)
				.then(setOutput)
				.catch(console.log);
		},
	}));

	return (
		<Space
			direction="vertical"
			size="middle"
			style={{ display: "flex", width: "100%", padding: 24 }}
		>
			{msgContextHolder}
			<Row justify="space-between" align="middle">
				<Col>
					<Title style={{ margin: 0 }} level={5}>
						Output:
					</Title>
				</Col>
				<Col>
					<TextRadioCodec
						ref={codecEl}
						codecor={textCodecor}
						props={{ size: size, defaultValue: TextEncoding.Base64 }}
						setInputs={(inputs) => {
							setOutput(inputs["output"]);
						}}
						getInputs={() => {
							return {
								output: output + "",
							};
						}}
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
				value={output}
				autoSize={{ minRows: 29, maxRows: 29 }}
				onChange={(e) => setOutput(e.target.value)}
			/>
		</Space>
	);
});
export default AesOutput;
