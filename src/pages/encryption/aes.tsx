import { Button, Col, Flex, Input, Row, Select, Space } from "antd";
import { invoke } from "@tauri-apps/api/tauri";
import { useState } from "react";
import { valueType } from "antd/es/statistic/utils";
const { TextArea } = Input;

const AesEncryption = () => {
	const [keySize, setKeySize] = useState<number>(128);
	const [key, setKey] = useState<valueType>();
	const [generating, setGenerating] = useState<boolean>(false);
	const onChange = (
		e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
	) => {
		console.log("Change:", e.target.value);
	};

	const action = async () => {
		setGenerating(true);
		const data: string = await invoke("generate_aes", { keySize: keySize });
		setKey(data);
		setGenerating(false);
	};

	return (
		<Row>
			<Col span={3}>col-18 col-push-6</Col>
			<Col span={16}>
				<Flex vertical gap={64}>
					<TextArea
						showCount
						autoSize={{ maxRows: 6, minRows: 4 }}
						onChange={onChange}
						size="large"
						placeholder="input plaintext"
					/>
					<Space.Compact size="large">
						<Input
							placeholder="input encryption key"
							value={key}
							onChange={(e) => {
								const { value: inputValue } = e.target;
								setKey(inputValue);
							}}
						/>
						<Select
							defaultValue={keySize}
							onChange={setKeySize}
							style={{ width: 150 }}
							options={[
								{ value: 128, label: <span>128bit</span> },
								{ value: 256, label: <span>256bit</span> },
							]}
						/>
						<Button loading={generating} onClick={action}>
							generate
						</Button>
					</Space.Compact>
					<TextArea
						showCount
						autoSize={{ maxRows: 6, minRows: 4 }}
						onChange={onChange}
						size="large"
						placeholder="output cipher"
					/>
				</Flex>
			</Col>
			<Col span={5}>col-18 col-push-6</Col>
		</Row>
	);
};

export default AesEncryption;
