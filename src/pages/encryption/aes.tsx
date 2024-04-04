import { Col, Flex, Input, Row, Select } from "antd";
const { TextArea } = Input;

const KeySize = () => {
	return (
		<Select
			defaultValue={128}
			style={{ width: 150 }}
			options={[
				{ value: 128, label: <span>128bit</span> },
				{ value: 256, label: <span>256bit</span> },
			]}
		></Select>
	);
};

const AesEncryption = () => {
	const onChange = (
		e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
	) => {
		console.log("Change:", e.target.value);
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
					<Input
						placeholder="input encryption key"
						allowClear
						size="large"
						addonAfter={<KeySize />}
					/>
				</Flex>
			</Col>
			<Col span={5}>col-18 col-push-6</Col>
		</Row>
	);
};

export default AesEncryption;
