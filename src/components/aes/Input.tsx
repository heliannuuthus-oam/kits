import { invoke } from "@tauri-apps/api";
import { Button, Col, Input, Row, Select, Space, Typography } from "antd";
import { valueType } from "antd/es/statistic/utils";
import { useState } from "react";

const { TextArea } = Input;

const { Title } = Typography;

enum Mode {
	ECB = "ECB",
	CBC = "CBC",
	GCM = "GCM",
}

enum Padding {
	Pkcs7Padding = "Pkcs7Padding",
	NoPadding = "NoPadding",
}

const size = "middle";

const AesInput = ({
	setCiphertext,
}: {
	setCiphertext: (ciphertext: valueType) => void;
}) => {
	const [mode, setMode] = useState<Mode>(Mode.CBC);
	const [padding, setPaddding] = useState<Padding>(Padding.Pkcs7Padding);
	const [keySize, setKeySize] = useState<number>(128);
	const [key, setKey] = useState<valueType>();
	const [iv, setIv] = useState<valueType>();
	const [aad, setAad] = useState<valueType>();
	const [plaintext, setPlaintext] = useState<valueType>();
	const generateKey = async () => {
		const data: string = await invoke("generate_aes", { keySize: keySize });
		setKey(data);
	};

	const generateIv = async () => {
		const data: string = await invoke("generate_iv", {
			size: mode === Mode.CBC ? 16 : 12,
		});
		setIv(data);
	};

	const encrypt = async () => {
		const ciphertext = await invoke<string>("encrypt_aes", {
			mode: mode,
			key: key,
			plaintext: plaintext,
			padding: padding,
			iv: iv,
		});
		setCiphertext(ciphertext);
	};

	const renderExtract = (mode: Mode) => {
		switch (mode) {
			case Mode.CBC:
				return (
					<Space.Compact size={size} style={{ width: "100%" }}>
						<Input
							placeholder="input iv"
							value={iv}
							onChange={(e) => setIv(e.target.value)}
						/>
						<Button style={{ margin: 0 }} onClick={generateIv}>
							generate iv
						</Button>
					</Space.Compact>
				);
			case Mode.ECB:
				return <></>;
			case Mode.GCM:
				return (
					<Space
						direction="vertical"
						size="middle"
						style={{ display: "flex", width: "100%" }}
					>
						<Space.Compact size={size} style={{ width: "100%" }}>
							<Input
								placeholder="input iv"
								value={iv}
								onChange={(e) => setIv(e.target.value)}
							/>
							<Button style={{ margin: 0 }} onClick={generateIv}>
								generate iv
							</Button>
						</Space.Compact>
						<Space.Compact size={size} style={{ width: "100%" }}>
							<Input
								placeholder="input aad"
								value={aad}
								onChange={(e) => setAad(e.target.value)}
							/>
						</Space.Compact>
					</Space>
				);
		}
	};

	return (
		<Space
			direction="vertical"
			size="middle"
			style={{ display: "flex", width: "100%", padding: 24 }}
		>
			<Row justify="space-between" align="middle">
				<Col>
					<Title style={{ margin: 0 }} level={5}>
						input:
					</Title>
				</Col>
				<Col>
					<Select
						size={size}
						defaultValue={mode}
						onChange={setMode}
						options={[
							{ value: Mode.ECB, label: <span>ECB</span> },
							{ value: Mode.CBC, label: <span>CBC</span> },
							{ value: Mode.GCM, label: <span>GCM</span> },
						]}
					/>
				</Col>
				<Col>
					<Select
						size={size}
						defaultValue={padding}
						onChange={setPaddding}
						options={[
							{ value: Padding.Pkcs7Padding, label: <span>Pkcs7Padding</span> },
							{ value: Padding.NoPadding, label: <span>NoPadding</span> },
						]}
					/>
				</Col>
				<Col>
					<Button
						color="green"
						size={size}
						style={{ margin: 0 }}
						onClick={encrypt}
					>
						encrypt
					</Button>
				</Col>
			</Row>
			<Space.Compact size={size} style={{ width: "100%" }}>
				<Input
					placeholder="input encryption key"
					value={key}
					onChange={(e) => setKey(e.target.value)}
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
				<Button style={{ margin: 0 }} onClick={generateKey}>
					generate key
				</Button>
			</Space.Compact>
			{renderExtract(mode)}

			<TextArea
				style={{ width: "100%", padding: "20, 40" }}
				value={plaintext}
				autoSize={{ minRows: 29, maxRows: 29 }}
				onChange={(e) => setPlaintext(e.target.value)}
			/>
		</Space>
	);
};

export default AesInput;
