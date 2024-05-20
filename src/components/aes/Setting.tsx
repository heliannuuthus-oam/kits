import { invoke } from "@tauri-apps/api";
import {
	Button,
	Flex,
	Form,
	Select,
	SelectProps,
	Space,
	Tabs,
	message,
} from "antd";
import { AesEncryptionForm } from "../../pages/encryption/aes";
import { textEncodings } from "../codec/codec";
import { TextEncodingSelect } from "../converter/TextEncodingSelect";
import { textEncodingConverter } from "../converter/converter";
import { createStyles } from "antd-style";
import { useState } from "react";
import { CaretRightOutlined } from "@ant-design/icons";
import { writeText } from "@tauri-apps/api/clipboard";
import Collapse from "../Collapse";
const useStyles = createStyles(({ css }) => ({
	container: css`
		.ant-tabs-nav-list {
			display: flex;
			flex-direction: column;
			justify-content: center;
		}
	`,
}));

export enum EncryptionMode {
	ECB = "ECB",
	CBC = "CBC",
	GCM = "GCM",
}

export enum AesPadding {
	Pkcs7Padding = "Pkcs7Padding",
	NoPadding = "NoPadding",
}

const modes: SelectProps["options"] = (
	Object.keys(EncryptionMode) as Array<keyof typeof EncryptionMode>
).map((key) => {
	return {
		value: EncryptionMode[key],
		label: <span>{EncryptionMode[key].toString()}</span>,
	};
});

const paddings: SelectProps["options"] = (
	Object.keys(AesPadding) as Array<keyof typeof AesPadding>
).map((key) => {
	return {
		value: AesPadding[key],
		label: <span>{AesPadding[key].toString()}</span>,
	};
});
const size = "middle";

export const AesSetting = () => {
	const form = Form.useFormInstance<AesEncryptionForm>();

	const { styles } = useStyles();
	const [activeKeys, setActiveKeys] = useState<string[]>([]);
	return (
		<Tabs
			className={styles.container}
			style={{ display: "flex", justifyContent: "center" }}
			tabPosition="left"
			centered
			onChange={(key) => {
				form.setFieldsValue({ forEncryption: key === "encryption" });
				const { inputEncoding, outputEncoding } = form.getFieldsValue([
					"inputEncoding",
					"outputEncoding",
				]);
				form.setFieldsValue({
					inputEncoding: outputEncoding,
					outputEncoding: inputEncoding,
				});
			}}
			items={[
				{
					key: "encrypt",
					tabKey: "encrypt",
					label: "encrypt",
					children: (
						<AesSettingInner
							activeKeys={activeKeys}
							setActiveKeys={setActiveKeys}
						/>
					),
				},
				{
					key: "decrypt",
					tabKey: "decrypt",
					label: "decrypt",
					children: (
						<AesSettingInner
							activeKeys={activeKeys}
							setActiveKeys={setActiveKeys}
						/>
					),
				},
			]}
		/>
	);
};

const AesSettingInner = ({
	activeKeys,
	setActiveKeys,
}: {
	activeKeys: string[];
	setActiveKeys: (val: string[]) => void;
}) => {
	const form = Form.useFormInstance<AesEncryptionForm>();
	const [msgApi, msgContext] = message.useMessage({
		maxCount: 1,
		duration: 4,
	});
	const forEncryption = Form.useWatch("forEncryption", {
		form,
		preserve: true,
	});
	const mode = Form.useWatch("mode", {
		form,
		preserve: true,
	});

	const encryptOrDecrypt = async () => {
		try {
			await form.validateFields({
				validateOnly: true,
			});
			const output = await invoke<string>("crypto_aes", {
				data: form.getFieldsValue(true),
			});

			form.setFieldsValue({ output });
			if (forEncryption) {
				if (output.length > 4096) {
					msgApi.warning("copied failed, output too larger");
				} else {
					await writeText(output);
					msgApi.success("output copied");
				}
			}
		} catch (err: unknown) {
			form.setFieldsValue({ output: "" });
			console.log(err);
		}
	};

	return (
		<Flex justify="space-between" gap={24} vertical>
			{msgContext}
			<Form.Item label="mode" name="mode">
				<Select size={size} options={modes} />
			</Form.Item>
			<Form.Item name="padding" label="padding">
				<Select
					disabled={mode === EncryptionMode.GCM}
					size={size}
					options={paddings}
				/>
			</Form.Item>
			<Space.Compact direction="vertical">
				{!forEncryption ? (
					<Button
						style={{ height: 42 }}
						onClick={encryptOrDecrypt}
						type="primary"
					>
						decrypt
					</Button>
				) : (
					<Button
						style={{ height: 42 }}
						onClick={encryptOrDecrypt}
						type="primary"
					>
						encrypt
					</Button>
				)}
			</Space.Compact>
			<Collapse
				onChange={(key) => {
					if (key instanceof Array) {
						setActiveKeys(key);
					} else {
						setActiveKeys([key]);
					}
				}}
				expandIcon={({ isActive }) => (
					<CaretRightOutlined rotate={isActive ? 90 : 0} />
				)}
				ghost
				activeKey={activeKeys}
				items={[
					{
						key: "configuration",
						label: "encoding",
						children: (
							<>
								<Form.Item name="ivEncoding" label="iv encoding">
									<TextEncodingSelect
										converter={textEncodingConverter}
										getInputs={() => form.getFieldsValue(["iv"])}
										setInputs={form.setFieldsValue}
										options={textEncodings}
									/>
								</Form.Item>
								<Form.Item name="keyEncoding" label="key encoding">
									<TextEncodingSelect
										converter={textEncodingConverter}
										getInputs={() => form.getFieldsValue(["key"])}
										setInputs={form.setFieldsValue}
										options={textEncodings}
									/>
								</Form.Item>
								<Form.Item
									name="inputEncoding"
									label="input encoding"
									tooltip={
										forEncryption ? (
											<div>
												<div>why disabled it?</div>
												<div>it is unnecessary on ecrypt</div>
											</div>
										) : null
									}
								>
									<TextEncodingSelect
										disabled={forEncryption}
										converter={textEncodingConverter}
										getInputs={() => form.getFieldsValue(["input"])}
										setInputs={form.setFieldsValue}
										options={textEncodings}
									/>
								</Form.Item>
								<Form.Item
									name="outputEncoding"
									label="output encoding"
									tooltip={
										!forEncryption ? (
											<div>
												<div>why disabled it?</div>
												<div>it is unnecessary on decrypt</div>
											</div>
										) : null
									}
								>
									<TextEncodingSelect
										disabled={!forEncryption}
										converter={textEncodingConverter}
										getInputs={() => form.getFieldsValue(["output"])}
										setInputs={form.setFieldsValue}
										options={textEncodings}
									/>
								</Form.Item>
							</>
						),
					},
				]}
			/>
		</Flex>
	);
};
