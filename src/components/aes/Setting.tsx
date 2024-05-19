import { Drawer, DrawerProps, Form, Select, SelectProps } from "antd";
import { TextSelectCodec } from "../codec/TextCodecSelect";
import { textCodecor } from "../codec/codec";

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

export const AesSetting = ({ open, ...props }: DrawerProps) => {
	const form = Form.useFormInstance();

	const forEncryption = Form.useWatch("forEncryption", {
		form,
		preserve: true,
	});
	return (
		<Drawer
			{...props}
			forceRender={true}
			closable={false}
			open={open}
			key="aes-encryption-setting"
			getContainer={false}
		>
			<Form.Item label="mode" name="mode">
				<Select size={size} options={modes} />
			</Form.Item>
			<Form.Item name="padding" label="padding">
				<Select size={size} options={paddings} />
			</Form.Item>

			<Form.Item name="ivEncoding" label="iv-encoding">
				<TextSelectCodec
					codecor={textCodecor}
					getInputs={() => form.getFieldsValue(["iv"])}
					setInputs={form.setFieldsValue}
				/>
			</Form.Item>
			<Form.Item name="keyEncoding" label="key-encoding">
				<TextSelectCodec
					codecor={textCodecor}
					getInputs={() => form.getFieldsValue(["key"])}
					setInputs={form.setFieldsValue}
				/>
			</Form.Item>
			<Form.Item
				name="inputEncoding"
				label="input-encoding"
				tooltip={
					forEncryption ? (
						<div>
							<div>why disabled it?</div>
							<div>it is unnecessary on ecrypt</div>
						</div>
					) : null
				}
			>
				<TextSelectCodec
					disabled={forEncryption}
					codecor={textCodecor}
					getInputs={() => form.getFieldsValue(["input"])}
					setInputs={form.setFieldsValue}
				/>
			</Form.Item>
			<Form.Item
				name="outputEncoding"
				label="output-encoding"
				tooltip={
					!forEncryption ? (
						<div>
							<div>why disabled it?</div>
							<div>it is unnecessary on decrypt</div>
						</div>
					) : null
				}
			>
				<TextSelectCodec
					disabled={!forEncryption}
					codecor={textCodecor}
					getInputs={() => form.getFieldsValue(["output"])}
					setInputs={form.setFieldsValue}
				/>
			</Form.Item>
		</Drawer>
	);
};
