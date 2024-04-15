import { invoke } from "@tauri-apps/api";
import { Radio, RadioChangeEvent, RadioGroupProps, notification } from "antd";
import { forwardRef, useImperativeHandle, useState } from "react";
export enum Formatter {
	Base64 = "base64",
	Hex = "hex",
	UTF8 = "utf8",
}

export const encode = async (
	format: Formatter,
	input: Uint8Array
): Promise<string> => {
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
		case Formatter.UTF8:
			return new Promise<string>((resovle, rejects) => {
				invoke<string>("string_encode", {
					input: Array.from(input),
				})
					.then(resovle)
					.catch(rejects);
			});
	}
};
export const decode = async (
	format: Formatter,
	input: string
): Promise<Uint8Array> => {
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
		case Formatter.UTF8:
			return new Promise((resovle, rejects) => {
				invoke<Uint8Array>("string_decode", {
					input: input,
				})
					.then(resovle)
					.catch(rejects);
			});
	}
};

type CodecProps = {
	props: RadioGroupProps;
	getInput: () => string;
	setInput: (input: string) => void;
};

export type CodecRef = {
	getFormat: () => Formatter;
	setFormat: (format: Formatter) => void;
};

export const Codec = forwardRef<CodecRef, CodecProps>((props, ref) => {
	const [format, setFormat] = useState<Formatter>(props.props.defaultValue);
	const [api, contextHolder] = notification.useNotification({
		stack: { threshold: 1 },
	});

	const openNotification = (
		prev: Formatter,
		present: Formatter,
		msg: string
	) => {
		api.open({
			type: "error",
			message: `change format ${prev} to ${present} failed`,
			description: msg,
			placement: "bottomRight",
			duration: 3,
		});
	};

	const changeFormat = async (event: RadioChangeEvent) => {
		decode(format, props.getInput())
			.then((bytes) =>
				encode(event.target.value, bytes)
					.then((i) => {
						props.setInput(i);
						setFormat(event.target.value);
					})
					.catch((err) => openNotification(format, event.target.value, err))
			)
			.catch((err) => openNotification(format, event.target.value, err));
	};

	useImperativeHandle(ref, () => ({
		getFormat() {
			return format;
		},
		setFormat(format: Formatter) {
			setFormat(format);
		},
	}));

	return (
		<>
			{contextHolder}
			<Radio.Group
				options={[
					{ value: Formatter.UTF8, label: <span>utf8</span> },
					{ value: Formatter.Base64, label: <span>base64</span> },
					{ value: Formatter.Hex, label: <span>hex</span> },
				]}
				onChange={changeFormat}
				value={format}
				{...props.props}
				optionType="button"
			/>
		</>
	);
});
