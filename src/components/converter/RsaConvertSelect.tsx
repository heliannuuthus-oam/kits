import { forwardRef } from "react";
import {
	Pkcs1Encoding,
	Pkcs8Encoding,
	ConvertRef,
	RsaConvertSelectProps,
	rsaConverter,
} from "./converter";
import { ConvertSelect } from "./ConvertSelect";

export const RsaSelectConvert = forwardRef<ConvertRef, RsaConvertSelectProps>(
	(
		{
			converter = rsaConverter,
			getInputs,
			setInputs,
			onChange,
			value,
			...props
		},
		ref
	) => {
		return (
			<ConvertSelect
				ref={ref}
				converter={converter}
				getInputs={getInputs}
				setInputs={setInputs}
				value={value}
				onChange={onChange}
				defaultValue={Pkcs8Encoding.PKCS8_PEM}
				options={[
					{ value: Pkcs8Encoding.PKCS8_PEM, label: <span>pkcs8-pem</span> },
					{ value: Pkcs8Encoding.PKCS8_DER, label: <span>pkcs8-der</span> },
					{ value: Pkcs1Encoding.PKCS1_PEM, label: <span>pkcs1-pem</span> },
					{ value: Pkcs1Encoding.PKCS1_DER, label: <span>pkcs1-der</span> },
				]}
				{...props}
			/>
		);
	}
);
