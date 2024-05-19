import { forwardRef } from "react";
import {
	ConvertRef,
	ConvertSelectProps,
	EccFromat,
	Pkcs8Format,
	PkcsEncodingProps,
	edwardPkcsConverter,
} from "../converter/converter";
import { PkcsFormatSelect } from "../converter/PkcsFormatSelect";

export const EdwardsPkcsSelect = forwardRef<
	ConvertRef,
	ConvertSelectProps<EccFromat, PkcsEncodingProps>
>(
	(
		{
			converter = edwardPkcsConverter,
			getInputs,
			setInputs,
			onChange,
			value,
			...props
		},
		ref
	) => {
		return (
			<PkcsFormatSelect
				ref={ref}
				converter={converter}
				getInputs={getInputs}
				setInputs={setInputs}
				value={value}
				onChange={onChange}
				defaultValue={Pkcs8Format.PKCS8_PEM}
				options={[
					{ value: Pkcs8Format.PKCS8_PEM, label: <span>pkcs8-pem</span> },
					{ value: Pkcs8Format.PKCS8_DER, label: <span>pkcs8-der</span> },
				]}
				{...props}
			/>
		);
	}
);
