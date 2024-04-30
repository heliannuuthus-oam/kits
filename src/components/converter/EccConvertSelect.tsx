import { forwardRef } from "react";
import {
	EccConvertRef,
	EccConvertSelectProps,
	Pkcs8Encoding,
	Sec1Encoding,
	eccConverter,
} from "./converter";
import { ConvertSelect } from "./ConvertSelect";

export const EccSelectConvert = forwardRef<
	EccConvertRef,
	EccConvertSelectProps
>(({ converter = eccConverter, getInputs, setInputs, ...props }, ref) => {
	return (
		<ConvertSelect
			ref={ref}
			converter={converter}
			getInputs={getInputs}
			setInputs={setInputs}
			defaultValue={Pkcs8Encoding.PKCS8_PEM}
			options={[
				{ value: Pkcs8Encoding.PKCS8_PEM, label: <span>pkcs8-pem</span> },
				{ value: Pkcs8Encoding.PKCS8_DER, label: <span>pkcs8-der</span> },
				{ value: Sec1Encoding.SEC1_PEM, label: <span>sec1-pem</span> },
				{ value: Sec1Encoding.SEC1_DER, label: <span>sec1-der</span> },
			]}
			{...props}
		/>
	);
});
