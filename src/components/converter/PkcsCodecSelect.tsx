import { forwardRef } from "react";
import {
	PkcsCodecRef,
	PkcsCodecSelectProps,
	Pkcs1Encoding,
	Pkcs8Encoding,
	Sec1Encoding,
	pkcsConverter,
} from "../converter/converter";
import { ConvertSelect } from "./ConvertSelect";

export const PkcsSelectConvert = forwardRef<PkcsCodecRef, PkcsCodecSelectProps>(
	({ converter = pkcsConverter, getInputs, setInputs, props }, ref) => {
		return (
			<ConvertSelect
				ref={ref}
				converter={converter}
				getInputs={getInputs}
				setInputs={setInputs}
				props={{
					defaultValue: Pkcs8Encoding.PKCS8_PEM,
					options: [
						{ value: Pkcs8Encoding.PKCS8_PEM, label: <span>pkcs8-pem</span> },
						{ value: Pkcs8Encoding.PKCS8_DER, label: <span>pkcs8-der</span> },
						{ value: Pkcs1Encoding.PKCS1_PEM, label: <span>pkcs1-pem</span> },
						{ value: Pkcs1Encoding.PKCS1_DER, label: <span>pkcs1-der</span> },
						{ value: Sec1Encoding.SEC1_PEM, label: <span>sec1-pem</span> },
						{ value: Sec1Encoding.SEC1_DER, label: <span>sec1-der</span> },
					],
					...props,
				}}
			/>
		);
	}
);
