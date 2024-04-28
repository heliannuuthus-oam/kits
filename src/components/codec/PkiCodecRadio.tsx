import { forwardRef, useRef } from "react";
import { CodecSelect } from "./CodecSelect";
import {
	PkiCodecSelectRef,
	PkiEncoding,
	PkiSelectProps,
	pkiCodecor,
} from "./codec";

export const PkiCodec = forwardRef<PkiCodecSelectRef, PkiSelectProps>(
	(props, _ref) => {
		const codecEl = useRef<PkiCodecSelectRef>(null);

		return (
			<CodecSelect
				ref={codecEl}
				codecor={pkiCodecor}
				getInputs={props.getInputs}
				setInputs={props.setInputs}
				props={{
					options: [
						{ value: PkiEncoding.PKCS8_PEM, label: <span>pkcs8-pem</span> },
						{ value: PkiEncoding.PKCS8_DER, label: <span>pkcs8-der</span> },
						{ value: PkiEncoding.PKCS1_PEM, label: <span>pkcs1-pem</span> },
						{ value: PkiEncoding.PKCS1_DER, label: <span>pkcs1-der</span> },
					],
				}}
			/>
		);
	}
);
