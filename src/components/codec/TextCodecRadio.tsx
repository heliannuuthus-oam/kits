import { forwardRef } from "react";
import { TextCodecRadioProps, TextCodecRef } from "./codec";
import { TextEncoding } from "./codec";
import { CodecRadio } from "./CodecRadio";

export const TextRadioCodec = forwardRef<TextCodecRef, TextCodecRadioProps>(
	({ codecor, getInputs: getInput, setInputs: setInput, props }, ref) => {
		return (
			<CodecRadio
				ref={ref}
				codecor={codecor}
				getInputs={getInput}
				setInputs={setInput}
				props={{
					defaultValue: TextEncoding.Base64,
					options: [
						{ value: TextEncoding.UTF8, label: <span>utf-8</span> },
						{ value: TextEncoding.Base64, label: <span>base64</span> },
						{ value: TextEncoding.Hex, label: <span>hex</span> },
					],
					...props,
				}}
			/>
		);
	}
);
