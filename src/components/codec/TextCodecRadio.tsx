import { forwardRef } from "react";
import { TextCodecRadioProps, TextCodecRef } from "./codec";
import { TextEncoding } from "./codec";
import { CodecRadio } from "./CodecRadio";

export const TextRadioCodec = forwardRef<TextCodecRef, TextCodecRadioProps>(
	({ codecor, getInputs, setInputs, callback = () => {}, ...props }, ref) => {
		return (
			<CodecRadio
				ref={ref}
				callback={callback}
				codecor={codecor}
				getInputs={getInputs}
				setInputs={setInputs}
				defaultValue={TextEncoding.Base64}
				options={[
					{ value: TextEncoding.UTF8, label: <span>utf-8</span> },
					{ value: TextEncoding.Base64, label: <span>base64</span> },
					{ value: TextEncoding.Hex, label: <span>hex</span> },
				]}
				{...props}
			/>
		);
	}
);
