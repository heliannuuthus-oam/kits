import { forwardRef } from "react";
import { TextCodecRef, TextCodecSelectProps } from "./codec";
import { CodecSelect } from "./CodecSelect";

export enum TextEncoding {
	Base64 = "base64",
	Hex = "hex",
	UTF8 = "utf8",
}

export const TextSelectCodec = forwardRef<TextCodecRef, TextCodecSelectProps>(
	({ codecor, getInputs: getInput, setInputs: setInput, props }, ref) => {
		return (
			<CodecSelect
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
