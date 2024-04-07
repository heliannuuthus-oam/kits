import instant from "./client";

enum Algorithm {
	AES = "aes",
	ECC = "ecc",
	ED = "ed",
	GM = "gm",
	RSA = "rsa",
}

const keys = async (algorithm: Algorithm, condition: string) => {
	return instant.get(`/processor/keys/${algorithm}`, {
		params: {
			qc: condition,
		},
	});
};

const aesKeys = async (size: number) => {
	return keys(Algorithm.AES, size + "");
};

export { aesKeys };
