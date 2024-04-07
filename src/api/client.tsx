import axios from "axios";

const instant = axios.create({
	timeout: import.meta.env.VITE_REQUEST_TIMEOUT,
});

instant.interceptors.response.use(
	(resp) => {
		if (resp.status === 200) {
			return resp;
		}
		return Promise.reject(resp);
	},

	(err) => {
		return Promise.reject(err);
	}
);

export default instant;
