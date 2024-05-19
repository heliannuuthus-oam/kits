pub(crate) const SALT: &str = "VSPDJrx1Pj1zqVGN";

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use pbkdf2::pbkdf2_hmac_array;
    use tracing::info;
    use tracing_test::traced_test;

    use crate::utils::common::random_bytes;

    #[test]
    #[traced_test]
    fn test_pbkdf_as_the_same_as_salt_usage() {
        let salt = "VSPDJrx1Pj1zqVGN";
        for length in [16, 32, 48, 64] {
            let start = Instant::now();
            let secret_bytes = random_bytes(length).unwrap();
            let first_result = pbkdf2_hmac_array::<sha2::Sha512, 48>(
                &secret_bytes,
                salt.as_bytes(),
                210_000,
            );
            info!("secret_bytes: {}", first_result.len());
            let second_result = pbkdf2_hmac_array::<sha2::Sha512, 48>(
                &secret_bytes,
                salt.as_bytes(),
                210_000,
            );
            assert_eq!(first_result, second_result);
            let duration = start.elapsed();
            info!("Time elapsed in expensive_function() is: {:?}", duration);
        }
    }
}
