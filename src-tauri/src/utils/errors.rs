use core::result;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("`{0}` is unsupported")]
    Unsupported(String),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            Error::Io(err) => tracing::warn!("io error: {:?}", err),
            Error::Unsupported(err) => {
                tracing::warn!("unsupported error: {:?}", err)
            }
            Error::Internal(err) => {
                tracing::error!("internal error: {:?}", err);
            }
        }

        serializer.serialize_str(self.to_string().as_ref())
    }
}
