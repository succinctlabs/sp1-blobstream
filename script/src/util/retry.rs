use std::future::Future;
use std::time::Duration;

pub async fn retry<Func, Fut, T, E>(func: Func, tries: u32, base_delay: Duration) -> Result<T, E>
where
    Func: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut attempts = 0;
    loop {
        let result = func().await;

        match result {
            Ok(output) => return Ok(output),
            Err(e) => {
                tracing::error!("Got error: {e:?}, retrying...");

                attempts += 1;
                if attempts == tries {
                    return Err(e);
                }
                tokio::time::sleep(base_delay * 2_u32.pow(attempts)).await;
            }
        }
    }
}
