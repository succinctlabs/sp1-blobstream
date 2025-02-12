use std::future::Future;
use std::pin::Pin;

use std::task::{Context, Poll};
use std::time::Duration;

use futures::ready;

trait Retry: Sized {
    /// Retry a fallible future `times` times, with a starting delay of `base_delay`,
    /// and an exponential backoff.
    fn retry(self, times: u32, base_delay: Duration) -> RetryFuture<Self>;
}

impl<T: Future> Retry for T {
    fn retry(self, tries: u32, base_delay: Duration) -> RetryFuture<Self> {
        RetryFuture::new(self, tries, base_delay)
    }
}

struct RetryFuture<F> {
    inner: F,
    tries: u32,
    base_delay: Option<Duration>,
    attempts: u32,
    sleep: Option<Pin<Box<dyn Future<Output = ()>>>>,
}

impl<F> RetryFuture<F> {
    #[inline]
    fn new(inner: F, tries: u32, base_delay: Duration) -> Self {
        Self {
            inner,
            tries,
            base_delay: Some(base_delay),
            attempts: 0,
            sleep: None,
        }
    }
}

impl<F, T, E> Future for RetryFuture<F>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFTEY: We are not using self after this point, and this we dont move the inner future.
        let this = unsafe { self.get_unchecked_mut() };

        if let Some(sleep) = &mut this.sleep {
            ready!(sleep.as_mut().poll(cx));

            this.sleep = None;
        }

        // SAFTEY: we havent moved the inner future, only taken references.
        let inner = unsafe { Pin::new_unchecked(&mut this.inner) };
        match ready!(inner.poll(cx)) {
            Ok(output) => Poll::Ready(Ok(output)),
            Err(e) => {
                this.attempts += 1;

                if this.attempts == this.tries {
                    return Poll::Ready(Err(e));
                }

                if let Some(base_delay) = this.base_delay {
                    this.sleep = Some(Box::pin(tokio::time::sleep(
                        base_delay * 2_u32.pow(this.attempts),
                    )));
                }

                Poll::Pending
            }
        }
    }
}
