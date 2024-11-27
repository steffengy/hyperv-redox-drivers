//! Implementation of debounced notify future primitives

use std::{cell::RefCell, future::Future, rc::Rc, task::Poll};


pub struct NotifyReceiver {
    state: Rc<RefCell<NotifyState>>
}

struct NotifyState {
    waker: Option<std::task::Waker>,
    rdy: bool
}

pub struct NotifySender {
    state: Rc<RefCell<NotifyState>>
}

impl NotifySender {
    pub fn notify(&self) {
        let mut state = (*self.state).borrow_mut();
        state.rdy = true;

        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

pub fn notify_pair() -> (NotifySender, NotifyReceiver) {
    let state = Rc::new(RefCell::new(NotifyState {
        waker: None,
        rdy: false,
    }));
    (NotifySender { state: state.clone() }, NotifyReceiver { state })
}

impl Future for NotifyReceiver {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut state = (*self.state).borrow_mut();
        if state.rdy {
            state.rdy = false;
            return Poll::Ready(())
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

pub mod arc {
    use std::{future::Future, sync::{Arc, Mutex}, task::Poll};

    pub struct NotifyReceiver {
        state: Arc<Mutex<NotifyState>>
    }

    struct NotifyState {
        waker: Option<std::task::Waker>,
        rdy: bool
    }

    pub struct NotifySender {
        state: Arc<Mutex<NotifyState>>
    }

    impl NotifySender {
        pub fn notify(&self) {
            let mut state = (*self.state).lock().unwrap();
            state.rdy = true;

            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
    }

    pub fn notify_pair() -> (NotifySender, NotifyReceiver) {
        let state = Arc::new(Mutex::new(NotifyState {
            waker: None,
            rdy: false,
        }));
        (NotifySender { state: state.clone() }, NotifyReceiver { state })
    }

    impl Future for NotifyReceiver {
        type Output = ();

        fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
            let mut state = (*self.state).lock().unwrap();
            if state.rdy {
                state.rdy = false;
                return Poll::Ready(())
            }
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
