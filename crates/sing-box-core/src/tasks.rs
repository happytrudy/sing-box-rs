use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::sync::Notify;

/// Tracks per-connection tasks separately from listener tasks.
///
/// Callers cancel their connection futures before joining this group.
#[derive(Clone, Default)]
pub struct ConnectionTasks {
    state: Arc<TaskState>,
}

#[derive(Default)]
struct TaskState {
    active: AtomicUsize,
    notify: Notify,
}

impl ConnectionTasks {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.state.active.fetch_add(1, Ordering::AcqRel);
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let _guard = TaskGuard { state };
            future.await;
        });
    }

    pub async fn join(&self) {
        loop {
            let notified = self.state.notify.notified();
            if self.state.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct TaskGuard {
    state: Arc<TaskState>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::AcqRel);
        self.state.notify.notify_waiters();
    }
}
