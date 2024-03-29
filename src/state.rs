use crate::{
    ledger_state::LedgerState, EventIndex, KeystoreBackend, KeystoreError, KeystoreModel,
    TransactionStatus, TransactionUID,
};
use async_std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use futures::{channel::oneshot, TryFuture, TryFutureExt};
use jf_cap::keys::{FreezerPubKey, UserAddress, ViewerPubKey};
use rand_chacha::ChaChaRng;
use reef::Ledger;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;

/// Keystore state which is shared with event handling threads.
pub struct KeystoreSharedState<
    L: 'static + Ledger,
    Backend: KeystoreBackend<L>,
    Meta: Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq,
> {
    pub(crate) state: LedgerState<L>,
    pub(crate) model: KeystoreModel<L, Backend, Meta>,
    pub(crate) sync_handles: Vec<(EventIndex, oneshot::Sender<()>)>,
    pub(crate) txn_subscribers: HashMap<TransactionUID<L>, Vec<oneshot::Sender<TransactionStatus>>>,
    pub(crate) pending_viewing_key_scans: HashMap<ViewerPubKey, Vec<oneshot::Sender<()>>>,
    pub(crate) pending_freezing_key_scans: HashMap<FreezerPubKey, Vec<oneshot::Sender<()>>>,
    pub(crate) pending_sending_key_scans: HashMap<UserAddress, Vec<oneshot::Sender<()>>>,
}

impl<
        L: 'static + Ledger,
        Backend: KeystoreBackend<L>,
        Meta: Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq,
    > KeystoreSharedState<L, Backend, Meta>
{
    fn commit(&mut self) -> Result<(), KeystoreError<L>> {
        self.model.stores.commit()
    }

    fn revert(&mut self) -> Result<(), KeystoreError<L>> {
        self.model.stores.revert()
    }
}

impl<
        L: Ledger,
        Backend: KeystoreBackend<L>,
        Meta: Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq,
    > KeystoreSharedState<L, Backend, Meta>
{
    pub fn new(
        state: LedgerState<L>,
        model: KeystoreModel<L, Backend, Meta>,
        viewing_key_scans: impl IntoIterator<Item = ViewerPubKey>,
        freezing_key_scans: impl IntoIterator<Item = FreezerPubKey>,
        sending_key_scans: impl IntoIterator<Item = UserAddress>,
    ) -> Self {
        Self {
            state,
            model,
            pending_viewing_key_scans: viewing_key_scans
                .into_iter()
                .map(|key| (key, vec![]))
                .collect(),
            pending_freezing_key_scans: freezing_key_scans
                .into_iter()
                .map(|key| (key, vec![]))
                .collect(),
            pending_sending_key_scans: sending_key_scans
                .into_iter()
                .map(|key| (key, vec![]))
                .collect(),
            sync_handles: Default::default(),
            txn_subscribers: Default::default(),
        }
    }

    pub fn backend(&self) -> &Backend {
        &self.model.backend
    }

    pub fn backend_mut(&mut self) -> &mut Backend {
        &mut self.model.backend
    }

    pub fn state(&self) -> LedgerState<L> {
        self.state.clone()
    }

    pub fn rng(&mut self) -> &mut ChaChaRng {
        &mut self.model.rng
    }
}

/// A read-write lock where writes must go through atomic storage transactions.
pub struct KeystoreSharedStateRwLock<
    L: 'static + Ledger,
    Backend: KeystoreBackend<L>,
    Meta: Send + Serialize + DeserializeOwned + Sync + Clone + PartialEq,
>(RwLock<KeystoreSharedState<L, Backend, Meta>>);

impl<
        L: 'static + Ledger,
        Backend: KeystoreBackend<L>,
        Meta: Send + Serialize + DeserializeOwned + Sync + Clone + PartialEq,
    > KeystoreSharedStateRwLock<L, Backend, Meta>
{
    pub fn new(
        state: LedgerState<L>,
        model: KeystoreModel<L, Backend, Meta>,
        viewing_key_scans: impl IntoIterator<Item = ViewerPubKey>,
        freezing_key_scans: impl IntoIterator<Item = FreezerPubKey>,
        sending_key_scans: impl IntoIterator<Item = UserAddress>,
    ) -> Self {
        Self(RwLock::new(KeystoreSharedState::new(
            state,
            model,
            viewing_key_scans,
            freezing_key_scans,
            sending_key_scans,
        )))
    }

    pub async fn read(&self) -> KeystoreSharedStateReadGuard<'_, L, Backend, Meta> {
        self.0.read().await
    }

    pub async fn write(&self) -> KeystoreSharedStateWriteGuard<'_, L, Backend, Meta> {
        KeystoreSharedStateWriteGuard::new(&self.0).await
    }
}

pub type KeystoreSharedStateReadGuard<'l, L, Backend, Meta> =
    RwLockReadGuard<'l, KeystoreSharedState<L, Backend, Meta>>;

/// A guard for [KeystoreSharedState] that allows writing and gracefully handles errors.
///
/// Unlike [RwLockWriteGuard], [KeystoreSharedStateWriteGuard] does not dereference to the target,
/// so the [KeystoreSharedState] cannot be freely edited directly. Instead,
/// [KeystoreSharedStateWriteGuard] provides an [update](Self::update) function, which can be used
/// to apply a closure to the shared state. The guard checks the result of this closure and takes
/// note if it fails. Upon being dropped, if any operation on the guard fails, the persistent _and_
/// in-memory state will be reverted to the state at the time the guard was created. All operations
/// between creating and dropping the guard are atomic.
///
/// This abstraction simplifies the problem of reverting previous changes when a later change fails,
/// and avoids confusion about when to open a storage transaction and when to commit it. With
/// [KeystoreSharedStateWriteGuard], both of these questions have simple answers: you open a
/// transaction when you obtain write access to the resource and you keep it open until you drop
/// your write access. All changes made within a transaction are reverted atomically and
/// automatically if the transaction fails.
pub struct KeystoreSharedStateWriteGuard<
    'l,
    L: 'static + Ledger,
    Backend: KeystoreBackend<L>,
    Meta: Send + Serialize + DeserializeOwned + Sync + Clone + PartialEq,
> {
    guard: RwLockWriteGuard<'l, KeystoreSharedState<L, Backend, Meta>>,
    failed: bool,
}

impl<
        'l,
        L: 'static + Ledger,
        Backend: KeystoreBackend<L>,
        Meta: Send + Serialize + DeserializeOwned + Sync + Clone + PartialEq,
    > KeystoreSharedStateWriteGuard<'l, L, Backend, Meta>
{
    async fn new(
        mutex: &'l RwLock<KeystoreSharedState<L, Backend, Meta>>,
    ) -> KeystoreSharedStateWriteGuard<'l, L, Backend, Meta> {
        Self {
            guard: mutex.write().await,
            failed: false,
        }
    }

    /// Mutate the [KeystoreSharedState] with a closure.
    ///
    /// `op` defines a self-contained operation to apply to the shared state. If it fails, or if any
    /// later operation on the same guard fails, all of its changes will be reverted. Otherwise, its
    /// changes will be committed when the guard is dropped.
    ///
    /// The result of [update](Self::update) is the result of `op`.
    ///
    /// # Lifetimes
    ///
    /// The lifetime `'s` deserves some discussion. It is more idiomatic for closure parameters that
    /// take a reference to use a higher-rank type bound, like
    ///
    /// ```ignore
    /// for<'s> FnOnce(&'s mut T) -> BoxFuture<'s, R>
    /// ```
    ///
    /// However, this simpler type signature states something that we don't want to be true: that
    /// the function parameter, `op`, returns a future that _only_ borrows from its argument
    /// (indicated by the polymorphic `'s`). We want to allow closures that borrow from _both_ their
    /// argument and their environment. Without this, it is impossible to write a function that
    /// takes a reference parameter and uses that parameter during an [update](Self::update) (at
    /// least, not without cloning every reference parameter and moving the clone into the closure).
    /// Unfortunately, there is not a good way to require that the future is bounded by two
    /// lifetimes. We'd like to write something like
    ///
    /// ```ignore
    /// F: for<'a> FnOnce(&'a T) -> BoxFuture<'a + 'b, R>
    /// ```
    ///
    /// or
    ///
    /// ```ignore
    /// for<'a>
    ///     F: FnOnce(&'a T) -> Fut,
    ///     Fut: 'a,
    ///     Fut: 'b,
    /// ```
    ///
    /// But neither of these can be expressed in the Rust type system.
    ///
    /// So, instead of requiring a closure that works for _every_ `'s`, we let the caller provide a
    /// lifetime `'s`, which can be the lifetime of some reference that outlives the
    /// [update](Self::update) operation. This is why the parameter `&'s mut self` is crucial: it
    /// allows the closure `op` to _also_ borrow from its argument, since it's argument, the shared
    /// state managed by this guard, is also borrowed from `self` and thus has the same lifetime,
    /// `'s`.
    ///
    /// This is actually the reason for this guard type's existence. Were it not for this limitation
    /// of the type system, we could simply write an update function that takes a
    /// `RwLock<KeystoreSharedState<'a, L, Backend, Meta>>`, locks it, and then calls `op` on the
    /// temporary guard. This fails because the lifetime of the guard itself must be the same as the
    /// lifetime of the captured environment chosen by the caller, and so the guard must outlive the
    /// update function; hence, we define this [KeystoreSharedStateWriteGuard] type, which can live
    /// on the caller's stack for the duration of the [update](Self::update), allowing the caller to
    /// name its lifetime: `'s`.
    ///
    /// # Errors
    ///
    /// If `op` returns an error, the error propagates out of [update](Self::update), and the guard
    /// enters a failed state. When it is dropped, any changes made by `op` will be reverted.
    ///
    /// If a previous [update](Self::update) failed, subsequent calls to [update](Self::update) will
    /// fail immediately without invoking `op` at all.
    pub async fn update<'s, F, Fut>(&'s mut self, op: F) -> Result<Fut::Ok, Fut::Error>
    where
        F: FnOnce(&'s mut KeystoreSharedState<L, Backend, Meta>) -> Fut,
        Fut: TryFuture<Error = KeystoreError<L>>,
    {
        if self.failed {
            return Err(KeystoreError::Failed {
                msg: "calling update on a transaction that has already failed".into(),
            });
        }

        let failed = &mut self.failed;
        op(&mut *self.guard)
            .inspect_err(|_| {
                // Enter the failed state if the operation fails.
                //
                // The reason we do things this way, instead of just reverting the change right
                // here, is a bit silly. In order to give a name to the lifetime of `op`s argument,
                // we defined the lifetime parameter `'s`, which necessarily outlives the body of
                // this function. Since the future returned by `op` borrows from `self.guard` with
                // lifetime `'s`, the compiler believes that `self.guard` is borrowed mutably until
                // after this function returns, even though this is impossible, since we know that
                // the future will be driven to completion before this error handler gets called.
                // Nevertheless, entering a failure state and then cleaning things up on drop (after
                // this function returns and the compiler realizes `self.guard` can no longer be
                // borrowed) is an acceptable workaround.
                *failed = true;
            })
            .into_future()
            .await
    }
}

impl<
        'l,
        L: 'static + Ledger,
        Backend: KeystoreBackend<L>,
        Meta: Send + Serialize + DeserializeOwned + Sync + Clone + PartialEq,
    > Drop for KeystoreSharedStateWriteGuard<'l, L, Backend, Meta>
{
    fn drop(&mut self) {
        if self.failed {
            self.guard.revert().unwrap();
        } else {
            self.guard.commit().unwrap();
        }
    }
}
