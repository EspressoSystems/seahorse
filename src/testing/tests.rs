// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
#![deny(warnings)]

use super::{transactions::Transaction, *};
use chrono::Duration;
use commit::Commitment;
use espresso_macros::generic_tests;
use futures::future::join_all;
use reef::{traits::TransactionKind as _, TransactionKind};
use std::env;

#[derive(Clone, Debug)]
pub struct TxnHistoryWithTimeTolerantEq<L: Ledger>(pub Transaction<L>);

impl<L: Ledger> PartialEq<Self> for TxnHistoryWithTimeTolerantEq<L> {
    fn eq(&self, other: &Self) -> bool {
        let time_tolerance_minutes = match env::var("SEAHORSE_TEST_TXN_HISTORY_TIME_TOLERANCE") {
            Ok(t) => t.parse().expect(
                "SEAHORSE_TEST_TXN_HISTORY_TIME_TOLERANCE should be an integer number of minutes",
            ),
            Err(_) => 5,
        };
        let time_tolerance = Duration::minutes(time_tolerance_minutes);
        let times_eq = if self.0.created_time() < other.0.created_time() {
            *other.0.created_time() - *self.0.created_time() < time_tolerance
        } else {
            *self.0.created_time() - *other.0.created_time() < time_tolerance
        };
        println!("time eq {}", times_eq);
        println!(
            "asset: self: {}, other: {}",
            self.0.asset(),
            other.0.asset()
        );
        println!("kind: self: {}, other: {}", self.0.kind(), other.0.kind());
        println!(
            "receivers: self: {:?}, other: {:?}",
            self.0.receivers(),
            other.0.receivers()
        );
        println!("uid: self: {:?}, other: {:?}", self.0.uid(), other.0.uid());
        times_eq
            && self.0.asset() == other.0.asset()
            && self.0.kind() == other.0.kind()
            && self.0.receivers() == other.0.receivers()
            && self.0.uid() == other.0.uid()
    }
}

pub fn random_txn_hash(rng: &mut ChaChaRng) -> Commitment<cap::Transaction> {
    let mut hash = [0; 64];
    rng.fill_bytes(&mut hash);
    commit::RawCommitmentBuilder::<cap::Transaction>::new("random_txn_hash")
        .fixed_size_bytes(&hash)
        .finalize()
}

#[async_std::test]
pub async fn test_keystore_freeze_unregistered() -> std::io::Result<()> {
    let mut t = crate::testing::mocks::MockSystem::default();
    let mut now = Instant::now();

    // Keystores[0], [1] and [2] will act as the sender, receiver and freezer, respectively.
    let (ledger, mut keystores) = t
        .create_test_network(&[(3, 3)], vec![2, 0, 6], &mut now)
        .await;

    // Set `block_size` to `1` so we don't have to explicitly flush the ledger after each
    // transaction submission.
    ledger.lock().await.set_block_size(1).unwrap();

    let asset = {
        let mut rng = ChaChaRng::from_seed([42u8; 32]);
        let viewing_key = ViewerKeyPair::generate(&mut rng);
        let freeze_key = FreezerKeyPair::generate(&mut rng);
        let policy = AssetPolicy::default()
            .set_viewer_pub_key(viewing_key.pub_key())
            .set_freezer_pub_key(freeze_key.pub_key())
            .reveal_record_opening()
            .unwrap();
        keystores[2]
            .0
            .add_viewing_account(viewing_key, "viewing_key".into(), EventIndex::default())
            .await
            .unwrap();
        keystores[2]
            .0
            .add_freezing_account(freeze_key, "freeze_key".into(), EventIndex::default())
            .await
            .unwrap();
        let asset = keystores[2]
            .0
            .define_asset("test".into(), "test asset".as_bytes(), policy)
            .await
            .unwrap();

        // The first address of keystores[0] gets 1 coin to transfer to keystores[1].
        let src = keystores[2].1[0].clone().address();
        let dst_pub_key = keystores[0].1[0].clone();
        keystores[2]
            .0
            .mint(Some(&src), 1, &asset.code, 1, dst_pub_key)
            .await
            .unwrap();
        t.sync(&ledger, keystores.as_slice()).await;

        asset
    };

    // Check the balance after minting.
    assert_eq!(
        keystores[0]
            .0
            .balance_breakdown(&keystores[0].1[0].address(), &asset.code)
            .await,
        1u64.into()
    );
    assert_eq!(
        keystores[0]
            .0
            .frozen_balance_breakdown(&keystores[0].1[0].address(), &asset.code)
            .await,
        0u64.into()
    );

    // Unregister keystores[0]'s first address by removing it from the address map.
    ledger
        .lock()
        .await
        .network()
        .address_map
        .remove(&keystores[0].1[0].address());

    // Freeze keystores[0]'s record.
    println!(
        "generating a freeze transaction: {}s",
        now.elapsed().as_secs_f32()
    );
    now = Instant::now();
    let src = keystores[2].1[0].clone().address();
    let dst = keystores[0].1[0].clone().address();
    ledger.lock().await.hold_next_transaction();
    keystores[2]
        .0
        .freeze(Some(&src), 1, &asset.code, 1, dst.clone())
        .await
        .unwrap();

    // Check the balance after freezing.
    ledger.lock().await.release_held_transaction();
    t.sync(&ledger, keystores.as_slice()).await;
    assert_eq!(
        keystores[0]
            .0
            .balance_breakdown(&keystores[0].1[0].address(), &asset.code)
            .await,
        0u64.into()
    );
    assert_eq!(
        keystores[0]
            .0
            .frozen_balance_breakdown(&keystores[0].1[0].address(), &asset.code)
            .await,
        1u64.into()
    );

    // Check that trying to transfer fails due to frozen balance.
    println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
    now = Instant::now();
    let src = keystores[0].1[0].clone();
    let dst = keystores[1].1[0].clone();
    match keystores[0]
        .0
        .transfer(Some(&src.address()), &asset.code, &[(dst, 1)], 1)
        .await
    {
        Err(KeystoreError::TransactionError {
            source: TransactionError::InsufficientBalance { .. },
        }) => {
            println!(
                "transfer correctly failed due to frozen balance: {}s",
                now.elapsed().as_secs_f32()
            );
            Ok(())
        }
        ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
    }
}

#[generic_tests]
pub mod generic_keystore_tests {
    use super::*;
    use crate::assets::Icon;
    use async_std::task::block_on;
    use jf_cap::KeyPair;
    use num_traits::identities::One;
    use proptest::{collection::vec, strategy::Strategy, test_runner, test_runner::TestRunner};
    use std::fs::File;
    use std::io::{BufReader, Cursor};
    use std::iter::once;
    use std::path::{Path, PathBuf};
    use tempdir::TempDir;

    fn same_txn_history<L: Ledger>(txn: &Transaction<L>, other: &Transaction<L>) -> bool {
        txn.created_time() == other.created_time()
            && txn.asset() == other.asset()
            && txn.kind() == other.kind()
            && txn.senders() == other.senders()
            && txn.receivers() == other.receivers()
            && txn.fee_change() == other.fee_change()
            && txn.asset_change() == other.asset_change()
    }
    /*
     * Test idea: simulate two keystores transferring funds back and forth. After initial
     * setup, the keystores only receive publicly visible information (e.g. block commitment
     * events and receiver memos posted on bulletin boards). Check that both keystores are
     * able to maintain accurate balance statements and enough state to construct new transfers.
     *
     * - Alice magically starts with some coins, Bob starts empty.
     * - Alice transfers some coins to Bob using exact change.
     * - Alice and Bob check their balances, then Bob transfers some coins back to Alice, in an
     *   amount that requires a fee change record.
     *
     * Limitations:
     * - Parts of the system are mocked (e.g. consensus is replaced by one omniscient validator,
     *   info event streams, query services, and bulletin boards is provided directly to the
     *   keystores by the test)
     */
    #[allow(unused_assignments)]
    async fn test_two_keystores<'a, T: SystemUnderTest<'a>>(native: bool) {
        let mut t = T::default();
        let mut now = Instant::now();

        // One more input and one more output than we will ever need, to test dummy records.
        let num_inputs = 3;
        let num_outputs = 4;

        // Give Alice an initial grant of 10 native coins. If using non-native transfers, give Bob
        // an initial grant with which to pay his transaction fee, since he will not be receiving
        // any native coins from Alice.
        let alice_grant = 10;
        let bob_grant = if native { 0 } else { 2 };
        let (ledger, mut keystores) = t
            .create_test_network(
                &[(num_inputs, num_outputs)],
                vec![alice_grant, bob_grant],
                &mut now,
            )
            .await;
        let alice_pub_keys = keystores[0].1.clone();
        let bob_pub_keys = keystores[1].1.clone();

        // Verify initial keystore state.
        assert_ne!(alice_pub_keys, bob_pub_keys);
        assert_eq!(
            keystores[0].0.balance(&AssetCode::native()).await,
            alice_grant.into()
        );
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&alice_pub_keys[0].clone().address(), &AssetCode::native())
                .await,
            (alice_grant / 2).into()
        );
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&alice_pub_keys[1].clone().address(), &AssetCode::native())
                .await,
            (alice_grant - alice_grant / 2).into()
        );
        assert_eq!(
            keystores[1].0.balance(&AssetCode::native()).await,
            bob_grant.into()
        );
        assert_eq!(
            keystores[1].0.balance(&AssetCode::native()).await,
            bob_grant.into()
        );
        assert_eq!(
            keystores[1]
                .0
                .balance_breakdown(&bob_pub_keys[0].clone().address(), &AssetCode::native())
                .await,
            (bob_grant / 2).into()
        );
        assert_eq!(
            keystores[1]
                .0
                .balance_breakdown(&bob_pub_keys[1].clone().address(), &AssetCode::native())
                .await,
            (bob_grant - bob_grant / 2).into()
        );

        let coin = if native {
            AssetDefinition::native()
        } else {
            let coin = keystores[0]
                .0
                .define_asset(
                    "Alice".into(),
                    "Alice's asset".as_bytes(),
                    Default::default(),
                )
                .await
                .unwrap();
            // Alice gives herself an initial grant of 5 coins.
            keystores[0]
                .0
                .mint(
                    Some(&alice_pub_keys[0].address()),
                    1,
                    &coin.code,
                    5,
                    alice_pub_keys[0].clone(),
                )
                .await
                .unwrap();
            t.sync(&ledger, keystores.as_slice()).await;
            println!("Asset minted: {}s", now.elapsed().as_secs_f32());
            now = Instant::now();

            assert_eq!(keystores[0].0.balance(&coin.code).await, 5u64.into());
            assert_eq!(
                keystores[0]
                    .0
                    .balance_breakdown(&alice_pub_keys[0].address(), &coin.code)
                    .await,
                5u64.into()
            );
            assert_eq!(keystores[1].0.balance(&coin.code).await, 0u64.into());

            coin
        };

        let alice_initial_native_balance = keystores[0].0.balance(&AssetCode::native()).await;
        let bob_initial_native_balance = keystores[1].0.balance(&AssetCode::native()).await;

        // Construct a transaction to transfer some coins from Alice to Bob.
        keystores[0]
            .0
            .transfer(
                Some(&alice_pub_keys[0].address()),
                &coin.code,
                &[(bob_pub_keys[0].clone(), 3)],
                1,
            )
            .await
            .unwrap();
        t.sync(&ledger, keystores.as_slice()).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that both keystores reflect the new balances (less any fees). This cannot be a
        // closure because rust infers the wrong lifetime for the references (it tries to use 'a,
        // which is longer than we want to borrow `keystores` for).
        async fn check_balance<'b, L: 'static + Ledger>(
            keystore: &(
                Keystore<'b, impl KeystoreBackend<'b, L> + Sync + 'b, L, ()>,
                Vec<UserPubKey>,
                TempDir,
            ),
            expected_coin_balance: u64,
            starting_native_balance: U256,
            fees_paid: u64,
            coin: &AssetDefinition,
            native: bool,
        ) {
            if native {
                assert_eq!(
                    keystore
                        .0
                        .balance_breakdown(&keystore.1[0].address(), &coin.code)
                        .await,
                    (expected_coin_balance - fees_paid).into()
                );
            } else {
                assert_eq!(
                    keystore.0.balance(&coin.code).await,
                    expected_coin_balance.into()
                );
                assert_eq!(
                    keystore.0.balance(&AssetCode::native()).await,
                    starting_native_balance - fees_paid
                );
            }
        }
        check_balance(
            &keystores[0],
            2,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        )
        .await;
        check_balance(
            &keystores[1],
            3,
            bob_initial_native_balance,
            0,
            &coin,
            native,
        )
        .await;

        // Check that Bob's keystore has sufficient information to access received funds by
        // transferring some back to Alice.
        //
        // This transaction should also result in a non-zero fee change record being
        // transferred back to Bob, since Bob's only sufficient record has an amount of 3 coins, but
        // the sum of the outputs and fee of this transaction is only 2.
        keystores[1]
            .0
            .transfer(
                Some(&bob_pub_keys[0].address()),
                &coin.code,
                &[(alice_pub_keys[0].clone(), 1)],
                1,
            )
            .await
            .unwrap();
        t.sync(&ledger, keystores.as_slice()).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        check_balance(
            &keystores[0],
            3,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        )
        .await;
        check_balance(
            &keystores[1],
            2,
            bob_initial_native_balance,
            1,
            &coin,
            native,
        )
        .await;
    }

    #[async_std::test]
    pub async fn test_two_keystores_native<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()> {
        test_two_keystores::<T>(true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_two_keystores_non_native<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()>
    {
        test_two_keystores::<T>(false).await;
        Ok(())
    }

    // Test transactions that fail to complete.
    //
    // If `native`, the transaction is a native asset transfer.
    // If `!native && !mint && !freeze`, the transaction is a non-native asset transfer.
    // If `!native && mint`, the transaction is a non-native asset mint.
    // If `!native && freeze`, the transaction is a non-native asset freeze.
    //
    // If `timeout`, the failed transaction times out with no explicit rejection event. Otherwise,
    // the failed transaction fails to verify and a Reject event is emitted.
    //
    // (native, mint), (native, freeze), and (mint, freeze) are pairs of mutually exclusive flags.
    async fn test_keystore_rejected<'a, T: SystemUnderTest<'a>>(
        native: bool,
        mint: bool,
        freeze: bool,
        timeout: bool,
    ) {
        if timeout && T::Ledger::record_root_history() > 100 {
            // Don't run the timeout tests if the timeout threshold is too large. For 100 transfers
            // per timeout, this test takes roughly 10 minutes.
            return;
        }

        let mut t = T::default();

        assert!(!(native && mint));
        assert!(!(native && freeze));
        assert!(!(mint && freeze));

        let mut now = Instant::now();

        // Native transfers have extra fee/change inputs/outputs.
        let num_inputs = if native { 1 } else { 2 };
        let num_outputs = if native { 2 } else { 3 };

        // The sender keystore (keystores[0]) gets an initial grant of 2 for a transaction fee and a
        // payment (or, for non-native transfers, a transaction fee and a mint fee). keystores[1] will
        // act as the receiver, and keystores[2] will be a third party which generates
        // RECORD_HOLD_TIME transfers while a transfer from keystores[0] is pending, causing the
        // transfer to time out.
        let (ledger, mut keystores) = t
            .create_test_network(
                &[(num_inputs, num_outputs)],
                // If native, each address of keystores[0] gets 1 coin to transfer and 1 for a
                // transaction fee. Otherwise, it gets
                //  * 1 transaction fee
                //  * 1 mint fee for its initial non-native record, if the test itself is not minting
                //    that record
                //  * 1 mint fee for keystores[2]'s initial non-native record in the timeout test.
                vec![
                    if native {
                        4
                    } else {
                        2 * (1 + !mint as u64 + timeout as u64)
                    },
                    0,
                    4 * T::Ledger::record_root_history() as u64,
                ],
                &mut now,
            )
            .await;

        let asset = if native {
            AssetDefinition::native()
        } else {
            let mut rng = ChaChaRng::from_seed([42u8; 32]);
            let viewing_key = ViewerKeyPair::generate(&mut rng);
            let freeze_key = FreezerKeyPair::generate(&mut rng);
            let policy = AssetPolicy::default()
                .set_viewer_pub_key(viewing_key.pub_key())
                .set_freezer_pub_key(freeze_key.pub_key())
                .reveal_record_opening()
                .unwrap();
            keystores[0]
                .0
                .add_viewing_account(viewing_key, "viewing_key".into(), EventIndex::default())
                .await
                .unwrap();
            keystores[0]
                .0
                .add_freezing_account(freeze_key, "freeze_key".into(), EventIndex::default())
                .await
                .unwrap();
            let asset = keystores[0]
                .0
                .define_asset("test".into(), "test asset".as_bytes(), policy)
                .await
                .unwrap();

            if !mint {
                // If we're freezing, the transaction is essentially taking balance away from
                // keystores[1], so keystores[1] gets 1 coin to start with. Otherwise, the transaction
                // is transferring balance from keystores[0] to keystores[1], so  keystores[0] gets 1
                // coin. We only need this if the test itself is not minting the asset later on.
                let src = keystores[0].1[0].clone().address();
                let dst_pub_key = if freeze {
                    keystores[1].1[0].clone()
                } else {
                    keystores[0].1[0].clone()
                };
                keystores[0]
                    .0
                    .mint(Some(&src), 1, &asset.code, 1, dst_pub_key)
                    .await
                    .unwrap();
                t.sync(&ledger, keystores.as_slice()).await;
            }

            if timeout {
                // If doing a timeout test, keystores[2] (the sender that will generate enough
                // transactions to cause keystores[0]'s transaction to timeout) gets RECORD_HOLD_TIME
                // coins.
                let src = keystores[0].1[0].clone().address();
                let dst_pub_key = keystores[2].1[0].clone();
                keystores[0]
                    .0
                    .mint(
                        Some(&src),
                        1,
                        &asset.code,
                        T::Ledger::record_root_history() as u64,
                        dst_pub_key,
                    )
                    .await
                    .unwrap();
                t.sync(&ledger, keystores.as_slice()).await;
            }

            asset
        };

        // Start a transfer that will ultimately get rejected.
        println!(
            "generating a transfer which will fail: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        ledger.lock().await.hold_next_transaction();
        let sender = keystores[0].1[0].clone().address();
        let receiver_pub_key = keystores[1].1[0].clone();
        let receiver = receiver_pub_key.address();
        if mint {
            keystores[0]
                .0
                .mint(Some(&sender), 1, &asset.code, 1, receiver_pub_key.clone())
                .await
                .unwrap();
        } else if freeze {
            keystores[0]
                .0
                .freeze(Some(&sender), 1, &asset.code, 1, receiver.clone())
                .await
                .unwrap();
        } else {
            keystores[0]
                .0
                .transfer(
                    Some(&sender),
                    &asset.code,
                    &[(receiver_pub_key.clone(), 1)],
                    1,
                )
                .await
                .unwrap();
        }
        println!("transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that the sender's balance is on hold (for the fee and the payment).
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&sender, &AssetCode::native())
                .await,
            0u64.into()
        );
        if !freeze {
            assert_eq!(
                keystores[0].0.balance_breakdown(&sender, &asset.code).await,
                0u64.into()
            );
        }

        // Now do something that causes the sender's transaction to not go through
        if timeout {
            // Generate RECORD_HOLD_TIME transactions to cause `txn` to time out.
            println!(
                "generating {} transfers to time out the original transfer: {}s",
                T::Ledger::record_root_history(),
                now.elapsed().as_secs_f32()
            );
            now = Instant::now();
            for _ in 0..T::Ledger::record_root_history() {
                // Check that the sender's balance is still on hold.
                assert_eq!(
                    keystores[0]
                        .0
                        .balance_breakdown(&sender, &AssetCode::native())
                        .await,
                    0u64.into()
                );
                if !freeze {
                    assert_eq!(
                        keystores[0].0.balance_breakdown(&sender, &asset.code).await,
                        0u64.into()
                    );
                }

                let sender = keystores[2].1[0].clone().address();
                keystores[2]
                    .0
                    .transfer(
                        Some(&sender),
                        &asset.code,
                        &[(receiver_pub_key.clone(), 1)],
                        1,
                    )
                    .await
                    .unwrap();
                t.sync(&ledger, keystores.as_slice()).await;
            }
        } else {
            {
                let mut ledger = ledger.lock().await;

                // Change the validator state, so that the keystore's transaction (built against the
                // old validator state) will fail to validate.
                ledger.mangle();

                println!(
                    "validating invalid transaction: {}s",
                    now.elapsed().as_secs_f32()
                );
                now = Instant::now();
                ledger.release_held_transaction();
                ledger.flush().unwrap();

                // The sender gets back in sync with the validator after their transaction is
                // rejected.
                ledger.unmangle();
            }

            t.sync(&ledger, keystores.as_slice()).await;
        }

        // Check that the sender got their balance back.
        if native {
            assert_eq!(
                keystores[0]
                    .0
                    .balance_breakdown(&sender, &AssetCode::native())
                    .await,
                2u64.into()
            );
        } else {
            assert_eq!(
                keystores[0]
                    .0
                    .balance_breakdown(&sender, &AssetCode::native())
                    .await,
                1u64.into()
            );
            if !(mint || freeze) {
                // in the mint and freeze cases, we never had a non-native balance to start with
                assert_eq!(
                    keystores[0].0.balance_breakdown(&sender, &asset.code).await,
                    1u64.into()
                );
            }
        }
        assert_eq!(
            keystores[1]
                .0
                .balance_breakdown(&receiver, &asset.code)
                .await,
            U256::from(if timeout {
                T::Ledger::record_root_history() as u64
            } else {
                0
            }) + (if freeze { 1 } else { 0 })
        );

        // Now check that they can use the un-held record if their state gets back in sync with the
        // validator.
        println!(
            "transferring un-held record: {}s",
            now.elapsed().as_secs_f32()
        );
        if mint {
            keystores[0]
                .0
                .mint(Some(&sender), 1, &asset.code, 1, receiver_pub_key)
                .await
                .unwrap();
        } else if freeze {
            keystores[0]
                .0
                .freeze(Some(&sender), 1, &asset.code, 1, receiver.clone())
                .await
                .unwrap();
        } else {
            keystores[0]
                .0
                .transfer(Some(&sender), &asset.code, &[(receiver_pub_key, 1)], 1)
                .await
                .unwrap();
        }
        t.sync(&ledger, keystores.as_slice()).await;
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&sender, &AssetCode::native())
                .await,
            0u64.into()
        );
        assert_eq!(
            keystores[0].0.balance_breakdown(&sender, &asset.code).await,
            0u64.into()
        );
        assert_eq!(
            keystores[1]
                .0
                .balance_breakdown(&receiver, &asset.code)
                .await,
            U256::from(if timeout {
                T::Ledger::record_root_history()
            } else {
                0
            }) + (if freeze { 0 } else { 1 })
        );
    }

    #[async_std::test]
    pub async fn test_keystore_rejected_native_xfr_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_keystore_rejected::<T>(true, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_keystore_rejected_native_xfr_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_keystore_rejected::<T>(true, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_keystore_rejected_non_native_xfr_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_keystore_rejected::<T>(false, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_keystore_rejected_non_native_xfr_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_keystore_rejected::<T>(false, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_keystore_rejected_non_native_mint_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_keystore_rejected::<T>(false, true, false, false).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_keystore_rejected_non_native_mint_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_keystore_rejected::<T>(false, true, false, true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_keystore_rejected_non_native_freeze_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_keystore_rejected::<T>(false, false, true, false).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_keystore_rejected_non_native_freeze_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_keystore_rejected::<T>(false, false, true, true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_keystore_freeze<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()> {
        let mut t = T::default();
        let mut now = Instant::now();

        // Each of the two addresses of the sender keystore (keystores[0]) gets an initial grant of 1
        // for a transfer fee. keystores[1] will act as the receiver, and keystores[2] will be a third
        // party which creates and freezes some of keystores[0]'s assets. Each of its two addresses
        // gets a grant of 3, for a mint fee, a freeze fee and an unfreeze fee.
        //
        // Note that the transfer proving key size (3, 4) used here is chosen to be 1 larger than
        // necessary in both inputs and outputs, to test dummy records.
        let (ledger, mut keystores) = t
            .create_test_network(&[(3, 4)], vec![2, 2, 2], &mut now)
            .await;
        let mut expected_history = keystores[0]
            .0
            .transaction_history()
            .await
            .unwrap()
            .into_iter()
            .map(TxnHistoryWithTimeTolerantEq)
            .collect::<Vec<_>>();

        let (asset, r1) = {
            let mut rng = ChaChaRng::from_seed([42u8; 32]);
            let viewing_key = ViewerKeyPair::generate(&mut rng);
            let freeze_key = FreezerKeyPair::generate(&mut rng);
            let policy = AssetPolicy::default()
                .set_viewer_pub_key(viewing_key.pub_key())
                .set_freezer_pub_key(freeze_key.pub_key())
                .reveal_record_opening()
                .unwrap();
            keystores[2]
                .0
                .add_viewing_account(viewing_key, "viewing_key".into(), EventIndex::default())
                .await
                .unwrap();
            keystores[2]
                .0
                .add_freezing_account(freeze_key, "freeze_key".into(), EventIndex::default())
                .await
                .unwrap();
            let asset = keystores[2]
                .0
                .define_asset("test".into(), "test asset".as_bytes(), policy)
                .await
                .unwrap();

            // keystores[0] gets 1 coin to transfer to keystores[1].
            let src = keystores[2].1[0].clone().address();
            let dst_pub_key = keystores[0].1[0].clone();
            let r1 = keystores[2]
                .0
                .mint(Some(&src), 0, &asset.code, 3, dst_pub_key)
                .await
                .unwrap();
            t.sync(&ledger, keystores.as_slice()).await;

            (asset, r1)
        };
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&keystores[0].1[0].address(), &asset.code)
                .await,
            3u64.into()
        );
        assert_eq!(
            keystores[0]
                .0
                .frozen_balance_breakdown(&keystores[0].1[0].address(), &asset.code)
                .await,
            0u64.into()
        );

        // Now freeze keystores[0]'s record.
        println!(
            "generating a freeze transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        let src = keystores[2].1[0].clone().address();
        let dst = keystores[0].1[0].clone().address();
        ledger.lock().await.hold_next_transaction();
        let r2 = keystores[2]
            .0
            .freeze(Some(&src), 0, &asset.code, 3, dst.clone())
            .await
            .unwrap();

        // Check that, like transfer inputs, freeze inputs are placed on hold and unusable while a
        // freeze that uses them is pending.
        match keystores[2]
            .0
            .freeze(Some(&src), 0, &asset.code, 3, dst)
            .await
        {
            Err(KeystoreError::TransactionError {
                source: TransactionError::InsufficientBalance { .. },
            }) => {}
            ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
        }

        // Now go ahead with the original freeze.
        ledger.lock().await.release_held_transaction();
        t.sync(&ledger, keystores.as_slice()).await;
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&keystores[0].1[0].address(), &asset.code)
                .await,
            0u64.into()
        );
        assert_eq!(
            keystores[0]
                .0
                .frozen_balance_breakdown(&keystores[0].1[0].address(), &asset.code)
                .await,
            3u64.into()
        );

        // Check that trying to transfer fails due to frozen balance.
        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();
        let src = keystores[0].1[0].clone().address();
        let dst_pub_key = keystores[1].1[0].clone();
        match keystores[0]
            .0
            .transfer(Some(&src), &asset.code, &[(dst_pub_key, 1)], 0)
            .await
        {
            Err(KeystoreError::TransactionError {
                source: TransactionError::InsufficientBalance { .. },
            }) => {
                println!(
                    "transfer correctly failed due to frozen balance: {}s",
                    now.elapsed().as_secs_f32()
                );
                now = Instant::now();
            }
            ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
        }

        // Now unfreeze the asset and try again.
        println!(
            "generating an unfreeze transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        let src = keystores[2].1[0].clone().address();
        let dst_pub_key = keystores[0].1[0].clone();
        let dst = dst_pub_key.address();
        let r3 = keystores[2]
            .0
            .unfreeze(Some(&src), 0, &asset.code, 3, dst)
            .await
            .unwrap();
        t.sync(&ledger, keystores.as_slice()).await;
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&keystores[0].1[0].address(), &asset.code)
                .await,
            3u64.into()
        );
        assert_eq!(
            keystores[0]
                .0
                .frozen_balance_breakdown(&keystores[0].1[0].address(), &asset.code)
                .await,
            0u64.into()
        );

        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        let src = keystores[0].1[0].clone().address();
        let dst_pub_key = keystores[1].1[0].clone();
        let xfr_receipt = keystores[0]
            .0
            .transfer(Some(&src), &asset.code, &[(dst_pub_key, 1)], 0)
            .await
            .unwrap()
            .clone();
        t.sync(&ledger, keystores.as_slice()).await;
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&keystores[0].1[0].address(), &asset.code)
                .await,
            2u64.into()
        );
        assert_eq!(
            keystores[0]
                .0
                .frozen_balance_breakdown(&keystores[0].1[0].address(), &asset.code)
                .await,
            0u64.into()
        );
        assert_eq!(
            keystores[1]
                .0
                .balance_breakdown(&keystores[1].1[0].address(), &asset.code)
                .await,
            1u64.into()
        );

        // Check that the history properly accounts for freezes and unfreezes.
        expected_history.extend(
            vec![
                transactions::create_test_txn(
                    r1,
                    TransactionParams {
                        timeout: None,
                        status: TransactionStatus::Unknown,
                        signed_memos: None,
                        inputs: Default::default(),
                        outputs: Default::default(),
                        time: Local::now(),
                        asset: asset.code,
                        kind: TransactionKind::<T::Ledger>::mint(),
                        senders: Vec::new(),
                        receivers: vec![(keystores[0].1[0].address(), 3.into())],
                        fee_change: None,
                        asset_change: None,
                    },
                ),
                transactions::create_test_txn(
                    r2,
                    TransactionParams {
                        timeout: None,
                        status: TransactionStatus::Unknown,
                        signed_memos: None,
                        inputs: Default::default(),
                        outputs: Default::default(),
                        time: Local::now(),
                        asset: asset.code,
                        kind: TransactionKind::<T::Ledger>::freeze(),
                        senders: Vec::new(),
                        receivers: vec![(keystores[0].1[0].address(), 3.into())],
                        fee_change: None,
                        asset_change: None,
                    },
                ),
                transactions::create_test_txn(
                    r3,
                    TransactionParams {
                        timeout: None,
                        status: TransactionStatus::Unknown,
                        signed_memos: None,
                        inputs: Default::default(),
                        outputs: Default::default(),
                        time: Local::now(),
                        asset: asset.code,
                        kind: TransactionKind::<T::Ledger>::unfreeze(),
                        senders: Vec::new(),
                        receivers: vec![(keystores[0].1[0].address(), 3.into())],
                        fee_change: None,
                        asset_change: None,
                    },
                ),
                transactions::create_test_txn(
                    xfr_receipt,
                    TransactionParams {
                        timeout: None,
                        status: TransactionStatus::Unknown,
                        signed_memos: None,
                        inputs: Default::default(),
                        outputs: Default::default(),
                        time: Local::now(),
                        asset: asset.code,
                        kind: TransactionKind::<T::Ledger>::send(),
                        senders: keystores[0]
                            .1
                            .clone()
                            .into_iter()
                            .map(|pub_key| pub_key.address())
                            .collect::<Vec<_>>(),
                        receivers: vec![(keystores[1].1[0].address(), RecordAmount::one())],
                        fee_change: Some(1.into()),
                        asset_change: Some(2.into()),
                    },
                ),
            ]
            .into_iter()
            .map(TxnHistoryWithTimeTolerantEq),
        );
        let actual_history = keystores[0]
            .0
            .transaction_history()
            .await
            .unwrap()
            .into_iter()
            .map(TxnHistoryWithTimeTolerantEq)
            .collect::<Vec<_>>();
        assert_eq!(actual_history, expected_history);

        Ok(())
    }

    /*
     * This test is very similar to test_two_keystores, but it is parameterized on the number of users,
     * number of asset types, initial ledger state, and transactions to do, so it can be used with
     * quickcheck or proptest to do randomized fuzzing.
     */
    #[allow(clippy::type_complexity)]
    async fn test_multixfr_keystore<'a, T: SystemUnderTest<'a>>(
        // List of blocks containing (def,key1,key2,amount) transfer specs
        // An asset def of 0 in a transfer spec or record indicates the native asset type; other
        // asset types are indexed startin from 1.
        txs: Vec<Vec<(u8, u8, u8, u64)>>,
        nkeystores: u8,
        ndefs: u8,
        // (def,key,amount)
        init_rec: (u8, u8, u64),
        init_recs: Vec<(u8, u8, u64)>,
    ) {
        let mut t = T::default();

        println!(
            "multixfr_keystore test: {} users, {} assets, {} records, {} transfers",
            nkeystores,
            ndefs,
            init_recs.len() + 1,
            txs.iter().flatten().count()
        );
        let mut now = Instant::now();

        let xfr_sizes = &[
            (1, 2), // basic native transfer
            (2, 2), // basic non-native transfer, or native merge
            (2, 3), // non-native transfer with change output
            (3, 2), // non-native merge
        ];
        let mut balances = vec![vec![0u64.into(); ndefs as usize + 1]; nkeystores as usize];
        let grants =
            // Each of the two addresses of the minter (keystore 0) gets 1 coin per initial record,
            // to pay transaction fees while it mints and distributes the records, and 1 coin per
            // transaction, to pay transaction fees while minting additional records if test
            // keystores run out of balance during the test.
            once((1 + init_recs.len() + txs.iter().flatten().count()) as u64 * 2).chain(
                (0..nkeystores)
                    .map(|i| {
                        // The remaining keystores (the test keystores) get 1 coin for each transaction
                        // in which they are the sender, to pay transaction fees, plus...
                        let txn_fees = txs.iter()
                            .flatten()
                            .map(|(_, sender, _, _)| {
                                if sender % nkeystores == i {1} else {0}
                            })
                            .sum::<u64>();
                        balances[i as usize][0] += txn_fees.into();
                        (txn_fees +
                        // ...one record for each native asset type initial record that they own,
                        // plus...
                        once(&init_rec).chain(&init_recs)
                            .map(|(def, owner, amount)| {
                                let def = (def % (ndefs + 1)) as usize;
                                let owner = (owner % nkeystores) as usize;
                                if def == 0 && owner == (i as usize) {
                                    balances[owner][def] += (*amount).into();
                                    *amount
                                } else {
                                    0
                                }
                            })
                            .sum::<u64>() +
                        // We want to prevent transfers of the native asset type from failing due to
                        // insufficient funds, or worse, from dipping into native coins which were
                        // intended to be used later as transaction fees. Unlike non-native
                        // transfers, we can't mint more native coins during the test if we find
                        // that one of the keystores is low on balance. So we give each keystore an
                        // extra grant of native coins large enough to cover all the native
                        // transactions it will need to make, when combined with its original grant
                        // of native coins.
                        {
                            let total_txn_amount: u64 = txs.iter()
                                .flatten()
                                .map(|(def, sender, _, amount)| {
                                    if (def % (ndefs + 1)) == 0 && (sender % nkeystores) == i {
                                        *amount
                                    } else {
                                        0
                                    }
                                })
                                .sum();
                            if U256::from(txn_fees + total_txn_amount) > balances[i as usize][0] {
                                let extra = U256::from(txn_fees + total_txn_amount) - balances[i as usize][0];
                                balances[i as usize][0] += extra;
                                extra.as_u64()
                            } else {
                                0
                            }
                        })
                        // Give the same grant to the two addresses of each keystore.
                        * 2
                    })
            ).collect();

        let (ledger, mut keystores) = t.create_test_network(xfr_sizes, grants, &mut now).await;
        println!(
            "ceremony complete, minting initial records: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();

        // `histories` is a list of blocks of transactions for each keystore. The reason for
        // blocking the history entries is that entries corresponding to transactions that were
        // validated in the same block can be recorded by the keystores in any order. Each keystore
        // starts with 1 block, containing the history entries it had after initialization. We will
        // append more blocks as we generate test transactions, and after each block we will check
        // that each keystore's reported historoy matches its expected history.
        let mut histories: Vec<Vec<Vec<Transaction<T::Ledger>>>> =
            join_all(keystores.iter().skip(1).map(|(keystore, _, _)| async move {
                vec![keystore.transaction_history().await.unwrap()]
            }))
            .await;

        fn push_history<L: Ledger>(
            keystore_ix: usize,
            histories: &mut [Vec<Vec<Transaction<L>>>],
            entry: Transaction<L>,
        ) {
            histories[keystore_ix].last_mut().unwrap().push(entry);
        }
        fn close_history_block<L: Ledger>(histories: &mut [Vec<Vec<Transaction<L>>>]) {
            for history in histories {
                history.push(vec![])
            }
        }

        // Define all of the test assets and mint initial records.
        let mut assets = vec![];
        for i in 0..ndefs {
            let name = format!("Asset {}", i);
            assets.push(
                keystores[0]
                    .0
                    .define_asset(name.clone(), name.as_bytes(), Default::default())
                    .await
                    .unwrap(),
            );
        }
        for (asset, owner, amount) in once(init_rec).chain(init_recs) {
            let asset = (asset % (ndefs + 1)) as usize;
            if asset == 0 {
                // can't mint native assets
                continue;
            }
            let minter = keystores[0].1[0].clone().address();
            let pub_key = keystores[(owner % nkeystores) as usize + 1].1[0].clone();
            let address = pub_key.address();
            balances[(owner % nkeystores) as usize][asset] += amount.into();
            let receipt = keystores[0]
                .0
                .mint(
                    Some(&minter),
                    1,
                    &assets[asset - 1].code,
                    amount,
                    pub_key.clone(),
                )
                .await
                .unwrap();
            push_history(
                (owner % nkeystores) as usize,
                &mut histories,
                transactions::create_test_txn(
                    receipt,
                    TransactionParams {
                        timeout: None,
                        status: TransactionStatus::Unknown,
                        signed_memos: None,
                        inputs: Default::default(),
                        outputs: Default::default(),
                        time: Local::now(),
                        asset: assets[asset - 1].code,
                        kind: TransactionKind::<T::Ledger>::mint(),
                        senders: Vec::new(),
                        receivers: vec![(address, amount.into())],
                        fee_change: None,
                        asset_change: None,
                    },
                ),
            );
            t.sync(&ledger, keystores.as_slice()).await;
            close_history_block(&mut histories);
        }

        println!("assets minted: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check initial balances. This cannot be a closure because rust infers the wrong lifetime
        // for the references (it tries to use 'a, which is longer than we want to borrow `keystores`
        // for).
        async fn check_balances<'b, L: Ledger + 'static>(
            keystores: &[(
                Keystore<'b, impl KeystoreBackend<'b, L> + Sync + 'b, L, ()>,
                Vec<UserPubKey>,
                TempDir,
            )],
            balances: &[Vec<U256>],
            assets: &[AssetDefinition],
        ) {
            for (i, balance) in balances.iter().enumerate() {
                let (keystore, pub_keys, _) = &keystores[i + 1];

                // Check native asset balance.
                assert_eq!(
                    keystore
                        .balance_breakdown(&pub_keys[0].address(), &AssetCode::native())
                        .await,
                    balance[0]
                );
                for (j, asset) in assets.iter().enumerate() {
                    assert_eq!(
                        keystore
                            .balance_breakdown(&pub_keys[0].address(), &asset.code)
                            .await,
                        balance[j + 1]
                    );
                }
            }
        }
        check_balances(&keystores, &balances, &assets).await;

        async fn check_histories<'b, L: Ledger + 'static>(
            keystores: &[(
                Keystore<'b, impl KeystoreBackend<'b, L> + Sync + 'b, L, ()>,
                Vec<UserPubKey>,
                TempDir,
            )],
            histories: &[Vec<Vec<Transaction<L>>>],
        ) {
            assert_eq!(keystores.len(), histories.len() + 1);
            for ((keystore, _, _), history) in keystores.iter().skip(1).zip(histories) {
                let mut keystore_history = keystore.transaction_history().await.unwrap();
                assert_eq!(
                    keystore_history.len(),
                    history.iter().map(|block| block.len()).sum::<usize>()
                );

                for block in history {
                    let remaining = keystore_history.split_off(block.len());
                    let keystore_block = keystore_history;
                    keystore_history = remaining;

                    // Compare the blocks, allowing for slight deviations in the timestamps of
                    // corresponding entries. We compare blocks modulo order by checking that they
                    // have the same length and that every entry in one is in the other, and vice
                    // versa.
                    assert_eq!(keystore_block.len(), block.len());
                    let keystore_block = keystore_block
                        .into_iter()
                        .map(|entry| {
                            // Ignore the change information when comparing. It's difficult to
                            // predict what the change should be without knowing exactly which
                            // input records the wallet chooses for the transaction.
                            TxnHistoryWithTimeTolerantEq(entry)
                        })
                        .collect::<Vec<_>>();
                    let block = block
                        .iter()
                        .map(|txn| TxnHistoryWithTimeTolerantEq(txn.clone()))
                        .collect::<Vec<_>>();
                    for txn in keystore_block.iter() {
                        assert!(
                            block.contains(txn),
                            "keystore contains unexpected transaction history:\n  {:?}\nexpected:\n  {:?}",
                            txn,
                            block,
                        );
                    }
                    for txn in block.iter() {
                        assert!(keystore_block.contains(txn));
                    }
                }
            }
        }
        check_histories(&keystores, &histories).await;

        // Run the test transactions.
        for (i, block) in txs.iter().enumerate() {
            println!(
                "Starting block {}/{}: {}s",
                i + 1,
                txs.len(),
                now.elapsed().as_secs_f32()
            );
            now = Instant::now();

            for (j, (asset_ix, sender_ix, receiver_ix, amount)) in block.iter().enumerate() {
                println!(
                    "Starting txn {}.{}/{}:{:?}: {}s",
                    i + 1,
                    j + 1,
                    block.len(),
                    (asset_ix, sender_ix, receiver_ix, amount),
                    now.elapsed().as_secs_f32()
                );

                let asset_ix = (asset_ix % (ndefs + 1)) as usize;
                let sender_ix = (sender_ix % nkeystores) as usize;
                let receiver_ix = (receiver_ix % nkeystores) as usize;
                let native = AssetDefinition::native();
                let asset = if asset_ix == 0 {
                    &native
                } else {
                    &assets[asset_ix - 1]
                };
                let sender_pub_key = keystores[sender_ix + 1].1[0].clone();
                let sender_address = sender_pub_key.address();
                let sender_balance = balances[sender_ix][asset_ix];
                let receiver_pub_key = keystores[receiver_ix + 1].1[0].clone();
                let receiver_address = receiver_pub_key.address();

                let mut amount = if U256::from(*amount) <= sender_balance {
                    *amount
                } else if sender_balance > U256::zero() {
                    // If we don't have enough to make the whole transfer, but we have some,
                    // transfer half of what we have.
                    let new_amount = std::cmp::max(sender_balance / 2, U256::one());
                    println!(
                        "decreasing transfer amount due to insufficient balance: {} -> {}: {}s",
                        *amount,
                        new_amount,
                        now.elapsed().as_secs_f32()
                    );
                    now = Instant::now();
                    new_amount.as_u64()
                } else {
                    // If we don't have any of this asset type, mint more.
                    assert_ne!(asset, &AssetDefinition::native());
                    println!(
                        "minting {} more of asset {:?}: {}s",
                        *amount,
                        &asset.code,
                        now.elapsed().as_secs_f32()
                    );
                    now = Instant::now();
                    let (minter, minter_pub_keys, _) = &mut keystores[0];
                    let receipt = minter
                        .mint(
                            Some(&minter_pub_keys[0].address()),
                            1,
                            &asset.code,
                            2 * amount,
                            sender_pub_key,
                        )
                        .await
                        .unwrap();
                    t.sync(&ledger, keystores.as_slice()).await;
                    balances[sender_ix][asset_ix] += (2 * amount).into();
                    push_history(
                        sender_ix,
                        &mut histories,
                        transactions::create_test_txn(
                            receipt,
                            TransactionParams {
                                timeout: None,
                                status: TransactionStatus::Unknown,
                                signed_memos: None,
                                inputs: Default::default(),
                                outputs: Default::default(),
                                time: Local::now(),
                                asset: asset.code,
                                kind: TransactionKind::<T::Ledger>::mint(),
                                senders: Vec::new(),
                                receivers: vec![(sender_address.clone(), (2 * amount).into())],
                                fee_change: None,
                                asset_change: None,
                            },
                        ),
                    );

                    println!("asset minted: {}s", now.elapsed().as_secs_f32());
                    now = Instant::now();
                    *amount
                };

                ledger.lock().await.hold_next_transaction();
                let sender = &mut keystores[sender_ix + 1].0;
                let receipt = match sender
                    .transfer(
                        Some(&sender_address),
                        &asset.code,
                        &[(receiver_pub_key.clone(), amount)],
                        1,
                    )
                    .await
                {
                    Ok(receipt) => receipt.clone(),
                    Err(KeystoreError::TransactionError {
                        source:
                            TransactionError::Fragmentation {
                                suggested_amount, ..
                            },
                    }) => {
                        // Allow fragmentation. Without merge transactions, there's not much we can
                        // do to prevent it, and merge transactions require multiple transaction
                        // arities, which requires either dummy records or multiple verifier keys in
                        // the validator.
                        if suggested_amount > 0u64.into() {
                            // If the keystore suggested a transaction amount that it _can_ process,
                            // try again with that amount.
                            println!(
                                "decreasing transfer amount due to fragmentation: {} -> {}: {}s",
                                amount,
                                suggested_amount,
                                now.elapsed().as_secs_f32()
                            );
                            now = Instant::now();

                            amount = suggested_amount.as_u64();
                            sender
                                .transfer(
                                    Some(&sender_address),
                                    &asset.code,
                                    &[(receiver_pub_key.clone(), amount)],
                                    1,
                                )
                                .await
                                .unwrap()
                                .clone()
                        } else {
                            println!(
                                "skipping transfer due to fragmentation: {}s",
                                now.elapsed().as_secs_f32()
                            );
                            now = Instant::now();
                            continue;
                        }
                    }
                    Err(KeystoreError::TransactionError {
                        source: TransactionError::InsufficientBalance { .. },
                    }) => {
                        // We should always have enough balance to make the transaction, because we
                        // adjusted the transaction amount (and potentially minted more of the
                        // asset) above, so that the transaction is covered by our most up-to-date
                        // balance.
                        //
                        // If we fail due to insufficient balance, it is likely because a record we
                        // need is on hold as part of a previous transaction, and we haven't gotten
                        // the change yet because the transaction is buffered in a block. The
                        // transaction should succeed after we flush any pending transactions.
                        println!("flushing pending blocks to retrieve change");
                        ledger.lock().await.flush().unwrap();
                        t.sync(&ledger, keystores.as_slice()).await;
                        let sender = &mut keystores[sender_ix + 1].0;
                        sender
                            .transfer(
                                Some(&sender_address),
                                &asset.code,
                                &[(receiver_pub_key.clone(), amount)],
                                1,
                            )
                            .await
                            .unwrap()
                            .clone()
                    }
                    Err(err) => {
                        panic!("transaction failed: {:?}", err)
                    }
                };
                println!(
                    "Generated txn {}.{}/{}: {}s",
                    i + 1,
                    j + 1,
                    block.len(),
                    now.elapsed().as_secs_f32()
                );
                now = Instant::now();

                balances[sender_ix][0] -= U256::one(); // transaction fee
                balances[sender_ix][asset_ix] -= amount.into();
                balances[receiver_ix][asset_ix] += amount.into();

                push_history(
                    sender_ix,
                    &mut histories,
                    transactions::create_test_txn(
                        receipt.clone(),
                        TransactionParams {
                            timeout: None,
                            status: TransactionStatus::Unknown,
                            signed_memos: None,
                            inputs: Default::default(),
                            outputs: Default::default(),
                            time: Local::now(),
                            asset: asset.code,
                            kind: TransactionKind::<T::Ledger>::send(),
                            senders: vec![sender_address],
                            receivers: vec![(receiver_address.clone(), amount.into())],
                            fee_change: None,
                            asset_change: None,
                        },
                    ),
                );
                if receiver_ix != sender_ix {
                    push_history(
                        receiver_ix,
                        &mut histories,
                        transactions::create_test_txn(
                            receipt,
                            TransactionParams {
                                timeout: None,
                                status: TransactionStatus::Unknown,
                                signed_memos: None,
                                inputs: Default::default(),
                                outputs: Default::default(),
                                time: Local::now(),
                                asset: asset.code,
                                kind: TransactionKind::<T::Ledger>::receive(),
                                senders: Vec::new(),
                                receivers: vec![(receiver_address, amount.into())],
                                fee_change: None,
                                asset_change: None,
                            },
                        ),
                    );
                }

                ledger.lock().await.release_held_transaction();
            }

            t.sync(&ledger, keystores.as_slice()).await;
            close_history_block(&mut histories);
            check_balances(&keystores, &balances, &assets).await;
            check_histories(&keystores, &histories).await;

            println!(
                "Finished block {}/{}: {}s",
                i + 1,
                block.len(),
                now.elapsed().as_secs_f32()
            );
        }
    }

    #[async_std::test]
    pub async fn test_multixfr_keystore_simple<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()>
    {
        let alice_grant = (0, 0, 3); // Alice gets 3 of coin 0 to start
        let bob_grant = (1, 1, 3); // Bob gets 3 of coin 1 to start
        let txns = vec![vec![
            (1, 0, 1, 2), // Alice sends 2 of coin 1 to Bob
            (2, 1, 0, 2), // Bob sends 2 of coin 2 to Alice
            (1, 1, 0, 1), // Bob sends 1 of coin 1 to Alice
        ]];
        test_multixfr_keystore::<T>(txns, 2, 2, alice_grant, vec![bob_grant]).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_multixfr_keystore_multi_xfr_block<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        // Alice and Bob each get 1 native token to start.
        let alice_grant = (0, 0, 1);
        let bob_grant = (0, 1, 1);
        // Alice and Bob make independent transactions, so that the transactions can end up in the
        // same block.
        let txns = vec![vec![
            (0, 0, 1, 1), // Alice sends 1 coin to Bob
            (0, 1, 0, 1), // Bob sends 1 coin to Alice
        ]];
        test_multixfr_keystore::<T>(txns, 2, 1, alice_grant, vec![bob_grant]).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_multixfr_keystore_various_kinds<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        let txns = vec![vec![
            (0, 0, 1, 1), // native asset transfer
            (1, 0, 1, 1), // non-native asset transfer with change output
            (1, 0, 1, 2), // non-native asset transfer with exact change
        ]];
        let native_grant = (0, 0, 1);
        let non_native_grant = (1, 0, 3);
        test_multixfr_keystore::<T>(txns, 2, 1, native_grant, vec![non_native_grant]).await;
        Ok(())
    }

    struct MultiXfrParams {
        max_txns: usize,
        max_blocks: usize,
        max_keys: u8,
        max_defs: u8,
        max_amt: u64,
        max_recs: usize,
    }

    impl MultiXfrParams {
        const fn new(txns: usize, max_amt: u64) -> Self {
            // divide txns into 5 blocks
            let max_txns = if txns > 5 { txns / 5 } else { 1 };
            let max_blocks = if txns > 5 { 5 } else { txns };
            // fewer users than txns so we get multiple txns with same key
            let max_keys = (txns / 2 + 2) as u8;
            // fewer defs than txns so we get multiple txns with same def
            let max_defs = (txns / 2 + 1) as u8;
            // enough records to give everyone 1 of each type, on average
            // Reasoning for /4:
            //      E[nkeys] = max_keys/2
            //      E[ndefs] = max_defs/2
            // So
            //      E[nkeys*ndefs] = max_keys*max_defs/4
            let max_recs = max_keys as usize * max_defs as usize / 4;

            MultiXfrParams {
                max_txns,
                max_blocks,
                max_keys,
                max_defs,
                max_amt,
                max_recs,
            }
        }

        fn def(&self) -> impl Strategy<Value = u8> {
            // range is inclusive because def 0 is the native asset, and other asset defs are
            // 1-indexed
            0..=self.max_defs
        }

        fn key(&self) -> impl Strategy<Value = u8> {
            0..self.max_keys
        }

        fn txn_amt(&self) -> impl Strategy<Value = u64> {
            // Transaction amounts are smaller than record amounts because we don't want to burn a
            // whole record in one transaction.
            1..=std::cmp::max(self.max_amt / 5, 2)
        }

        fn amt(&self) -> impl Strategy<Value = u64> {
            1..=self.max_amt
        }

        fn txs(&self) -> impl Strategy<Value = Vec<Vec<(u8, u8, u8, u64)>>> {
            vec(
                vec(
                    (self.def(), self.key(), self.key(), self.txn_amt()),
                    self.max_txns,
                ),
                self.max_blocks,
            )
        }

        fn nkeys(&self) -> impl Strategy<Value = u8> {
            2..=self.max_keys
        }

        fn ndefs(&self) -> impl Strategy<Value = u8> {
            1..=self.max_defs
        }

        fn rec(&self) -> impl Strategy<Value = (u8, u8, u64)> {
            (self.def(), self.key(), self.amt())
        }

        fn recs(&self) -> impl Strategy<Value = Vec<(u8, u8, u64)>> {
            vec(self.rec(), self.max_recs)
        }
    }

    const MULTI_XFR_SMALL: MultiXfrParams = MultiXfrParams::new(5, 1000);
    const MULTI_XFR_LARGE: MultiXfrParams = MultiXfrParams::new(50, 1000);

    #[allow(clippy::type_complexity)]
    fn proptest_multixfr_keystore<'a, T: SystemUnderTest<'a>>(
        (txs, nkeys, ndefs, init_rec, init_recs): (
            Vec<Vec<(u8, u8, u8, u64)>>,
            u8,
            u8,
            (u8, u8, u64),
            Vec<(u8, u8, u64)>,
        ),
    ) -> test_runner::TestCaseResult {
        block_on(test_multixfr_keystore::<T>(
            txs, nkeys, ndefs, init_rec, init_recs,
        ));
        Ok(())
    }

    #[test]
    pub fn proptest_multixfr_keystore_regression1<'a, T: SystemUnderTest<'a>>() {
        // This input caused an assertion failure:
        //  assertion failed: block.contains(txn)
        // when checking that an expected transaction was in a keystore's transaction history in the
        // right place. The transaction which was actually in the history differed from the expected
        // one in that its `receivers` field was empty.
        //
        // The root cause was a `skip(1)` when iterating over the output records when creating the
        // transaction history entry. This was an attempt to skip the fee change record, but the
        // records available at that point were only the records received by the current keystore,
        // which does not necessarily include the fee change. (If the transaction was sent to us
        // from someone else, the first record we received would not be the fee change.)
        //
        // Removing this `skip(1)` fixed the bug, and the logic that skips records whose asset types
        // don't match the asset type of the overall transaction still causes the fee change record
        // to be skipped when present.
        proptest_multixfr_keystore::<T>((
            vec![
                vec![(0, 0, 0, 1)],
                vec![(0, 0, 0, 1)],
                vec![(0, 0, 0, 1)],
                vec![(0, 0, 0, 1)],
                vec![(0, 0, 0, 1)],
            ],
            2,
            1,
            (0, 0, 1),
            vec![(0, 0, 1), (0, 0, 1), (1, 0, 1)],
        ))
        .unwrap();
    }

    #[test]
    pub fn proptest_multixfr_keystore_small<'a, T: SystemUnderTest<'a>>() {
        TestRunner::new(test_runner::Config {
            cases: 1,
            ..test_runner::Config::default()
        })
        .run(
            &(
                MULTI_XFR_SMALL.txs(),
                MULTI_XFR_SMALL.nkeys(),
                MULTI_XFR_SMALL.ndefs(),
                MULTI_XFR_SMALL.rec(),
                MULTI_XFR_SMALL.recs(),
            ),
            proptest_multixfr_keystore::<T>,
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    pub fn proptest_multixfr_keystore_many_small_tests<'a, T: SystemUnderTest<'a>>() {
        TestRunner::new(test_runner::Config {
            cases: 10,
            ..test_runner::Config::default()
        })
        .run(
            &(
                MULTI_XFR_SMALL.txs(),
                MULTI_XFR_SMALL.nkeys(),
                MULTI_XFR_SMALL.ndefs(),
                MULTI_XFR_SMALL.rec(),
                MULTI_XFR_SMALL.recs(),
            ),
            proptest_multixfr_keystore::<T>,
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    pub fn proptest_multixfr_keystore_one_big_test<'a, T: SystemUnderTest<'a>>() {
        TestRunner::new(test_runner::Config {
            cases: 1,
            ..test_runner::Config::default()
        })
        .run(
            &(
                MULTI_XFR_LARGE.txs(),
                MULTI_XFR_LARGE.nkeys(),
                MULTI_XFR_LARGE.ndefs(),
                MULTI_XFR_LARGE.rec(),
                MULTI_XFR_LARGE.recs(),
            ),
            proptest_multixfr_keystore::<T>,
        )
        .unwrap();
    }

    #[async_std::test]
    pub async fn test_generate_user_key<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();
        let (ledger, mut keystores) = t
            .create_test_network(&[(3, 4)], vec![0, 100], &mut now)
            .await;

        // Figure out the next key in `keystores[0]`s deterministic key stream without adding it to
        // the keystore. We will use this to create a record owned by this key, _and then_ generate
        // the key through the keystore's public interface, triggering a background ledger scan which
        // should identify the existing record belonging to the key.
        let key = {
            keystores[0]
                .0
                .write()
                .await
                .update(|KeystoreSharedState { model, .. }| async move {
                    let key = model
                        .stores
                        .meta_store
                        .key_stream()
                        .derive_sub_tree("user".as_bytes())
                        .derive_user_key_pair(&model.stores.sending_accounts.index().to_le_bytes());
                    model.backend.register_user_key(&key).await.unwrap();
                    Ok(key)
                })
                .await
                .unwrap()
        };

        // Transfer a record to `key` before we tell `keystores[0]` to generate the key, so that we
        // can check if the background ledger scan initiated when the keystore generates the key
        // successfully discovers the record.
        let send_pub_key = keystores[1].1[0].clone();
        let send_addr = send_pub_key.address();
        keystores[1]
            .0
            .transfer(
                Some(&send_addr),
                &AssetCode::native(),
                &[(key.pub_key(), 1)],
                1,
            )
            .await
            .unwrap();
        t.sync(&ledger, keystores.as_slice()).await;
        // The receiving keystore doesn't initially get the new balance, because it hasn't added the
        // key yet.
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&key.address(), &AssetCode::native())
                .await,
            0u64.into()
        );

        // Generate a lot of events to slow down the key scan.
        for _ in 0..10 {
            keystores[1]
                .0
                .transfer(
                    Some(&send_addr),
                    &AssetCode::native(),
                    &[(send_pub_key.clone(), 1)],
                    1,
                )
                .await
                .unwrap();
            t.sync(&ledger, keystores.as_slice()).await;
        }

        // Pre-compute a transaction to release after the key scan starts, so that the Merkle root
        // when the key scan ends will be different from when it started, and we can check if it
        // updates its Merkle paths correctly.
        {
            let mut ledger = ledger.lock().await;
            ledger.set_block_size(1).unwrap();
            ledger.hold_next_transaction();
        }
        keystores[1]
            .0
            .transfer(
                Some(&send_addr),
                &AssetCode::native(),
                &[(send_pub_key.clone(), 1)],
                1,
            )
            .await
            .unwrap();

        // Now add the key and start a scan from event 0.
        assert_eq!(
            key.pub_key(),
            keystores[0]
                .0
                .generate_sending_account("sending_key".into(), Some(Default::default()))
                .await
                .unwrap()
        );

        // Immediately change the Merkle root.
        {
            ledger.lock().await.release_held_transaction();
        }
        t.sync(&ledger, &keystores).await;

        // Check that the scan is persisted, so it would restart if the keystore crashed.
        t.check_storage(&keystores).await;

        // Check that the scan discovered the existing record.
        keystores[0]
            .0
            .await_sending_key_scan(&key.address())
            .await
            .unwrap();
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&key.address(), &AssetCode::native())
                .await,
            1u64.into()
        );

        // Now check that the regular event handling loop discovers records owned by this key going
        // forwards.
        keystores[1]
            .0
            .transfer(
                Some(&send_addr),
                &AssetCode::native(),
                &[(key.pub_key(), 1)],
                1,
            )
            .await
            .unwrap();
        t.sync(&ledger, keystores.as_slice()).await;
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&key.address(), &AssetCode::native())
                .await,
            2u64.into()
        );
    }

    #[async_std::test]
    pub async fn test_create_with_existing_ledger<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut rng = ChaChaRng::from_seed([127u8; 32]);

        // Initialize a ledger and keystore, and get the owner address.
        let mut now = Instant::now();
        let initial_grant = 10;
        let (ledger, mut keystores) = t
            .create_test_network(&[(2, 2)], vec![initial_grant * 2], &mut now)
            .await;
        ledger.lock().await.set_block_size(1).unwrap();

        let (mut keystore1, pub_keys1, _tmp_dir) = keystores.remove(0);
        let receipt = keystore1
            .transfer(
                Some(&pub_keys1[0].address()),
                &AssetCode::native(),
                &[(pub_keys1[0].clone(), 1)],
                1,
            )
            .await
            .unwrap()
            .clone();
        await_transaction(&receipt, &keystore1, &[]).await;
        assert_eq!(
            keystore1
                .balance_breakdown(&pub_keys1[0].address(), &AssetCode::native())
                .await,
            (initial_grant - 1).into()
        );

        // A new keystore joins the system after there are already some transactions on the ledger.
        let (mut keystore2, _tmp_dir2) = t
            .create_keystore(KeyTree::random(&mut rng).0, &ledger)
            .await;
        keystore2.sync(ledger.lock().await.now()).await.unwrap();
        let pub_key2 = keystore2
            .generate_sending_account("sending_key".into(), None)
            .await
            .unwrap();

        // Transfer to the late keystore.
        let receipt = keystore1
            .transfer(
                Some(&pub_keys1[0].address()),
                &AssetCode::native(),
                &[(pub_key2.clone(), 2)],
                1,
            )
            .await
            .unwrap()
            .clone();
        await_transaction(&receipt, &keystore1, &[&keystore2]).await;
        assert_eq!(
            keystore1
                .balance_breakdown(&pub_keys1[0].address(), &AssetCode::native())
                .await,
            (initial_grant - 4).into()
        );
        assert_eq!(
            keystore2
                .balance_breakdown(&pub_key2.address(), &AssetCode::native())
                .await,
            2u64.into()
        );

        // Transfer back.
        let receipt = keystore2
            .transfer(
                Some(&pub_key2.address()),
                &AssetCode::native(),
                &[(pub_keys1[0].clone(), 1)],
                1,
            )
            .await
            .unwrap()
            .clone();
        await_transaction(&receipt, &keystore2, &[&keystore1]).await;
        assert_eq!(
            keystore1
                .balance_breakdown(&pub_keys1[0].address(), &AssetCode::native())
                .await,
            (initial_grant - 3).into()
        );
        assert_eq!(
            keystore2
                .balance_breakdown(&pub_key2.address(), &AssetCode::native())
                .await,
            0u64.into()
        );
    }

    #[async_std::test]
    pub async fn test_aggregate_addresses<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();

        // One more input and one more output than we will ever need, to test dummy records.
        let num_inputs = 3;
        let num_outputs = 4;

        // Give Alice and Bob some initial grants.
        let alice_grant = 21;
        let bob_grant = 10;
        let (ledger, mut keystores) = t
            .create_test_network(
                &[(num_inputs, num_outputs)],
                vec![alice_grant, bob_grant],
                &mut now,
            )
            .await;
        let alice_pub_keys = keystores[0].1.clone();
        let alice_addresses = alice_pub_keys
            .clone()
            .into_iter()
            .map(|pub_key| pub_key.address())
            .collect::<Vec<_>>();
        let bob_pub_keys = keystores[1].1.clone();
        let bob_addresses = bob_pub_keys
            .clone()
            .into_iter()
            .map(|pub_key| pub_key.address())
            .collect::<Vec<_>>();

        // Verify initial keystore state.
        assert_eq!(
            keystores[0].0.balance(&AssetCode::native()).await,
            alice_grant.into()
        );
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&alice_addresses[0], &AssetCode::native())
                .await,
            (alice_grant / 2).into()
        );
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&alice_addresses[1], &AssetCode::native())
                .await,
            (alice_grant - alice_grant / 2).into()
        );
        assert_eq!(
            keystores[1].0.balance(&AssetCode::native()).await,
            bob_grant.into()
        );
        assert_eq!(
            keystores[1].0.balance(&AssetCode::native()).await,
            bob_grant.into()
        );
        assert_eq!(
            keystores[1]
                .0
                .balance_breakdown(&bob_addresses[0], &AssetCode::native())
                .await,
            (bob_grant / 2).into()
        );
        assert_eq!(
            keystores[1]
                .0
                .balance_breakdown(&bob_addresses[1], &AssetCode::native())
                .await,
            (bob_grant - bob_grant / 2).into()
        );

        // Alice defines a coin and gives her first address some initial grant.
        let coin = keystores[0]
            .0
            .define_asset(
                "Alice".into(),
                "Alice's asset".as_bytes(),
                Default::default(),
            )
            .await
            .unwrap();
        let amount = 10;
        keystores[0]
            .0
            .mint(
                Some(&alice_addresses[0]),
                1,
                &coin.code,
                amount,
                alice_pub_keys[0].clone(),
            )
            .await
            .unwrap();
        t.sync(&ledger, keystores.as_slice()).await;
        println!("Asset minted: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Verify the aggragated balance and the balance in each address of Alice.
        assert_eq!(keystores[0].0.balance(&coin.code).await, amount.into());
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&alice_addresses[0], &coin.code)
                .await,
            amount.into()
        );
        assert_eq!(
            keystores[0]
                .0
                .balance_breakdown(&alice_addresses[1], &coin.code)
                .await,
            0u64.into()
        );

        // Transferring from Alice's second address to Bob should fail due to insufficient
        // balance.
        let transfer_amount = 3;
        let fee = 1;
        match keystores[0]
            .0
            .transfer(
                Some(&alice_addresses[1]),
                &coin.code,
                &[(bob_pub_keys[0].clone(), transfer_amount)],
                fee,
            )
            .await
        {
            Err(KeystoreError::TransactionError {
                source: TransactionError::InsufficientBalance { .. },
            }) => {}
            ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
        }

        // Transferring from Alice's first address to Bob should succeed.
        keystores[0]
            .0
            .transfer(
                Some(&alice_addresses[0]),
                &coin.code,
                &[(bob_pub_keys[0].clone(), transfer_amount)],
                fee,
            )
            .await
            .unwrap();
        t.sync(&ledger, keystores.as_slice()).await;
        println!(
            "Transfer generated from a specified address: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();

        // Transferring from Alice to Bob without specifying Alice's address should also succeed.
        keystores[0]
            .0
            .transfer(
                None,
                &coin.code,
                &[(bob_pub_keys[0].clone(), transfer_amount)],
                fee,
            )
            .await
            .unwrap();
        t.sync(&ledger, keystores.as_slice()).await;
        println!(
            "Transfer generated without a specified address: {}s",
            now.elapsed().as_secs_f32()
        );

        // Verify the balances of the native and defined coins.
        assert_eq!(
            keystores[0].0.balance(&AssetCode::native()).await,
            (alice_grant - fee * 3).into()
        );
        assert_eq!(
            keystores[0].0.balance(&coin.code).await,
            (amount - transfer_amount * 2).into()
        );
        assert_eq!(
            keystores[1].0.balance(&AssetCode::native()).await,
            bob_grant.into()
        );
        assert_eq!(
            keystores[1].0.balance(&coin.code).await,
            (transfer_amount * 2).into()
        );
    }

    #[async_std::test]
    pub async fn test_asset_library<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();
        let initial_grant = 10;
        let (ledger, mut keystores) = t
            .create_test_network(&[(2, 2)], vec![initial_grant, initial_grant], &mut now)
            .await;

        // Test various ways of discovering assets. We will have keystores[0] discover assets by
        //  * defining one itself
        //  * receiving one from keystores[1]
        //  * importing one
        // All of these asset types should end up in the asset library, as well as the native asset
        // type which should always be present. The defined asset should also appear in the
        // viewable subset if we use the right viewer key, which we will define now:
        let viewing_key0 = keystores[0]
            .0
            .generate_viewing_account("viewing_key".into(), Some(EventIndex::default()))
            .await
            .unwrap();

        // Define an asset.
        let defined_asset = keystores[0]
            .0
            .define_asset(
                "defined_asset".into(),
                "defined_asset description".as_bytes(),
                AssetPolicy::default().set_viewer_pub_key(viewing_key0),
            )
            .await
            .unwrap();

        // Receive an asset. keystores[1] will define a new asset type (viewable by itself) and then
        // mint some to keystores[0].
        let viewing_key1 = keystores[1]
            .0
            .generate_viewing_account("viewing_key".into(), Some(EventIndex::default()))
            .await
            .unwrap();
        let minted_asset = keystores[1]
            .0
            .define_asset(
                "minted_asset".into(),
                "minted_asset description".as_bytes(),
                AssetPolicy::default().set_viewer_pub_key(viewing_key1),
            )
            .await
            .unwrap();
        let minter_addr = keystores[1].1[0].clone().address();
        let receiver_addr = keystores[0].1[0].clone();
        keystores[1]
            .0
            .mint(Some(&minter_addr), 1, &minted_asset.code, 1, receiver_addr)
            .await
            .unwrap();
        t.sync(&ledger, &keystores).await;

        // Import an asset (we'll use `keystores[1]` to define it).
        let imported_asset = keystores[1]
            .0
            .define_asset(
                "imported_asset".into(),
                "imported_asset description".as_bytes(),
                AssetPolicy::default(),
            )
            .await
            .unwrap();
        keystores[0]
            .0
            .create_asset(imported_asset.clone(), None, None, None, None)
            .await
            .unwrap();

        // Now check that all expected asset types appear in keystores[0]'s asset library.
        let get_asset = |code| {
            let keystore = &keystores[0].0;
            async move {
                let asset = keystore.asset(code).await.unwrap();
                assert!(keystore.assets().await.contains(&asset));
                asset
            }
        };
        assert_eq!(
            get_asset(defined_asset.code).await.definition(),
            &defined_asset
        );
        assert!(get_asset(defined_asset.code).await.mint_info().is_some());
        assert_eq!(
            get_asset(defined_asset.code).await.name.unwrap(),
            "defined_asset"
        );
        assert_eq!(
            get_asset(defined_asset.code).await.description.unwrap(),
            "defined_asset description"
        );
        assert!(!get_asset(defined_asset.code).await.verified());
        assert_eq!(get_asset(minted_asset.code).await.name, None);
        assert_eq!(get_asset(minted_asset.code).await.description, None);
        assert!(!get_asset(minted_asset.code).await.verified());
        assert_eq!(get_asset(imported_asset.code).await.name, None);
        assert_eq!(get_asset(imported_asset.code).await.description, None);
        assert!(!get_asset(imported_asset.code).await.verified());
    }

    #[async_std::test]
    pub async fn test_verified_assets<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut rng = ChaChaRng::from_seed([37; 32]);
        let mut now = Instant::now();
        let initial_grant = 10;
        let (_ledger, mut keystores) = t
            .create_test_network(&[(2, 2)], vec![initial_grant], &mut now)
            .await;

        // Discover a non-verified asset so we can later test verifying a non-verified asset.
        let asset1 = keystores[0]
            .0
            .define_asset("asset1".into(), &[], AssetPolicy::default())
            .await
            .unwrap();
        {
            let asset1_info = keystores[0].0.asset(asset1.code).await.unwrap();
            assert!(!asset1_info.verified());
        }

        // Now created a verified asset library with 2 assets:
        // * one that will update `asset1` to be marked verified
        // * one that does not yet exist in the keystore (later we will import it to check updating
        //   verified assets with new information)
        let key_pair = KeyPair::generate(&mut rng);
        let (asset2, mint_info2) = {
            let (code, seed) = AssetCode::random(&mut rng);
            let definition = AssetDefinition::new(code, AssetPolicy::default()).unwrap();
            (
                definition,
                MintInfo {
                    seed,
                    description: vec![],
                },
            )
        };
        let verified_assets = VerifiedAssetLibrary::new(
            vec![asset1.clone().into(), asset2.clone().into()],
            &key_pair,
        );
        let imposter_assets =
            VerifiedAssetLibrary::new(vec![asset2.clone().into()], &KeyPair::generate(&mut rng));

        // Import the verified asset library and check that the two expected assets are returned.
        let imported = keystores[0]
            .0
            .verify_assets(key_pair.ver_key_ref(), verified_assets)
            .await
            .unwrap();
        assert_eq!(imported, vec![asset1.clone(), asset2.clone()]);

        // Check that importing an asset library signed by an imposter fails.
        assert!(matches!(
            keystores[0]
                .0
                .verify_assets(key_pair.ver_key_ref(), imposter_assets)
                .await,
            Err(KeystoreError::AssetVerificationError)
        ));

        // Check that `asset1` got updated, retaining its mint info but attaining verified status.
        {
            let asset1_info = keystores[0].0.asset(asset1.code).await.unwrap();
            assert!(asset1_info.verified());
            assert_eq!(asset1_info.definition(), &asset1);
            assert!(asset1_info.mint_info().is_some());
        }

        // Check that `asset2`, which was not present before, got imported as-is.

        let asset2_info = keystores[0].0.asset(asset2.code).await.unwrap();
        assert_eq!(asset2_info.definition(), &asset2);
        assert_eq!(asset2_info.mint_info(), None);
        assert!(asset2_info.verified());
        let created_time = asset2_info.created_time();
        let modified_time = asset2_info.modified_time();
        assert!(modified_time >= created_time);

        // Now import `asset2`, updating the existing verified asset with mint info.
        keystores[0]
            .0
            .insert_asset(Asset::from(
                asset2.clone(),
                None,
                None,
                None,
                Some(mint_info2.clone()),
                true,
            ))
            .await
            .unwrap();
        let asset2_info = keystores[0].0.asset(asset2.code).await.unwrap();
        assert_eq!(asset2_info.mint_info(), Some(mint_info2.clone()));
        assert!(asset2_info.verified());
        assert_eq!(asset2_info.created_time(), created_time);
        assert!(asset2_info.modified_time() > modified_time);
    }

    #[async_std::test]
    pub async fn test_accounts<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();
        let (ledger, mut keystores) = t
            .create_test_network(&[(2, 2)], vec![10, 0], &mut now)
            .await;
        ledger.lock().await.set_block_size(1).unwrap();
        t.check_storage(&keystores).await;

        // The default accounts have no name and a balance of the native assets.
        for pub_key in &keystores[0].1 {
            let address = pub_key.address();
            let account = keystores[0].0.sending_account(&address).await.unwrap();
            assert!(account.used());
            assert_eq!(account.pub_key(), address);
            assert_eq!(account.description, "");
        }

        // Create a named sending account with no balance.
        let sending_key = keystores[0]
            .0
            .generate_sending_account("sending_account".into(), None)
            .await
            .unwrap();
        let pub_key = sending_key;
        let address = pub_key.address();
        let sending_account = keystores[0].0.sending_account(&address).await.unwrap();
        assert_eq!(sending_account.pub_key(), address);
        assert_eq!(sending_account.description(), "sending_account".to_string());
        assert!(!sending_account.used());
        assert_eq!(sending_account.scan(), None);
        t.check_storage(&keystores).await;

        // Transfer to the new account, make sure it gets marked used and gets the new balance,
        // records, and assets.
        let receipt = keystores[0]
            .0
            .transfer(None, &AssetCode::native(), &[(pub_key.clone(), 2i32)], 1i32)
            .await
            .unwrap();
        await_transaction(&receipt, &keystores[0].0, &[]).await;
        {
            let account = keystores[0].0.sending_account(&address).await.unwrap();
            assert!(account.used());
        }
        t.check_storage(&keystores).await;

        // Create empty viewing and freezing accounts.
        let viewing_key = keystores[0]
            .0
            .generate_viewing_account("viewing_account".into(), Some(EventIndex::default()))
            .await
            .unwrap();
        let freezing_key = keystores[0]
            .0
            .generate_freezing_account("freezing_account".into(), Some(EventIndex::default()))
            .await
            .unwrap();
        let viewing_account = keystores[0].0.viewing_account(&viewing_key).await.unwrap();
        assert_eq!(viewing_account.pub_key(), viewing_key);
        assert_eq!(viewing_account.description(), "viewing_account".to_string());
        assert!(!viewing_account.used());
        assert!(viewing_account.scan().is_some());
        let freezing_account = keystores[0]
            .0
            .freezing_account(&freezing_key)
            .await
            .unwrap();
        assert_eq!(freezing_account.pub_key(), freezing_key);
        assert_eq!(
            freezing_account.description(),
            "freezing_account".to_string()
        );
        assert!(!freezing_account.used());
        assert!(freezing_account.scan().is_some());
        t.check_storage(&keystores).await;

        // Generate one asset that is just viewable and one that is both viewable and freezable.
        let viewable_asset = keystores[0]
            .0
            .define_asset(
                "asset1".into(),
                "asset1".as_bytes(),
                AssetPolicy::default()
                    .set_viewer_pub_key(viewing_key.clone())
                    .reveal_amount()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(keystores[0]
            .0
            .viewing_account(&viewing_key)
            .await
            .unwrap()
            .used());
        assert!(!keystores[0]
            .0
            .freezing_account(&freezing_key)
            .await
            .unwrap()
            .used());
        let freezable_asset = keystores[0]
            .0
            .define_asset(
                "asset2".into(),
                "asset2".as_bytes(),
                AssetPolicy::default()
                    .set_viewer_pub_key(viewing_key.clone())
                    .set_freezer_pub_key(freezing_key.clone())
                    .reveal_record_opening()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(keystores[0]
            .0
            .viewing_account(&viewing_key)
            .await
            .unwrap()
            .used());
        assert!(keystores[0]
            .0
            .freezing_account(&freezing_key)
            .await
            .unwrap()
            .used());

        // Mint some of each asset for the other keystore (`keystores[1]`). Check that the freezable
        // record is added to both accounts.
        let receiver = keystores[1].1[0].clone();
        let receipt = keystores[0]
            .0
            .mint(
                Some(&address),
                1i32,
                &viewable_asset.code,
                100i32,
                receiver.clone(),
            )
            .await
            .unwrap();
        await_transaction(&receipt, &keystores[0].0, &[&keystores[1].0]).await;
        t.check_storage(&keystores).await;

        // Mint the freezable asset.
        let receipt = keystores[0]
            .0
            .mint(
                Some(&address),
                1i32,
                &freezable_asset.code,
                200i32,
                receiver,
            )
            .await
            .unwrap();
        await_transaction(&receipt, &keystores[0].0, &[&keystores[1].0]).await;
        t.check_storage(&keystores).await;
    }

    #[async_std::test]
    pub async fn test_update_asset<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut rng = ChaChaRng::from_seed([4; 32]);
        let mut now = Instant::now();
        let (_ledger, mut keystores) = t.create_test_network(&[(2, 2)], vec![0], &mut now).await;

        // Case 1: update user-defined asset with user-defined asset.
        let asset1 = keystores[0]
            .0
            .define_asset(
                "asset1_orig".into(),
                "asset1_orig description".as_bytes(),
                AssetPolicy::default(),
            )
            .await
            .unwrap();
        keystores[0]
            .0
            .insert_asset(Asset::from(
                asset1.clone(),
                Some("asset1".into()),
                Some("asset1 description".into()),
                None,
                None,
                false,
            ))
            .await
            .unwrap();
        let info = keystores[0].0.asset(asset1.code).await.unwrap();
        assert_eq!(info.name, Some("asset1".into()));
        assert_eq!(info.description, Some("asset1 description".into()));
        t.check_storage(&keystores).await;

        // Create verified asset library containing one user-defined asset and one other asset.
        let key_pair = KeyPair::generate(&mut rng);
        let asset2 = {
            let (code, _) = AssetCode::random(&mut rng);
            AssetDefinition::new(code, AssetPolicy::default()).unwrap()
        };
        let verified_asset1 = Asset::from(
            asset1.clone(),
            Some("asset1_verified".into()),
            Some("asset1_verified description".into()),
            None,
            None,
            true,
        );
        let verified_asset2 = Asset::from(
            asset2.clone(),
            Some("asset2_verified".into()),
            Some("asset2_verified description".into()),
            None,
            None,
            true,
        );
        let verified_assets =
            VerifiedAssetLibrary::new(vec![verified_asset1, verified_asset2], &key_pair);

        // Case 2: update user-defined asset with verified asset.
        keystores[0]
            .0
            .verify_assets(&key_pair.ver_key(), verified_assets)
            .await
            .unwrap();
        let info = keystores[0].0.asset(asset1.code).await.unwrap();
        assert_eq!(info.name, Some("asset1_verified".into()));
        assert_eq!(info.description, Some("asset1_verified description".into()));
        t.check_storage(&keystores).await;

        // Case 3: update verified asset with user-defined asset.
        keystores[0]
            .0
            .import_asset(Asset::from(
                asset2.clone(),
                Some("asset2_fake".into()),
                Some("asset2_fake description".into()),
                None,
                None,
                false,
            ))
            .await
            .unwrap();
        let info = keystores[0].0.asset(asset2.code).await.unwrap();
        assert_eq!(info.name, Some("asset2_verified".into()));
        assert_eq!(info.description, Some("asset2_verified description".into()));
        t.check_storage(&keystores).await;

        // Case 4: update verified asset with verified asset.
        let verified_assets = VerifiedAssetLibrary::new(
            vec![Asset::from(
                asset2.clone(),
                Some("asset2_verified_new".into()),
                Some("asset2_verified_new description".into()),
                None,
                None,
                true,
            )],
            &key_pair,
        );
        keystores[0]
            .0
            .verify_assets(&key_pair.ver_key(), verified_assets)
            .await
            .unwrap();
        let info = keystores[0].0.asset(asset2.code).await.unwrap();
        assert_eq!(info.name, Some("asset2_verified_new".into()));
        assert_eq!(
            info.description,
            Some("asset2_verified_new description".into())
        );
        t.check_storage(&keystores).await;
    }

    #[async_std::test]
    pub async fn test_asset_icon<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();
        let (_, mut keystores) = t.create_test_network(&[(2, 2)], vec![0], &mut now).await;

        let jpeg_bytes = include_bytes!("icons/espresso.jpeg");
        let icon = Icon::load_jpeg(Cursor::new(jpeg_bytes)).unwrap();
        // Check that the icon is not the expected size, so we can check the resizing behavior.
        assert_ne!(icon.size(), (64, 64));

        keystores[0]
            .0
            .insert_asset(Asset::from(
                AssetDefinition::native(),
                None,
                None,
                Some(icon),
                None,
                false,
            ))
            .await
            .unwrap();
        let icon = keystores[0]
            .0
            .asset(AssetCode::native())
            .await
            .unwrap()
            .icon
            .unwrap();
        assert_eq!(icon.size(), (64, 64));

        // Test format conversion.
        let dir = TempDir::new("icon_test").unwrap();
        let path = &[dir.path(), Path::new("espresso_resized.png")]
            .iter()
            .collect::<PathBuf>();
        icon.write_png(File::create(path).unwrap()).unwrap();
        let loaded = Icon::load_png(BufReader::new(File::open(path).unwrap())).unwrap();
        assert_eq!(loaded, icon);
    }

    #[async_std::test]
    pub async fn test_txn_history<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();
        let (ledger, mut keystores) = t.create_test_network(&[(2, 2)], vec![4, 0], &mut now).await;
        {
            let mut ledger = ledger.lock().await;
            ledger.set_block_size(1).unwrap();
            // Hold the transfer so we can observe the pending transaction history entry.
            ledger.hold_next_transaction();
        }

        // Submit a transaction.
        let src = keystores[0].1[0].clone().address();
        let dst_pub_key = keystores[1].1[0].clone();
        let dst = dst_pub_key.address();
        let receipt = keystores[0]
            .0
            .transfer(Some(&src), &AssetCode::native(), &[(dst_pub_key, 1)], 1)
            .await
            .unwrap();

        // The history entry should be added immediately.
        let expected_entry = TxnHistoryWithTimeTolerantEq(transactions::create_test_txn(
            receipt.clone(),
            TransactionParams {
                timeout: None,
                status: TransactionStatus::Unknown,
                signed_memos: None,
                inputs: Default::default(),
                outputs: Default::default(),
                time: Local::now(),
                asset: AssetCode::native(),
                kind: TransactionKind::<T::Ledger>::send(),
                senders: vec![src.clone()],
                receivers: vec![(dst.clone(), 1.into())],
                fee_change: Some(1.into()),
                asset_change: Some(0.into()),
            },
        ));
        let entry = keystores[0]
            .0
            .transaction_history()
            .await
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert_eq!(TxnHistoryWithTimeTolerantEq(entry.clone()), expected_entry);

        // The status of the entry should be pending.
        assert_eq!(
            keystores[0]
                .0
                .transaction_status(entry.uid())
                .await
                .unwrap(),
            TransactionStatus::Pending
        );

        // Release the transfer so it can finalize.
        ledger.lock().await.release_held_transaction();
        await_transaction(&receipt, &keystores[0].0, &[&keystores[1].0]).await;

        // The receiver should have a new entry.
        let expected_entry = TxnHistoryWithTimeTolerantEq(transactions::create_test_txn(
            receipt.clone(),
            TransactionParams {
                timeout: None,
                status: TransactionStatus::Unknown,
                signed_memos: None,
                inputs: Default::default(),
                outputs: Default::default(),
                time: Local::now(),
                asset: AssetCode::native(),
                kind: TransactionKind::<T::Ledger>::receive(),
                senders: vec![],
                receivers: vec![(dst.clone(), 1.into())],
                fee_change: None,
                asset_change: None,
            },
        ));
        assert_eq!(
            TxnHistoryWithTimeTolerantEq(
                keystores[1]
                    .0
                    .transaction_history()
                    .await
                    .unwrap()
                    .last()
                    .unwrap()
                    .clone()
            ),
            expected_entry
        );

        // The sender's entry should be unchanged...
        // It is wrong becuase the status is different
        assert!(same_txn_history(
            &entry,
            &keystores[0]
                .0
                .transaction_history()
                .await
                .unwrap()
                .last()
                .unwrap()
                .clone()
        ));
        // ...but the status should be finalized.
        assert_eq!(
            keystores[0]
                .0
                .transaction_status(entry.uid())
                .await
                .unwrap(),
            TransactionStatus::Retired
        );
    }

    // Regression test for a bug where submitting an empty block would sometimes cause the event
    // handling thread to panic.
    #[async_std::test]
    pub async fn test_empty_block_after_record_to_forget<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();
        let (ledger, mut keystores) = t.create_test_network(&[(2, 2)], vec![3, 0], &mut now).await;
        ledger.lock().await.set_block_size(1).unwrap();

        let pub_key0 = keystores[0].1[0].clone();
        let pub_key1 = keystores[1].1[0].clone();

        // Transfer from keystore 0 to keystore 1, creating a last Merkle leaf that keystore 0 wants
        // to forget.
        keystores[0]
            .0
            .transfer(None, &AssetCode::native(), &[(pub_key1, 2)], 1)
            .await
            .unwrap();
        t.sync(&ledger, &keystores).await;
        assert_eq!(
            keystores[0].0.balance(&AssetCode::native()).await,
            0u64.into()
        );
        assert_eq!(
            keystores[1].0.balance(&AssetCode::native()).await,
            2u64.into()
        );

        // Submit an empty block.
        {
            let mut ledger = ledger.lock().await;
            let block = ledger.network().state().next_block();
            ledger.network().submit(block).unwrap();
        }
        t.sync(&ledger, &keystores).await;

        // Submit a non-empty block after the empty one. If we don't do this, the background scan
        // (see below) can "cheat" by terminating before it processes the empty block event, since
        // at that point its Merkle root would be equivalent to the overall Merkle root.
        keystores[1]
            .0
            .transfer(None, &AssetCode::native(), &[(pub_key0, 1)], 1)
            .await
            .unwrap();
        t.sync(&ledger, &keystores).await;
        assert_eq!(
            keystores[0].0.balance(&AssetCode::native()).await,
            1u64.into()
        );
        assert_eq!(
            keystores[1].0.balance(&AssetCode::native()).await,
            0u64.into()
        );

        // Add a new key to an existing keystore, causing it to process the events (including the
        // empty block) on the background scan code path.
        let pub_key = keystores[0]
            .0
            .generate_sending_account("key".into(), Some(EventIndex::default()))
            .await
            .unwrap();
        keystores[0]
            .0
            .await_sending_key_scan(&pub_key.address())
            .await
            .unwrap();
    }

    #[async_std::test]
    pub async fn test_big_amount<'a, T: SystemUnderTest<'a>>() {
        let max_record = 2u128.pow(127) - 1;
        let max_record_times_2 =
            U256::from_dec_str("340282366920938463463374607431768211454").unwrap();
        let max_record_times_3 =
            U256::from_dec_str("510423550381407695195061911147652317181").unwrap();

        let mut t = T::default();
        let mut now = Instant::now();
        let (ledger, mut keystores) = t.create_test_network(&[(4, 4)], vec![8, 0], &mut now).await;
        ledger.lock().await.set_block_size(1).unwrap();

        let pub_key0 = keystores[0].1[0].clone();
        let addr0 = pub_key0.address();
        let pub_key1 = keystores[1].1[0].clone();

        // Define a mintable asset type.
        let asset = keystores[0]
            .0
            .define_asset("my_asset".into(), &[], AssetPolicy::default())
            .await
            .unwrap();

        // Mint the maximum single-record amount, thrice (which will cause a total amount which
        // exceeds both the max single-record amount and the max of a u128).
        keystores[0]
            .0
            .mint(Some(&addr0), 1, &asset.code, max_record, pub_key0.clone())
            .await
            .unwrap();
        t.sync(&ledger, &keystores).await;
        keystores[0]
            .0
            .mint(Some(&addr0), 1, &asset.code, max_record, pub_key0.clone())
            .await
            .unwrap();
        t.sync(&ledger, &keystores).await;
        keystores[0]
            .0
            .mint(Some(&addr0), 1, &asset.code, max_record, pub_key0.clone())
            .await
            .unwrap();
        t.sync(&ledger, &keystores).await;

        // Check that the total balance is aggregated without overflowing.
        assert_eq!(
            keystores[0].0.balance(&asset.code).await,
            max_record_times_3
        );

        // Check that we can do a transfer whose total amount exceeds the maximum record amount, as
        // long as the amount of each input and output record is acceptable. There is an additional
        // constraint in Jellyfish that the total input amount of a transaction (including the fee!)
        // can be represented as a u128. In our case, we can use 2 of our max_record inputs (which
        // sums to 2(2^127 - 1) = 2^128 - 2) and our last remaining native asset record of amount 1
        // for the fee, giving a total of 2^128 - 1. We just need to make sure we use the account
        // with a native record of amount 1 to pay the fee, not the secondary account which still
        // has its initial native record of amount 4.
        keystores[0]
            .0
            .transfer(
                Some(&addr0),
                &asset.code,
                &[
                    (pub_key1.clone(), max_record),
                    (pub_key1.clone(), max_record),
                ],
                1,
            )
            .await
            .unwrap();
        t.sync(&ledger, &keystores).await;
        assert_eq!(
            keystores[0].0.balance(&asset.code).await,
            U256::from(max_record)
        );
        assert_eq!(
            keystores[1].0.balance(&asset.code).await,
            max_record_times_2
        );
    }

    #[async_std::test]
    pub async fn test_zero_fee<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();
        let mut rng = ChaChaRng::from_seed([118; 32]);
        let (ledger, mut keystores) = t.create_test_network(&[(4, 4)], vec![2], &mut now).await;
        ledger.lock().await.set_block_size(1).unwrap();

        // Allocating a zero fee is tricky if the keystore has one account with 0 native tokens and
        // one account with nonzero -- since the first account technically has enough balance to pay
        // the fee, but it doesn't actually have any records. This was once a bug that caused a
        // panic. To test with these conditions, we will create a fresh keystore with two accounts,
        // and fund only the second one.
        let (mut sender, _tmp_dir) = t
            .create_keystore(KeyTree::random(&mut rng).0, &ledger)
            .await;
        sender
            .generate_sending_account("account0".into(), None)
            .await
            .unwrap();
        sender
            .generate_sending_account("account1".into(), None)
            .await
            .unwrap();
        let addresses = sender.sending_addresses().await;

        // Fund the second account.
        let txn = keystores[0]
            .0
            .transfer(
                None,
                &AssetCode::native(),
                &[(
                    sender
                        .sending_account(&addresses[1])
                        .await
                        .unwrap()
                        .key()
                        .pub_key()
                        .clone(),
                    1,
                )],
                0,
            )
            .await
            .unwrap();
        await_transaction(&txn, &keystores[0].0, &[&sender]).await;
        assert_eq!(
            sender
                .balance_breakdown(&addresses[0], &AssetCode::native())
                .await,
            0u64.into()
        );
        assert_eq!(
            sender
                .balance_breakdown(&addresses[1], &AssetCode::native())
                .await,
            1u64.into()
        );

        // Mint a non-native asset which we can transfer, to test the path where fees and transfer
        // inputs are allocated separately.
        let asset = sender
            .define_asset("asset".into(), &[], AssetPolicy::default())
            .await
            .unwrap();
        let txn = sender
            .mint(
                None,
                0,
                &asset.code,
                1,
                sender
                    .sending_account(&addresses[0])
                    .await
                    .unwrap()
                    .key()
                    .pub_key()
                    .clone(),
            )
            .await
            .unwrap();
        await_transaction(&txn, &sender, &[]).await;
        assert_eq!(sender.balance(&asset.code).await, 1u64.into());

        // Now do a non-native transfer with a 0 fee.
        let txn = sender
            .transfer(None, &asset.code, &[(keystores[0].1[0].clone(), 1)], 0)
            .await
            .unwrap();
        await_transaction(&txn, &sender, &[&keystores[0].0]).await;
        assert_eq!(sender.balance(&AssetCode::native()).await, 1u64.into());
        assert_eq!(sender.balance(&asset.code).await, 0u64.into());
        assert_eq!(keystores[0].0.balance(&asset.code).await, 1u64.into());
    }
}
