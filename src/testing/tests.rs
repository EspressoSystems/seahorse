// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::*;
use chrono::Duration;
use espresso_macros::generic_tests;

#[derive(Clone, Debug)]
pub struct TxnHistoryWithTimeTolerantEq<L: Ledger>(pub TransactionHistoryEntry<L>);

impl<L: Ledger> PartialEq<Self> for TxnHistoryWithTimeTolerantEq<L> {
    fn eq(&self, other: &Self) -> bool {
        let time_tolerance = Duration::minutes(5);
        let times_eq = if self.0.time < other.0.time {
            other.0.time - self.0.time < time_tolerance
        } else {
            self.0.time - other.0.time < time_tolerance
        };
        times_eq
            && self.0.asset == other.0.asset
            && self.0.kind == other.0.kind
            && self.0.receivers == other.0.receivers
            && self.0.receipt == other.0.receipt
    }
}

#[generic_tests]
pub mod generic_wallet_tests {
    use super::*;
    use async_std::task::block_on;
    use proptest::{collection::vec, strategy::Strategy, test_runner, test_runner::TestRunner};
    use std::iter::once;

    /*
     * Test idea: simulate two wallets transferring funds back and forth. After initial
     * setup, the wallets only receive publicly visible information (e.g. block commitment
     * events and receiver memos posted on bulletin boards). Check that both wallets are
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
     *   wallets by the test)
     */
    #[allow(unused_assignments)]
    async fn test_two_wallets<'a, T: SystemUnderTest<'a>>(native: bool) {
        let mut t = T::default();
        let mut now = Instant::now();

        // One more input and one more output than we will ever need, to test dummy records.
        let num_inputs = 3;
        let num_outputs = 4;

        // Give Alice an initial grant of 5 native coins. If using non-native transfers, give Bob an
        // initial grant with which to pay his transaction fee, since he will not be receiving any
        // native coins from Alice.
        let alice_grant = 5;
        let bob_grant = if native { 0 } else { 1 };
        let (ledger, mut wallets) = t
            .create_test_network(
                &[(num_inputs, num_outputs)],
                vec![alice_grant, bob_grant],
                false,
                &mut now,
            )
            .await;
        let alice_address = wallets[0].1[0].clone();
        let bob_address = wallets[1].1[0].clone();

        // Verify initial wallet state.
        assert_ne!(alice_address, bob_address);
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&alice_address, &AssetCode::native())
                .await,
            alice_grant
        );
        assert_eq!(
            wallets[1]
                .0
                .balance_breakdown(&bob_address, &AssetCode::native())
                .await,
            bob_grant
        );

        let coin = if native {
            AssetDefinition::native()
        } else {
            let coin = wallets[0]
                .0
                .define_asset("Alice's asset".as_bytes(), Default::default())
                .await
                .unwrap();
            // Alice gives herself an initial grant of 5 coins.
            wallets[0]
                .0
                .mint(&alice_address, 1, &coin.code, 5, alice_address.clone())
                .await
                .unwrap();
            t.sync(&ledger, wallets.as_slice()).await;
            println!("Asset minted: {}s", now.elapsed().as_secs_f32());
            now = Instant::now();

            assert_eq!(
                wallets[0]
                    .0
                    .balance_breakdown(&alice_address, &coin.code)
                    .await,
                5
            );
            assert_eq!(
                wallets[1]
                    .0
                    .balance_breakdown(&bob_address, &coin.code)
                    .await,
                0
            );

            coin
        };

        let alice_initial_native_balance = wallets[0]
            .0
            .balance_breakdown(&alice_address, &AssetCode::native())
            .await;
        let bob_initial_native_balance = wallets[1]
            .0
            .balance_breakdown(&bob_address, &AssetCode::native())
            .await;

        // Construct a transaction to transfer some coins from Alice to Bob.
        wallets[0]
            .0
            .transfer(
                Some(&alice_address),
                &coin.code,
                &[(bob_address.clone(), 3)],
                1,
            )
            .await
            .unwrap();
        t.sync(&ledger, wallets.as_slice()).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that both wallets reflect the new balances (less any fees). This cannot be a
        // closure because rust infers the wrong lifetime for the references (it tries to use 'a,
        // which is longer than we want to borrow `wallets` for).
        async fn check_balance<'b, L: 'static + Ledger>(
            wallet: &(
                Wallet<'b, impl WalletBackend<'b, L> + Sync + 'b, L>,
                Vec<UserAddress>,
            ),
            expected_coin_balance: u64,
            starting_native_balance: u64,
            fees_paid: u64,
            coin: &AssetDefinition,
            native: bool,
        ) {
            if native {
                assert_eq!(
                    wallet.0.balance_breakdown(&wallet.1[0], &coin.code).await,
                    expected_coin_balance - fees_paid
                );
            } else {
                assert_eq!(
                    wallet.0.balance_breakdown(&wallet.1[0], &coin.code).await,
                    expected_coin_balance
                );
                assert_eq!(
                    wallet
                        .0
                        .balance_breakdown(&wallet.1[0], &AssetCode::native())
                        .await,
                    starting_native_balance - fees_paid
                );
            }
        }
        check_balance(
            &wallets[0],
            2,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        )
        .await;
        check_balance(&wallets[1], 3, bob_initial_native_balance, 0, &coin, native).await;

        // Check that Bob's wallet has sufficient information to access received funds by
        // transferring some back to Alice.
        //
        // This transaction should also result in a non-zero fee change record being
        // transferred back to Bob, since Bob's only sufficient record has an amount of 3 coins, but
        // the sum of the outputs and fee of this transaction is only 2.
        wallets[1]
            .0
            .transfer(Some(&bob_address), &coin.code, &[(alice_address, 1)], 1)
            .await
            .unwrap();
        t.sync(&ledger, wallets.as_slice()).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        check_balance(
            &wallets[0],
            3,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        )
        .await;
        check_balance(&wallets[1], 2, bob_initial_native_balance, 1, &coin, native).await;
    }

    #[async_std::test]
    pub async fn test_two_wallets_native<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()> {
        test_two_wallets::<T>(true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_two_wallets_non_native<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()> {
        test_two_wallets::<T>(false).await;
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
    async fn test_wallet_rejected<'a, T: SystemUnderTest<'a>>(
        native: bool,
        mint: bool,
        freeze: bool,
        timeout: bool,
    ) {
        let mut t = T::default();

        assert!(!(native && mint));
        assert!(!(native && freeze));
        assert!(!(mint && freeze));

        let mut now = Instant::now();

        // Native transfers have extra fee/change inputs/outputs.
        let num_inputs = if native { 1 } else { 2 };
        let num_outputs = if native { 2 } else { 3 };

        // The sender wallet (wallets[0]) gets an initial grant of 2 for a transaction fee and a
        // payment (or, for non-native transfers, a transaction fee and a mint fee). wallets[1] will
        // act as the receiver, and wallets[2] will be a third party which generates
        // RECORD_HOLD_TIME transfers while a transfer from wallets[0] is pending, causing the
        // transfer to time out.
        let (ledger, mut wallets) = t
            .create_test_network(
                &[(num_inputs, num_outputs)],
                // If native, wallets[0] gets 1 coin to transfer and 1 for a transaction fee. Otherwise,
                // it gets
                //  * 1 transaction fee
                //  * 1 mint fee for its initial non-native record, if the test itself is not minting
                //    that record
                //  * 1 mint fee for wallets[2]'s initial non-native record in the timeout test.
                vec![
                    if native {
                        2
                    } else {
                        1 + !mint as u64 + timeout as u64
                    },
                    0,
                    2 * T::Ledger::record_root_history() as u64,
                ],
                false,
                &mut now,
            )
            .await;

        let asset = if native {
            AssetDefinition::native()
        } else {
            let mut rng = ChaChaRng::from_seed([42u8; 32]);
            let audit_key = AuditorKeyPair::generate(&mut rng);
            let freeze_key = FreezerKeyPair::generate(&mut rng);
            let policy = AssetPolicy::default()
                .set_auditor_pub_key(audit_key.pub_key())
                .set_freezer_pub_key(freeze_key.pub_key())
                .reveal_record_opening()
                .unwrap();
            wallets[0].0.add_audit_key(audit_key).await.unwrap();
            wallets[0].0.add_freeze_key(freeze_key).await.unwrap();
            let asset = wallets[0]
                .0
                .define_asset("test asset".as_bytes(), policy)
                .await
                .unwrap();

            if !mint {
                // If we're freezing, the transaction is essentially taking balance away from
                // wallets[1], so wallets[1] gets 1 coin to start with. Otherwise, the transaction
                // is transferring balance from wallets[0] to wallets[1], so  wallets[0] gets 1
                // coin. We only need this if the test itself is not minting the asset later on.
                let dst = if freeze {
                    wallets[1].1[0].clone()
                } else {
                    wallets[0].1[0].clone()
                };
                let src = wallets[0].1[0].clone();
                wallets[0]
                    .0
                    .mint(&src, 1, &asset.code, 1, dst)
                    .await
                    .unwrap();
                t.sync(&ledger, wallets.as_slice()).await;
            }

            if timeout {
                // If doing a timeout test, wallets[2] (the sender that will generate enough
                // transactions to cause wallets[0]'s transaction to timeout) gets RECORD_HOLD_TIME
                // coins.
                let src = wallets[0].1[0].clone();
                let dst = wallets[2].1[0].clone();
                wallets[0]
                    .0
                    .mint(
                        &src,
                        1,
                        &asset.code,
                        T::Ledger::record_root_history() as u64,
                        dst,
                    )
                    .await
                    .unwrap();
                t.sync(&ledger, wallets.as_slice()).await;
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
        let receiver = wallets[1].1[0].clone();
        let sender = wallets[0].1[0].clone();
        if mint {
            wallets[0]
                .0
                .mint(&sender, 1, &asset.code, 1, receiver.clone())
                .await
                .unwrap();
        } else if freeze {
            wallets[0]
                .0
                .freeze(&sender, 1, &asset.code, 1, receiver.clone())
                .await
                .unwrap();
        } else {
            wallets[0]
                .0
                .transfer(Some(&sender), &asset.code, &[(receiver.clone(), 1)], 1)
                .await
                .unwrap();
        }
        println!("transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that the sender's balance is on hold (for the fee and the payment).
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&wallets[0].1[0], &AssetCode::native())
                .await,
            0
        );
        if !freeze {
            assert_eq!(
                wallets[0]
                    .0
                    .balance_breakdown(&wallets[0].1[0], &asset.code)
                    .await,
                0
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
                    wallets[0]
                        .0
                        .balance_breakdown(&wallets[0].1[0], &AssetCode::native())
                        .await,
                    0
                );
                if !freeze {
                    assert_eq!(
                        wallets[0]
                            .0
                            .balance_breakdown(&wallets[0].1[0], &asset.code)
                            .await,
                        0
                    );
                }

                let sender = wallets[2].1[0].clone();
                wallets[2]
                    .0
                    .transfer(Some(&sender), &asset.code, &[(receiver.clone(), 1)], 1)
                    .await
                    .unwrap();
                t.sync(&ledger, wallets.as_slice()).await;
            }
        } else {
            {
                let mut ledger = ledger.lock().await;

                // Change the validator state, so that the wallet's transaction (built against the
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

            t.sync(&ledger, wallets.as_slice()).await;
        }

        // Check that the sender got their balance back.
        if native {
            assert_eq!(
                wallets[0]
                    .0
                    .balance_breakdown(&wallets[0].1[0], &AssetCode::native())
                    .await,
                2
            );
        } else {
            assert_eq!(
                wallets[0]
                    .0
                    .balance_breakdown(&wallets[0].1[0], &AssetCode::native())
                    .await,
                1
            );
            if !(mint || freeze) {
                // in the mint and freeze cases, we never had a non-native balance to start with
                assert_eq!(
                    wallets[0]
                        .0
                        .balance_breakdown(&wallets[0].1[0], &asset.code)
                        .await,
                    1
                );
            }
        }
        assert_eq!(
            wallets[1]
                .0
                .balance_breakdown(&wallets[1].1[0], &asset.code)
                .await,
            (if timeout {
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
            wallets[0]
                .0
                .mint(&sender, 1, &asset.code, 1, receiver)
                .await
                .unwrap();
        } else if freeze {
            wallets[0]
                .0
                .freeze(&sender, 1, &asset.code, 1, receiver)
                .await
                .unwrap();
        } else {
            wallets[0]
                .0
                .transfer(Some(&sender), &asset.code, &[(receiver, 1)], 1)
                .await
                .unwrap();
        }
        t.sync(&ledger, wallets.as_slice()).await;
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&wallets[0].1[0], &AssetCode::native())
                .await,
            0
        );
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&wallets[0].1[0], &asset.code)
                .await,
            0
        );
        assert_eq!(
            wallets[1]
                .0
                .balance_breakdown(&wallets[1].1[0], &asset.code)
                .await,
            (if timeout {
                T::Ledger::record_root_history() as u64
            } else {
                0
            }) + (if freeze { 0 } else { 1 })
        );
    }

    #[async_std::test]
    pub async fn test_wallet_rejected_native_xfr_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(true, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_wallet_rejected_native_xfr_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(true, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_wallet_rejected_non_native_xfr_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_wallet_rejected_non_native_xfr_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_wallet_rejected_non_native_mint_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, true, false, false).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_wallet_rejected_non_native_mint_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, true, false, true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_wallet_rejected_non_native_freeze_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, false, true, false).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_wallet_rejected_non_native_freeze_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, false, true, true).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_wallet_freeze<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()> {
        let mut t = T::default();
        let mut now = Instant::now();

        // The sender wallet (wallets[0]) gets an initial grant of 1 for a transfer fee. wallets[1]
        // will act as the receiver, and wallets[2] will be a third party which creates and freezes
        // some of wallets[0]'s assets. It gets a grant of 3, for a mint fee, a freeze fee and an
        // unfreeze fee.
        //
        // Note that the transfer proving key size (3, 4) used here is chosen to be 1 larger than
        // necessary in both inputs and outputs, to test dummy records.
        let (ledger, mut wallets) = t
            .create_test_network(&[(3, 4)], vec![1, 0, 3], false, &mut now)
            .await;

        let asset = {
            let mut rng = ChaChaRng::from_seed([42u8; 32]);
            let audit_key = AuditorKeyPair::generate(&mut rng);
            let freeze_key = FreezerKeyPair::generate(&mut rng);
            let policy = AssetPolicy::default()
                .set_auditor_pub_key(audit_key.pub_key())
                .set_freezer_pub_key(freeze_key.pub_key())
                .reveal_record_opening()
                .unwrap();
            wallets[2].0.add_audit_key(audit_key).await.unwrap();
            wallets[2].0.add_freeze_key(freeze_key).await.unwrap();
            let asset = wallets[2]
                .0
                .define_asset("test asset".as_bytes(), policy)
                .await
                .unwrap();

            // wallets[0] gets 1 coin to transfer to wallets[1].
            let src = wallets[2].1[0].clone();
            let dst = wallets[0].1[0].clone();
            wallets[2]
                .0
                .mint(&src, 1, &asset.code, 1, dst)
                .await
                .unwrap();
            t.sync(&ledger, wallets.as_slice()).await;

            asset
        };
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&wallets[0].1[0], &asset.code)
                .await,
            1
        );
        assert_eq!(
            wallets[0]
                .0
                .frozen_balance(&wallets[0].1[0], &asset.code)
                .await,
            0
        );

        // Now freeze wallets[0]'s record.
        println!(
            "generating a freeze transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        let src = wallets[2].1[0].clone();
        let dst = wallets[0].1[0].clone();
        ledger.lock().await.hold_next_transaction();
        wallets[2]
            .0
            .freeze(&src, 1, &asset.code, 1, dst.clone())
            .await
            .unwrap();

        // Check that, like transfer inputs, freeze inputs are placed on hold and unusable while a
        // freeze that uses them is pending.
        match wallets[2].0.freeze(&src, 1, &asset.code, 1, dst).await {
            Err(WalletError::TransactionError {
                source: TransactionError::InsufficientBalance { .. },
            }) => {}
            ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
        }

        // Now go ahead with the original freeze.
        ledger.lock().await.release_held_transaction();
        t.sync(&ledger, wallets.as_slice()).await;
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&wallets[0].1[0], &asset.code)
                .await,
            0
        );
        assert_eq!(
            wallets[0]
                .0
                .frozen_balance(&wallets[0].1[0], &asset.code)
                .await,
            1
        );

        // Check that trying to transfer fails due to frozen balance.
        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();
        let src = wallets[0].1[0].clone();
        let dst = wallets[1].1[0].clone();
        match wallets[0]
            .0
            .transfer(Some(&src), &asset.code, &[(dst, 1)], 1)
            .await
        {
            Err(WalletError::TransactionError {
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
        let src = wallets[2].1[0].clone();
        let dst = wallets[0].1[0].clone();
        wallets[2]
            .0
            .unfreeze(&src, 1, &asset.code, 1, dst)
            .await
            .unwrap();
        t.sync(&ledger, wallets.as_slice()).await;
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&wallets[0].1[0], &asset.code)
                .await,
            1
        );
        assert_eq!(
            wallets[0]
                .0
                .frozen_balance(&wallets[0].1[0], &asset.code)
                .await,
            0
        );

        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        let src = wallets[0].1[0].clone();
        let dst = wallets[1].1[0].clone();
        let xfr_receipt = wallets[0]
            .0
            .transfer(Some(&src), &asset.code, &[(dst, 1)], 1)
            .await
            .unwrap()
            .clone();
        t.sync(&ledger, wallets.as_slice()).await;
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&wallets[0].1[0], &asset.code)
                .await,
            0
        );
        assert_eq!(
            wallets[0]
                .0
                .frozen_balance(&wallets[0].1[0], &asset.code)
                .await,
            0
        );
        assert_eq!(
            wallets[1]
                .0
                .balance_breakdown(&wallets[1].1[0], &asset.code)
                .await,
            1
        );

        // Check that the history properly accounts for freezes and unfreezes.
        let expected_history = vec![
            TransactionHistoryEntry {
                time: Local::now(),
                asset: asset.code,
                kind: TransactionKind::<T::Ledger>::mint(),
                senders: Vec::new(),
                receivers: vec![(wallets[0].1[0].clone(), 1)],
                receipt: None,
            },
            TransactionHistoryEntry {
                time: Local::now(),
                asset: asset.code,
                kind: TransactionKind::<T::Ledger>::freeze(),
                senders: Vec::new(),
                receivers: vec![(wallets[0].1[0].clone(), 1)],
                receipt: None,
            },
            TransactionHistoryEntry {
                time: Local::now(),
                asset: asset.code,
                kind: TransactionKind::<T::Ledger>::unfreeze(),
                senders: Vec::new(),
                receivers: vec![(wallets[0].1[0].clone(), 1)],
                receipt: None,
            },
            TransactionHistoryEntry {
                time: Local::now(),
                asset: asset.code,
                kind: TransactionKind::<T::Ledger>::send(),
                senders: wallets[0].1.clone(),
                receivers: vec![(wallets[1].1[0].clone(), 1)],
                receipt: Some(xfr_receipt),
            },
        ]
        .into_iter()
        .map(TxnHistoryWithTimeTolerantEq)
        .collect::<Vec<_>>();
        let actual_history = wallets[0]
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
     * This test is very similar to test_two_wallets, but it is parameterized on the number of users,
     * number of asset types, initial ledger state, and transactions to do, so it can be used with
     * quickcheck or proptest to do randomized fuzzing.
     */
    #[allow(clippy::type_complexity)]
    async fn test_multixfr_wallet<'a, T: SystemUnderTest<'a>>(
        // List of blocks containing (def,key1,key2,amount) transfer specs
        // An asset def of 0 in a transfer spec or record indicates the native asset type; other
        // asset types are indexed startin from 1.
        txs: Vec<Vec<(u8, u8, u8, u64)>>,
        nkeys: u8,
        ndefs: u8,
        // (def,key,amount)
        init_rec: (u8, u8, u64),
        init_recs: Vec<(u8, u8, u64)>,
    ) {
        let mut t = T::default();

        println!(
            "multixfr_wallet test: {} users, {} assets, {} records, {} transfers",
            nkeys,
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
        let mut balances = vec![vec![0; ndefs as usize + 1]; nkeys as usize];
        // `histories` is a map from wallet indices to vectors of blocks of history entries. The
        // reason for blocking the history entries is that entries corresponding to transactions
        // that were validated in the same block can be recorded by the wallets in any order.
        let mut histories = vec![vec![vec![]]; nkeys as usize];
        let grants =
            // The minter (wallet 0) gets 1 coin per initial record, to pay transaction fees while
            // it mints and distributes the records, and 1 coin per transaction, to pay transaction
            // fees while minting additional records if test wallets run out of balance during the
            // test.
            once((1 + init_recs.len() + txs.iter().flatten().count()) as u64).chain(
                (0..nkeys)
                    .map(|i| {
                        // The remaining wallets (the test wallets) get 1 coin for each transaction
                        // in which they are the sender, to pay transaction fees, plus...
                        let txn_fees = txs.iter()
                            .flatten()
                            .map(|(_, sender, _, _)| {
                                if sender % nkeys == i {1} else {0}
                            })
                            .sum::<u64>();
                        balances[i as usize][0] += txn_fees;
                        txn_fees +
                        // ...one record for each native asset type initial record that they own,
                        // plus...
                        once(&init_rec).chain(&init_recs)
                            .map(|(def, owner, amount)| {
                                let def = (def % (ndefs + 1)) as usize;
                                let owner = (owner % nkeys) as usize;
                                if def == 0 && owner == (i as usize) {
                                    balances[owner][def] += amount;
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
                        // that one of the wallets is low on balance. So we give each wallet an
                        // extra grant of native coins large enough to cover all the native
                        // transactions it will need to make, when combined with its original grant
                        // of native coins.
                        {
                            let total_txn_amount: u64 = txs.iter()
                                .flatten()
                                .map(|(def, sender, _, amount)| {
                                    if (def % (ndefs + 1)) == 0 && (sender % nkeys) == i {
                                        *amount
                                    } else {
                                        0
                                    }
                                })
                                .sum();
                            if txn_fees + total_txn_amount > balances[i as usize][0] {
                                let extra = txn_fees + total_txn_amount - balances[i as usize][0];
                                balances[i as usize][0] += extra;
                                extra
                            } else {
                                0
                            }
                        }
                    })
            ).collect();

        let (ledger, mut wallets) = t
            .create_test_network(xfr_sizes, grants, false, &mut now)
            .await;
        println!(
            "ceremony complete, minting initial records: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();

        fn push_history<L: Ledger>(
            wallet_ix: usize,
            histories: &mut [Vec<Vec<TransactionHistoryEntry<L>>>],
            entry: TransactionHistoryEntry<L>,
        ) {
            histories[wallet_ix].last_mut().unwrap().push(entry);
        }
        fn close_history_block<L: Ledger>(histories: &mut [Vec<Vec<TransactionHistoryEntry<L>>>]) {
            for history in histories {
                history.push(vec![])
            }
        }

        // Define all of the test assets and mint initial records.
        let mut assets = vec![];
        for i in 0..ndefs {
            assets.push(
                wallets[0]
                    .0
                    .define_asset(format!("Asset {}", i).as_bytes(), Default::default())
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
            let minter = wallets[0].1[0].clone();
            let address = wallets[(owner % nkeys) as usize + 1].1[0].clone();
            balances[(owner % nkeys) as usize][asset] += amount;
            wallets[0]
                .0
                .mint(&minter, 1, &assets[asset - 1].code, amount, address.clone())
                .await
                .unwrap();
            push_history(
                (owner % nkeys) as usize,
                &mut histories,
                TransactionHistoryEntry {
                    time: Local::now(),
                    asset: assets[asset - 1].code,
                    kind: TransactionKind::<T::Ledger>::mint(),
                    senders: Vec::new(),
                    receivers: vec![(address, amount)],
                    receipt: None,
                },
            );
            t.sync(&ledger, wallets.as_slice()).await;
            close_history_block(&mut histories);
        }

        println!("assets minted: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check initial balances. This cannot be a closure because rust infers the wrong lifetime
        // for the references (it tries to use 'a, which is longer than we want to borrow `wallets`
        // for).
        async fn check_balances<'b, L: Ledger + 'static>(
            wallets: &[(
                Wallet<'b, impl WalletBackend<'b, L> + Sync + 'b, L>,
                Vec<UserAddress>,
            )],
            balances: &[Vec<u64>],
            assets: &[AssetDefinition],
        ) {
            for (i, balance) in balances.iter().enumerate() {
                let (wallet, addresses) = &wallets[i + 1];

                // Check native asset balance.
                assert_eq!(
                    wallet
                        .balance_breakdown(&addresses[0], &AssetCode::native())
                        .await,
                    balance[0]
                );
                for (j, asset) in assets.iter().enumerate() {
                    assert_eq!(
                        wallet.balance_breakdown(&addresses[0], &asset.code).await,
                        balance[j + 1]
                    );
                }
            }
        }
        check_balances(&wallets, &balances, &assets).await;

        async fn check_histories<'b, L: Ledger + 'static>(
            wallets: &[(
                Wallet<'b, impl WalletBackend<'b, L> + Sync + 'b, L>,
                Vec<UserAddress>,
            )],
            histories: &[Vec<Vec<TransactionHistoryEntry<L>>>],
        ) {
            assert_eq!(wallets.len(), histories.len() + 1);
            for ((wallet, _), history) in wallets.iter().skip(1).zip(histories) {
                let mut wallet_history = wallet.transaction_history().await.unwrap();
                assert_eq!(
                    wallet_history.len(),
                    history.iter().map(|block| block.len()).sum::<usize>()
                );

                for block in history {
                    let remaining = wallet_history.split_off(block.len());
                    let wallet_block = wallet_history;
                    wallet_history = remaining;

                    // Compare the blocks, allowing for slight deviations in the timestamps of
                    // corresponding entries. We compare blocks modulo order by checking that they
                    // have the same length and that every entry in one is in the other, and vice
                    // versa.
                    assert_eq!(wallet_block.len(), block.len());
                    let wallet_block = wallet_block
                        .into_iter()
                        .map(TxnHistoryWithTimeTolerantEq)
                        .collect::<Vec<_>>();
                    let block = block
                        .iter()
                        .map(|txn| TxnHistoryWithTimeTolerantEq(txn.clone()))
                        .collect::<Vec<_>>();
                    for txn in wallet_block.iter() {
                        assert!(block.contains(txn));
                    }
                    for txn in block.iter() {
                        assert!(wallet_block.contains(txn));
                    }
                }
            }
        }
        check_histories(&wallets, &histories).await;

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
                let sender_ix = (sender_ix % nkeys) as usize;
                let receiver_ix = (receiver_ix % nkeys) as usize;
                let native = AssetDefinition::native();
                let asset = if asset_ix == 0 {
                    &native
                } else {
                    &assets[asset_ix - 1]
                };
                let receiver = wallets[receiver_ix + 1].1[0].clone();
                let sender_address = wallets[sender_ix + 1].1[0].clone();
                let sender_balance = balances[sender_ix][asset_ix];

                let mut amount = if *amount <= sender_balance {
                    *amount
                } else if sender_balance > 0 {
                    // If we don't have enough to make the whole transfer, but we have some,
                    // transfer half of what we have.
                    let new_amount = std::cmp::max(sender_balance / 2, 1);
                    println!(
                        "decreasing transfer amount due to insufficient balance: {} -> {}: {}s",
                        *amount,
                        new_amount,
                        now.elapsed().as_secs_f32()
                    );
                    now = Instant::now();
                    new_amount
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
                    let (minter, minter_addresses) = &mut wallets[0];
                    minter
                        .mint(
                            &minter_addresses[0],
                            1,
                            &asset.code,
                            2 * amount,
                            sender_address.clone(),
                        )
                        .await
                        .unwrap();
                    t.sync(&ledger, wallets.as_slice()).await;
                    balances[sender_ix][asset_ix] += 2 * amount;
                    push_history(
                        sender_ix,
                        &mut histories,
                        TransactionHistoryEntry {
                            time: Local::now(),
                            asset: asset.code,
                            kind: TransactionKind::<T::Ledger>::mint(),
                            senders: Vec::new(),
                            receivers: vec![(sender_address.clone(), 2 * amount)],
                            receipt: None,
                        },
                    );

                    println!("asset minted: {}s", now.elapsed().as_secs_f32());
                    now = Instant::now();
                    *amount
                };

                ledger.lock().await.hold_next_transaction();
                let sender = &mut wallets[sender_ix + 1].0;
                let receipt = match sender
                    .transfer(
                        Some(&sender_address),
                        &asset.code,
                        &[(receiver.clone(), amount)],
                        1,
                    )
                    .await
                {
                    Ok(receipt) => receipt.clone(),
                    Err(WalletError::TransactionError {
                        source:
                            TransactionError::Fragmentation {
                                suggested_amount, ..
                            },
                    }) => {
                        // Allow fragmentation. Without merge transactions, there's not much we can
                        // do to prevent it, and merge transactions require multiple transaction
                        // arities, which requires either dummy records or multiple verifier keys in
                        // the validator.
                        if suggested_amount > 0 {
                            // If the wallet suggested a transaction amount that it _can_ process,
                            // try again with that amount.
                            println!(
                                "decreasing transfer amount due to fragmentation: {} -> {}: {}s",
                                amount,
                                suggested_amount,
                                now.elapsed().as_secs_f32()
                            );
                            now = Instant::now();

                            amount = suggested_amount;
                            sender
                                .transfer(
                                    Some(&sender_address),
                                    &asset.code,
                                    &[(receiver.clone(), amount)],
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
                    Err(WalletError::TransactionError {
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
                        t.sync(&ledger, wallets.as_slice()).await;
                        let sender = &mut wallets[sender_ix + 1].0;
                        sender
                            .transfer(
                                Some(&sender_address),
                                &asset.code,
                                &[(receiver.clone(), amount)],
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

                balances[sender_ix][0] -= 1; // transaction fee
                balances[sender_ix][asset_ix] -= amount;
                balances[receiver_ix][asset_ix] += amount;

                push_history(
                    sender_ix,
                    &mut histories,
                    TransactionHistoryEntry {
                        time: Local::now(),
                        asset: asset.code,
                        kind: TransactionKind::<T::Ledger>::send(),
                        senders: vec![sender_address],
                        receivers: vec![(receiver.clone(), amount)],
                        receipt: Some(receipt),
                    },
                );
                if receiver_ix != sender_ix {
                    push_history(
                        receiver_ix,
                        &mut histories,
                        TransactionHistoryEntry {
                            time: Local::now(),
                            asset: asset.code,
                            kind: TransactionKind::<T::Ledger>::receive(),
                            senders: Vec::new(),
                            receivers: vec![(receiver, amount)],
                            receipt: None,
                        },
                    );
                }

                ledger.lock().await.release_held_transaction();
            }

            t.sync(&ledger, wallets.as_slice()).await;
            close_history_block(&mut histories);
            check_balances(&wallets, &balances, &assets).await;
            check_histories(&wallets, &histories).await;

            println!(
                "Finished block {}/{}: {}s",
                i + 1,
                block.len(),
                now.elapsed().as_secs_f32()
            );
        }
    }

    #[async_std::test]
    pub async fn test_multixfr_wallet_simple<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()> {
        let alice_grant = (0, 0, 3); // Alice gets 3 of coin 0 to start
        let bob_grant = (1, 1, 3); // Bob gets 3 of coin 1 to start
        let txns = vec![vec![
            (1, 0, 1, 2), // Alice sends 2 of coin 1 to Bob
            (2, 1, 0, 2), // Bob sends 2 of coin 2 to Alice
            (1, 1, 0, 1), // Bob sends 1 of coin 1 to Alice
        ]];
        test_multixfr_wallet::<T>(txns, 2, 2, alice_grant, vec![bob_grant]).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_multixfr_wallet_multi_xfr_block<'a, T: SystemUnderTest<'a>>(
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
        test_multixfr_wallet::<T>(txns, 2, 1, alice_grant, vec![bob_grant]).await;
        Ok(())
    }

    #[async_std::test]
    pub async fn test_multixfr_wallet_various_kinds<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        let txns = vec![vec![
            (0, 0, 1, 1), // native asset transfer
            (1, 0, 1, 1), // non-native asset transfer with change output
            (1, 0, 1, 2), // non-native asset transfer with exact change
        ]];
        let native_grant = (0, 0, 1);
        let non_native_grant = (1, 0, 3);
        test_multixfr_wallet::<T>(txns, 2, 1, native_grant, vec![non_native_grant]).await;
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
    fn proptest_multixfr_wallet<'a, T: SystemUnderTest<'a>>(
        (txs, nkeys, ndefs, init_rec, init_recs): (
            Vec<Vec<(u8, u8, u8, u64)>>,
            u8,
            u8,
            (u8, u8, u64),
            Vec<(u8, u8, u64)>,
        ),
    ) -> test_runner::TestCaseResult {
        block_on(test_multixfr_wallet::<T>(
            txs, nkeys, ndefs, init_rec, init_recs,
        ));
        Ok(())
    }

    #[test]
    pub fn proptest_multixfr_wallet_small<'a, T: SystemUnderTest<'a>>() {
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
            proptest_multixfr_wallet::<T>,
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    pub fn proptest_multixfr_wallet_many_small_tests<'a, T: SystemUnderTest<'a>>() {
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
            proptest_multixfr_wallet::<T>,
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    pub fn proptest_multixfr_wallet_one_big_test<'a, T: SystemUnderTest<'a>>() {
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
            proptest_multixfr_wallet::<T>,
        )
        .unwrap();
    }

    #[async_std::test]
    pub async fn test_generate_user_key<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();
        let (ledger, mut wallets) = t
            .create_test_network(&[(3, 4)], vec![0, 4], false, &mut now)
            .await;

        // Figure out the next key in `wallets[0]`s deterministic key stream without adding it to
        // the wallet. We will use this to create a record owned by this key, _and then_ generate
        // the key through the wallet's public interface, triggering a background ledger scan which
        // should identify the existing record belonging to the key.
        let key = {
            let WalletSharedState { state, session, .. } = &mut *wallets[0].0.lock().await;
            let key = session
                .backend
                .key_stream()
                .derive_sub_tree("user".as_bytes())
                .derive_user_key_pair(&state.key_state.user.to_le_bytes());
            session.backend.register_user_key(&key).await.unwrap();
            key
        };

        // Transfer a record to `key` before we tell `wallets[0]` to generate the key, so that we
        // can check if the background ledger scan initiated when the wallet generates the key
        // successfully discovers the record.
        let send_addr = wallets[1].1[0].clone();
        wallets[1]
            .0
            .transfer(
                Some(&send_addr),
                &AssetCode::native(),
                &[(key.address(), 1)],
                1,
            )
            .await
            .unwrap();
        t.sync(&ledger, wallets.as_slice()).await;
        // The receiving wallet doesn't initially get the new balance, because it hasn't added the
        // key yet.
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&key.address(), &AssetCode::native())
                .await,
            0
        );

        // Now add the key and check that the scan discovers the existing record.
        assert_eq!(
            key.pub_key(),
            wallets[0]
                .0
                .generate_user_key(Some(Default::default()))
                .await
                .unwrap()
        );
        t.check_storage(&ledger, &wallets).await;
        wallets[0].0.await_key_scan(&key.address()).await.unwrap();
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&key.address(), &AssetCode::native())
                .await,
            1
        );

        // Now check that the regular event handling loop discovers records owned by this key going
        //forwards.
        wallets[1]
            .0
            .transfer(
                Some(&send_addr),
                &AssetCode::native(),
                &[(key.address(), 1)],
                1,
            )
            .await
            .unwrap();
        t.sync(&ledger, wallets.as_slice()).await;
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&key.address(), &AssetCode::native())
                .await,
            2
        );
    }

    #[async_std::test]
    pub async fn test_create_with_existing_ledger<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut rng = ChaChaRng::from_seed([127u8; 32]);

        // Initialize a ledger and wallet, and get the owner address.
        let mut now = Instant::now();
        let initial_grant = 10;
        let (ledger, mut wallets) = t
            .create_test_network(&[(2, 2)], vec![initial_grant], false, &mut now)
            .await;
        ledger.lock().await.set_block_size(1).unwrap();

        let (mut wallet1, addresses1) = wallets.remove(0);
        let receipt = wallet1
            .transfer(
                Some(&addresses1[0]),
                &AssetCode::native(),
                &[(addresses1[0].clone(), 1)],
                1,
            )
            .await
            .unwrap()
            .clone();
        await_transaction(&receipt, &wallet1, &[]).await;
        assert_eq!(
            wallet1
                .balance_breakdown(&addresses1[0], &AssetCode::native())
                .await,
            initial_grant - 1
        );

        // A new wallet joins the system after there are already some transactions on the ledger.
        let storage = t.create_storage().await;
        let key_stream = hd::KeyTree::random(&mut rng).0;
        let backend = t
            .create_backend(
                ledger.clone(),
                vec![],
                key_stream,
                Arc::new(Mutex::new(storage)),
            )
            .await;
        let mut wallet2 = Wallet::new(backend).await.unwrap();
        wallet2.sync(ledger.lock().await.now()).await.unwrap();
        let address2 = wallet2.generate_user_key(None).await.unwrap().address();

        // Transfer to the late wallet.
        let receipt = wallet1
            .transfer(
                Some(&addresses1[0]),
                &AssetCode::native(),
                &[(address2.clone(), 2)],
                1,
            )
            .await
            .unwrap()
            .clone();
        await_transaction(&receipt, &wallet1, &[&wallet2]).await;
        assert_eq!(
            wallet1
                .balance_breakdown(&addresses1[0], &AssetCode::native())
                .await,
            initial_grant - 4
        );
        assert_eq!(
            wallet2
                .balance_breakdown(&address2, &AssetCode::native())
                .await,
            2
        );

        // Transfer back.
        let receipt = wallet2
            .transfer(
                Some(&address2),
                &AssetCode::native(),
                &[(addresses1[0].clone(), 1)],
                1,
            )
            .await
            .unwrap()
            .clone();
        await_transaction(&receipt, &wallet2, &[&wallet1]).await;
        assert_eq!(
            wallet1
                .balance_breakdown(&addresses1[0], &AssetCode::native())
                .await,
            initial_grant - 3
        );
        assert_eq!(
            wallet2
                .balance_breakdown(&address2, &AssetCode::native())
                .await,
            0
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
        let (ledger, mut wallets) = t
            .create_test_network(
                &[(num_inputs, num_outputs)],
                vec![alice_grant, bob_grant],
                true,
                &mut now,
            )
            .await;
        let alice_addresses = wallets[0].1.clone();
        let bob_addresses = wallets[1].1.clone();

        // Verify initial wallet state.
        assert_eq!(
            wallets[0].0.balance(&AssetCode::native()).await,
            alice_grant
        );
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&alice_addresses[0], &AssetCode::native())
                .await,
            alice_grant / 2
        );
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&alice_addresses[1], &AssetCode::native())
                .await,
            alice_grant - alice_grant / 2
        );
        assert_eq!(wallets[1].0.balance(&AssetCode::native()).await, bob_grant);
        assert_eq!(
            wallets[1]
                .0
                .balance_breakdown(&bob_addresses[0], &AssetCode::native())
                .await,
            bob_grant / 2
        );
        assert_eq!(
            wallets[1]
                .0
                .balance_breakdown(&bob_addresses[1], &AssetCode::native())
                .await,
            bob_grant - bob_grant / 2
        );

        // Alice defines a coin and gives her first address some initial grant.
        let coin = wallets[0]
            .0
            .define_asset("Alice's asset".as_bytes(), Default::default())
            .await
            .unwrap();
        let amount = 10;
        wallets[0]
            .0
            .mint(
                &alice_addresses[0],
                1,
                &coin.code,
                amount,
                alice_addresses[0].clone(),
            )
            .await
            .unwrap();
        t.sync(&ledger, wallets.as_slice()).await;
        println!("Asset minted: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Verify the aggragated balance and the balance in each address of Alice.
        assert_eq!(wallets[0].0.balance(&coin.code).await, amount);
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&alice_addresses[0], &coin.code)
                .await,
            amount
        );
        assert_eq!(
            wallets[0]
                .0
                .balance_breakdown(&alice_addresses[1], &coin.code)
                .await,
            0
        );

        // Transferring from Alice's second address to Bob should fail due to insufficient
        // balance.
        let transfer_amount = 3;
        let fee = 1;
        match wallets[0]
            .0
            .transfer(
                Some(&alice_addresses[1]),
                &coin.code,
                &[(bob_addresses[0].clone(), transfer_amount)],
                fee,
            )
            .await
        {
            Err(WalletError::TransactionError {
                source: TransactionError::InsufficientBalance { .. },
            }) => {}
            ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
        }

        // Transferring from Alice's first address to Bob should succeed.
        wallets[0]
            .0
            .transfer(
                Some(&alice_addresses[0]),
                &coin.code,
                &[(bob_addresses[0].clone(), transfer_amount)],
                fee,
            )
            .await
            .unwrap();
        t.sync(&ledger, wallets.as_slice()).await;
        println!(
            "Transfer generated from a specified address: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();

        // Transferring from Alice to Bob without specifying Alice's address should also succeed.
        wallets[0]
            .0
            .transfer(
                None,
                &coin.code,
                &[(bob_addresses[0].clone(), transfer_amount)],
                fee,
            )
            .await
            .unwrap();
        t.sync(&ledger, wallets.as_slice()).await;
        println!(
            "Transfer generated without a specified address: {}s",
            now.elapsed().as_secs_f32()
        );

        // Verify the balances of the native and defined coins.
        assert_eq!(
            wallets[0].0.balance(&AssetCode::native()).await,
            alice_grant - fee * 3
        );
        assert_eq!(
            wallets[0].0.balance(&coin.code).await,
            amount - transfer_amount * 2
        );
        assert_eq!(wallets[1].0.balance(&AssetCode::native()).await, bob_grant);
        assert_eq!(wallets[1].0.balance(&coin.code).await, transfer_amount * 2);
    }

    #[async_std::test]
    pub async fn test_asset_library<'a, T: SystemUnderTest<'a>>() {
        let mut t = T::default();
        let mut now = Instant::now();
        let initial_grant = 10;
        let (ledger, mut wallets) = t
            .create_test_network(&[(2, 2)], vec![initial_grant, initial_grant], &mut now)
            .await;

        // Test various ways of discovering assets. We will have wallets[0] discover assets by
        //  * defining one itself
        //  * receiving one from wallets[1]
        //  * importing one
        // All of these asset types should end up in the asset library, as well as the native asset
        // type which should always be present. The defined asset should also appear in the
        // auditable subset if we use the right auditor key, which we will define now:
        let audit_key0 = wallets[0].0.generate_audit_key().await.unwrap();

        // Define an asset.
        let defined_asset = wallets[0]
            .0
            .define_asset(&[], AssetPolicy::default().set_auditor_pub_key(audit_key0))
            .await
            .unwrap();

        // Receive an asset. wallets[1] will define a new asset type (auditable by itself) and then
        // mint some to wallets[0].
        let audit_key1 = wallets[1].0.generate_audit_key().await.unwrap();
        let minted_asset = wallets[1]
            .0
            .define_asset(&[], AssetPolicy::default().set_auditor_pub_key(audit_key1))
            .await
            .unwrap();
        let minter_addr = wallets[1].1.clone();
        let receiver_addr = wallets[0].1.clone();
        wallets[1]
            .0
            .mint(&minter_addr, 1, &minted_asset.code, 1, receiver_addr)
            .await
            .unwrap();
        t.sync(&ledger, &wallets).await;

        // Import an asset (we'll use `wallets[1]` to define it).
        let imported_asset = wallets[1]
            .0
            .define_asset(&[], AssetPolicy::default())
            .await
            .unwrap();
        wallets[0]
            .0
            .import_asset(AssetInfo::from(imported_asset.clone()))
            .await
            .unwrap();

        // Now check that all expected asset types appear in wallets[0]'s asset library.
        let get_asset = |code| {
            let wallet = &wallets[0].0;
            async move {
                let asset = wallet.asset(code).await.unwrap();
                assert!(wallet.assets().await.contains(&asset));
                asset
            }
        };
        assert_eq!(get_asset(AssetCode::native()).await, AssetInfo::native());
        assert_eq!(
            get_asset(defined_asset.code).await.definition,
            defined_asset
        );
        assert!(get_asset(defined_asset.code).await.mint_info.is_some());
        assert_eq!(
            get_asset(minted_asset.code).await,
            AssetInfo::from(minted_asset.clone())
        );
        assert_eq!(
            get_asset(imported_asset.code).await,
            AssetInfo::from(imported_asset.clone())
        );
    }
}
