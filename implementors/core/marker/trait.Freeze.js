(function() {var implementors = {};
implementors["seahorse"] = [{"text":"impl&lt;L, Key&gt; Freeze for <a class=\"struct\" href=\"seahorse/accounts/struct.Account.html\" title=\"struct seahorse::accounts::Account\">Account</a>&lt;L, Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::accounts::Account"]},{"text":"impl&lt;'a, L, Key&gt; Freeze for <a class=\"struct\" href=\"seahorse/accounts/struct.AccountEditor.html\" title=\"struct seahorse::accounts::AccountEditor\">AccountEditor</a>&lt;'a, L, Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::accounts::AccountEditor"]},{"text":"impl&lt;L, Key&gt; Freeze for <a class=\"struct\" href=\"seahorse/accounts/struct.Accounts.html\" title=\"struct seahorse::accounts::Accounts\">Accounts</a>&lt;L, Key&gt;","synthetic":true,"types":["seahorse::accounts::Accounts"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/assets/struct.Icon.html\" title=\"struct seahorse::assets::Icon\">Icon</a>","synthetic":true,"types":["seahorse::assets::Icon"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/assets/struct.MintInfo.html\" title=\"struct seahorse::assets::MintInfo\">MintInfo</a>","synthetic":true,"types":["seahorse::assets::MintInfo"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/assets/struct.VerifiedAssetLibrary.html\" title=\"struct seahorse::assets::VerifiedAssetLibrary\">VerifiedAssetLibrary</a>","synthetic":true,"types":["seahorse::assets::VerifiedAssetLibrary"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/assets/struct.Asset.html\" title=\"struct seahorse::assets::Asset\">Asset</a>","synthetic":true,"types":["seahorse::assets::Asset"]},{"text":"impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"seahorse/assets/struct.AssetEditor.html\" title=\"struct seahorse::assets::AssetEditor\">AssetEditor</a>&lt;'a&gt;","synthetic":true,"types":["seahorse::assets::AssetEditor"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/assets/struct.Assets.html\" title=\"struct seahorse::assets::Assets\">Assets</a>","synthetic":true,"types":["seahorse::assets::Assets"]},{"text":"impl&lt;'a, C&gt; Freeze for <a class=\"struct\" href=\"seahorse/cli/struct.Command.html\" title=\"struct seahorse::cli::Command\">Command</a>&lt;'a, C&gt;","synthetic":true,"types":["seahorse::cli::Command"]},{"text":"impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"seahorse/cli/struct.ListItem.html\" title=\"struct seahorse::cli::ListItem\">ListItem</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::cli::ListItem"]},{"text":"impl Freeze for <a class=\"enum\" href=\"seahorse/cli/enum.KeyType.html\" title=\"enum seahorse::cli::KeyType\">KeyType</a>","synthetic":true,"types":["seahorse::cli::KeyType"]},{"text":"impl Freeze for <a class=\"enum\" href=\"seahorse/encryption/enum.Error.html\" title=\"enum seahorse::encryption::Error\">Error</a>","synthetic":true,"types":["seahorse::encryption::Error"]},{"text":"impl&lt;Rng&gt; Freeze for <a class=\"struct\" href=\"seahorse/encryption/struct.Cipher.html\" title=\"struct seahorse::encryption::Cipher\">Cipher</a>&lt;Rng&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Rng: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::encryption::Cipher"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/encryption/struct.Decrypter.html\" title=\"struct seahorse::encryption::Decrypter\">Decrypter</a>","synthetic":true,"types":["seahorse::encryption::Decrypter"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/encryption/struct.CipherText.html\" title=\"struct seahorse::encryption::CipherText\">CipherText</a>","synthetic":true,"types":["seahorse::encryption::CipherText"]},{"text":"impl&lt;L&gt; Freeze for <a class=\"enum\" href=\"seahorse/events/enum.LedgerEvent.html\" title=\"enum seahorse::events::LedgerEvent\">LedgerEvent</a>&lt;L&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Error: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Transaction as Transaction&gt;::Hash: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Transaction as Transaction&gt;::Kind: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::StateCommitment: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::events::LedgerEvent"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/events/struct.EventIndex.html\" title=\"struct seahorse::events::EventIndex\">EventIndex</a>","synthetic":true,"types":["seahorse::events::EventIndex"]},{"text":"impl Freeze for <a class=\"enum\" href=\"seahorse/events/enum.EventSource.html\" title=\"enum seahorse::events::EventSource\">EventSource</a>","synthetic":true,"types":["seahorse::events::EventSource"]},{"text":"impl&lt;S&gt; Freeze for <a class=\"struct\" href=\"seahorse/hd/struct.Secret.html\" title=\"struct seahorse::hd::Secret\">Secret</a>&lt;S&gt;","synthetic":true,"types":["seahorse::secret::Secret"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/hd/struct.KeyTree.html\" title=\"struct seahorse::hd::KeyTree\">KeyTree</a>","synthetic":true,"types":["seahorse::hd::KeyTree"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/hd/struct.Key.html\" title=\"struct seahorse::hd::Key\">Key</a>","synthetic":true,"types":["seahorse::hd::Key"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/io/struct.SharedIO.html\" title=\"struct seahorse::io::SharedIO\">SharedIO</a>","synthetic":true,"types":["seahorse::io::SharedIO"]},{"text":"impl&lt;S&gt; Freeze for <a class=\"struct\" href=\"seahorse/io/struct.Tee.html\" title=\"struct seahorse::io::Tee\">Tee</a>&lt;S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::io::Tee"]},{"text":"impl Freeze for <a class=\"enum\" href=\"seahorse/key_value_store/enum.KeyValueStoreError.html\" title=\"enum seahorse::key_value_store::KeyValueStoreError\">KeyValueStoreError</a>","synthetic":true,"types":["seahorse::key_value_store::KeyValueStoreError"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/key_value_store/struct.KeyNotFoundSnafu.html\" title=\"struct seahorse::key_value_store::KeyNotFoundSnafu\">KeyNotFoundSnafu</a>","synthetic":true,"types":["seahorse::key_value_store::KeyNotFoundSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/key_value_store/struct.PersistenceSnafu.html\" title=\"struct seahorse::key_value_store::PersistenceSnafu\">PersistenceSnafu</a>","synthetic":true,"types":["seahorse::key_value_store::PersistenceSnafu"]},{"text":"impl&lt;K, V&gt; Freeze for <a class=\"struct\" href=\"seahorse/key_value_store/struct.KeyValueStore.html\" title=\"struct seahorse::key_value_store::KeyValueStore\">KeyValueStore</a>&lt;K, V&gt;","synthetic":true,"types":["seahorse::key_value_store::KeyValueStore"]},{"text":"impl&lt;C&gt; Freeze for <a class=\"enum\" href=\"seahorse/key_value_store/enum.IndexChange.html\" title=\"enum seahorse::key_value_store::IndexChange\">IndexChange</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::key_value_store::IndexChange"]},{"text":"impl&lt;C, I&gt; Freeze for <a class=\"struct\" href=\"seahorse/key_value_store/struct.PersistableMap.html\" title=\"struct seahorse::key_value_store::PersistableMap\">PersistableMap</a>&lt;C, I&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;I: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::key_value_store::PersistableMap"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.RecordAmount.html\" title=\"struct seahorse::ledger_state::RecordAmount\">RecordAmount</a>","synthetic":true,"types":["seahorse::ledger_state::RecordAmount"]},{"text":"impl Freeze for <a class=\"enum\" href=\"seahorse/ledger_state/enum.ConvertRecordAmountError.html\" title=\"enum seahorse::ledger_state::ConvertRecordAmountError\">ConvertRecordAmountError</a>","synthetic":true,"types":["seahorse::ledger_state::ConvertRecordAmountError"]},{"text":"impl Freeze for <a class=\"enum\" href=\"seahorse/ledger_state/enum.TransactionError.html\" title=\"enum seahorse::ledger_state::TransactionError\">TransactionError</a>","synthetic":true,"types":["seahorse::ledger_state::TransactionError"]},{"text":"impl&lt;__T0, __T1, __T2&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.InsufficientBalanceSnafu.html\" title=\"struct seahorse::ledger_state::InsufficientBalanceSnafu\">InsufficientBalanceSnafu</a>&lt;__T0, __T1, __T2&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T2: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::ledger_state::InsufficientBalanceSnafu"]},{"text":"impl&lt;__T0, __T1, __T2, __T3&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.FragmentationSnafu.html\" title=\"struct seahorse::ledger_state::FragmentationSnafu\">FragmentationSnafu</a>&lt;__T0, __T1, __T2, __T3&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T2: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T3: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::ledger_state::FragmentationSnafu"]},{"text":"impl&lt;__T0, __T1, __T2, __T3&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.TooManyOutputsSnafu.html\" title=\"struct seahorse::ledger_state::TooManyOutputsSnafu\">TooManyOutputsSnafu</a>&lt;__T0, __T1, __T2, __T3&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T2: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T3: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::ledger_state::TooManyOutputsSnafu"]},{"text":"impl&lt;__T0, __T1, __T2, __T3, __T4&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.InvalidSizeSnafu.html\" title=\"struct seahorse::ledger_state::InvalidSizeSnafu\">InvalidSizeSnafu</a>&lt;__T0, __T1, __T2, __T3, __T4&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T2: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T3: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T4: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::ledger_state::InvalidSizeSnafu"]},{"text":"impl&lt;__T0, __T1&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.NoFitKeySnafu.html\" title=\"struct seahorse::ledger_state::NoFitKeySnafu\">NoFitKeySnafu</a>&lt;__T0, __T1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::ledger_state::NoFitKeySnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.CryptoSnafu.html\" title=\"struct seahorse::ledger_state::CryptoSnafu\">CryptoSnafu</a>","synthetic":true,"types":["seahorse::ledger_state::CryptoSnafu"]},{"text":"impl&lt;__T0, __T1&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.InvalidViewerKeySnafu.html\" title=\"struct seahorse::ledger_state::InvalidViewerKeySnafu\">InvalidViewerKeySnafu</a>&lt;__T0, __T1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::ledger_state::InvalidViewerKeySnafu"]},{"text":"impl&lt;__T0, __T1&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.InvalidFreezerKeySnafu.html\" title=\"struct seahorse::ledger_state::InvalidFreezerKeySnafu\">InvalidFreezerKeySnafu</a>&lt;__T0, __T1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::ledger_state::InvalidFreezerKeySnafu"]},{"text":"impl Freeze for <a class=\"enum\" href=\"seahorse/ledger_state/enum.TransactionStatus.html\" title=\"enum seahorse::ledger_state::TransactionStatus\">TransactionStatus</a>","synthetic":true,"types":["seahorse::ledger_state::TransactionStatus"]},{"text":"impl&lt;L&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.TransactionUID.html\" title=\"struct seahorse::ledger_state::TransactionUID\">TransactionUID</a>&lt;L&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Transaction as Transaction&gt;::Hash: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::ledger_state::TransactionUID"]},{"text":"impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.TransferSpec.html\" title=\"struct seahorse::ledger_state::TransferSpec\">TransferSpec</a>&lt;'a&gt;","synthetic":true,"types":["seahorse::ledger_state::TransferSpec"]},{"text":"impl&lt;'a, L&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.LedgerState.html\" title=\"struct seahorse::ledger_state::LedgerState\">LedgerState</a>&lt;'a, L&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Transaction as Transaction&gt;::NullifierSet: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;L as Ledger&gt;::Validator: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::ledger_state::LedgerState"]},{"text":"impl&lt;'a, L&gt; Freeze for <a class=\"struct\" href=\"seahorse/ledger_state/struct.LedgerStates.html\" title=\"struct seahorse::ledger_state::LedgerStates\">LedgerStates</a>&lt;'a, L&gt;","synthetic":true,"types":["seahorse::ledger_state::LedgerStates"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/loader/create/struct.CreateLoader.html\" title=\"struct seahorse::loader::create::CreateLoader\">CreateLoader</a>","synthetic":true,"types":["seahorse::loader::create::CreateLoader"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/loader/interactive/struct.InteractiveLoader.html\" title=\"struct seahorse::loader::interactive::InteractiveLoader\">InteractiveLoader</a>","synthetic":true,"types":["seahorse::loader::interactive::InteractiveLoader"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/loader/login/struct.LoginLoader.html\" title=\"struct seahorse::loader::login::LoginLoader\">LoginLoader</a>","synthetic":true,"types":["seahorse::loader::login::LoginLoader"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/loader/recovery/struct.RecoveryLoader.html\" title=\"struct seahorse::loader::recovery::RecoveryLoader\">RecoveryLoader</a>","synthetic":true,"types":["seahorse::loader::recovery::RecoveryLoader"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/loader/struct.MnemonicPasswordLogin.html\" title=\"struct seahorse::loader::MnemonicPasswordLogin\">MnemonicPasswordLogin</a>","synthetic":true,"types":["seahorse::loader::MnemonicPasswordLogin"]},{"text":"impl&lt;Meta&gt; Freeze for <a class=\"struct\" href=\"seahorse/meta/struct.MetaStore.html\" title=\"struct seahorse::meta::MetaStore\">MetaStore</a>&lt;Meta&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Meta: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::meta::MetaStore"]},{"text":"impl Freeze for <a class=\"enum\" href=\"seahorse/reader/enum.Reader.html\" title=\"enum seahorse::reader::Reader\">Reader</a>","synthetic":true,"types":["seahorse::reader::Reader"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/records/struct.Record.html\" title=\"struct seahorse::records::Record\">Record</a>","synthetic":true,"types":["seahorse::records::Record"]},{"text":"impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"seahorse/records/struct.RecordEditor.html\" title=\"struct seahorse::records::RecordEditor\">RecordEditor</a>&lt;'a&gt;","synthetic":true,"types":["seahorse::records::RecordEditor"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/records/struct.Records.html\" title=\"struct seahorse::records::Records\">Records</a>","synthetic":true,"types":["seahorse::records::Records"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/sparse_merkle_tree/struct.SparseMerkleTree.html\" title=\"struct seahorse::sparse_merkle_tree::SparseMerkleTree\">SparseMerkleTree</a>","synthetic":true,"types":["seahorse::sparse_merkle_tree::SparseMerkleTree"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/transactions/struct.SignedMemos.html\" title=\"struct seahorse::transactions::SignedMemos\">SignedMemos</a>","synthetic":true,"types":["seahorse::transactions::SignedMemos"]},{"text":"impl&lt;L&gt; Freeze for <a class=\"struct\" href=\"seahorse/transactions/struct.Transaction.html\" title=\"struct seahorse::transactions::Transaction\">Transaction</a>&lt;L&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Transaction as Transaction&gt;::Hash: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Transaction as Transaction&gt;::Kind: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::transactions::Transaction"]},{"text":"impl&lt;'a, L&gt; Freeze for <a class=\"struct\" href=\"seahorse/transactions/struct.TransactionEditor.html\" title=\"struct seahorse::transactions::TransactionEditor\">TransactionEditor</a>&lt;'a, L&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Transaction as Transaction&gt;::Hash: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Transaction as Transaction&gt;::Kind: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::transactions::TransactionEditor"]},{"text":"impl&lt;L&gt; Freeze for <a class=\"struct\" href=\"seahorse/transactions/struct.TransactionParams.html\" title=\"struct seahorse::transactions::TransactionParams\">TransactionParams</a>&lt;L&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Transaction as Transaction&gt;::Kind: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::transactions::TransactionParams"]},{"text":"impl&lt;L&gt; Freeze for <a class=\"struct\" href=\"seahorse/transactions/struct.Transactions.html\" title=\"struct seahorse::transactions::Transactions\">Transactions</a>&lt;L&gt;","synthetic":true,"types":["seahorse::transactions::Transactions"]},{"text":"impl&lt;L&gt; Freeze for <a class=\"enum\" href=\"seahorse/enum.KeystoreError.html\" title=\"enum seahorse::KeystoreError\">KeystoreError</a>&lt;L&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;&lt;L as Ledger&gt;::Validator as Validator&gt;::Block as Block&gt;::Error: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::KeystoreError"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.UndefinedAssetSnafu.html\" title=\"struct seahorse::UndefinedAssetSnafu\">UndefinedAssetSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::UndefinedAssetSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.InvalidBlockSnafu.html\" title=\"struct seahorse::InvalidBlockSnafu\">InvalidBlockSnafu</a>","synthetic":true,"types":["seahorse::InvalidBlockSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.NullifierAlreadyPublishedSnafu.html\" title=\"struct seahorse::NullifierAlreadyPublishedSnafu\">NullifierAlreadyPublishedSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::NullifierAlreadyPublishedSnafu"]},{"text":"impl&lt;__T0, __T1&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.BadMerkleProofSnafu.html\" title=\"struct seahorse::BadMerkleProofSnafu\">BadMerkleProofSnafu</a>&lt;__T0, __T1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::BadMerkleProofSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.TimedOutSnafu.html\" title=\"struct seahorse::TimedOutSnafu\">TimedOutSnafu</a>","synthetic":true,"types":["seahorse::TimedOutSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.CancelledSnafu.html\" title=\"struct seahorse::CancelledSnafu\">CancelledSnafu</a>","synthetic":true,"types":["seahorse::CancelledSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.CryptoSnafu.html\" title=\"struct seahorse::CryptoSnafu\">CryptoSnafu</a>","synthetic":true,"types":["seahorse::CryptoSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.InvalidAddressSnafu.html\" title=\"struct seahorse::InvalidAddressSnafu\">InvalidAddressSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::InvalidAddressSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.InconsistentAssetSnafu.html\" title=\"struct seahorse::InconsistentAssetSnafu\">InconsistentAssetSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::InconsistentAssetSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.AssetNotViewableSnafu.html\" title=\"struct seahorse::AssetNotViewableSnafu\">AssetNotViewableSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::AssetNotViewableSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.AssetNotFreezableSnafu.html\" title=\"struct seahorse::AssetNotFreezableSnafu\">AssetNotFreezableSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::AssetNotFreezableSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.AssetNotMintableSnafu.html\" title=\"struct seahorse::AssetNotMintableSnafu\">AssetNotMintableSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::AssetNotMintableSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.ClientConfigSnafu.html\" title=\"struct seahorse::ClientConfigSnafu\">ClientConfigSnafu</a>","synthetic":true,"types":["seahorse::ClientConfigSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.PersistenceSnafu.html\" title=\"struct seahorse::PersistenceSnafu\">PersistenceSnafu</a>","synthetic":true,"types":["seahorse::PersistenceSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.IoSnafu.html\" title=\"struct seahorse::IoSnafu\">IoSnafu</a>","synthetic":true,"types":["seahorse::IoSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.BincodeSnafu.html\" title=\"struct seahorse::BincodeSnafu\">BincodeSnafu</a>","synthetic":true,"types":["seahorse::BincodeSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.EncryptionSnafu.html\" title=\"struct seahorse::EncryptionSnafu\">EncryptionSnafu</a>","synthetic":true,"types":["seahorse::EncryptionSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.MnemonicSnafu.html\" title=\"struct seahorse::MnemonicSnafu\">MnemonicSnafu</a>","synthetic":true,"types":["seahorse::MnemonicSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.KeySnafu.html\" title=\"struct seahorse::KeySnafu\">KeySnafu</a>","synthetic":true,"types":["seahorse::KeySnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.KeyValueStoreSnafu.html\" title=\"struct seahorse::KeyValueStoreSnafu\">KeyValueStoreSnafu</a>","synthetic":true,"types":["seahorse::KeyValueStoreSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.NoSuchAccountSnafu.html\" title=\"struct seahorse::NoSuchAccountSnafu\">NoSuchAccountSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::NoSuchAccountSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.CannotDecryptMemoSnafu.html\" title=\"struct seahorse::CannotDecryptMemoSnafu\">CannotDecryptMemoSnafu</a>","synthetic":true,"types":["seahorse::CannotDecryptMemoSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.TransactionSnafu.html\" title=\"struct seahorse::TransactionSnafu\">TransactionSnafu</a>","synthetic":true,"types":["seahorse::TransactionSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.UserKeyExistsSnafu.html\" title=\"struct seahorse::UserKeyExistsSnafu\">UserKeyExistsSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::UserKeyExistsSnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.AssetVerificationSnafu.html\" title=\"struct seahorse::AssetVerificationSnafu\">AssetVerificationSnafu</a>","synthetic":true,"types":["seahorse::AssetVerificationSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.FailedSnafu.html\" title=\"struct seahorse::FailedSnafu\">FailedSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::FailedSnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.InvalidFreezerKeySnafu.html\" title=\"struct seahorse::InvalidFreezerKeySnafu\">InvalidFreezerKeySnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::InvalidFreezerKeySnafu"]},{"text":"impl&lt;__T0&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.InvalidViewerKeySnafu.html\" title=\"struct seahorse::InvalidViewerKeySnafu\">InvalidViewerKeySnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::InvalidViewerKeySnafu"]},{"text":"impl Freeze for <a class=\"struct\" href=\"seahorse/struct.ScanNotFoundSnafu.html\" title=\"struct seahorse::ScanNotFoundSnafu\">ScanNotFoundSnafu</a>","synthetic":true,"types":["seahorse::ScanNotFoundSnafu"]},{"text":"impl&lt;'a, L, Backend, Meta&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.KeystoreModel.html\" title=\"struct seahorse::KeystoreModel\">KeystoreModel</a>&lt;'a, L, Backend, Meta&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Backend: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;Meta: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::KeystoreModel"]},{"text":"impl&lt;'a, Backend, L, Meta&gt; !Freeze for <a class=\"struct\" href=\"seahorse/struct.Keystore.html\" title=\"struct seahorse::Keystore\">Keystore</a>&lt;'a, Backend, L, Meta&gt;","synthetic":true,"types":["seahorse::Keystore"]},{"text":"impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.EncryptingResourceAdapter.html\" title=\"struct seahorse::EncryptingResourceAdapter\">EncryptingResourceAdapter</a>&lt;T&gt;","synthetic":true,"types":["seahorse::EncryptingResourceAdapter"]},{"text":"impl&lt;'a, L, Meta&gt; Freeze for <a class=\"struct\" href=\"seahorse/struct.KeystoreResources.html\" title=\"struct seahorse::KeystoreResources\">KeystoreResources</a>&lt;'a, L, Meta&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Meta: Freeze,&nbsp;</span>","synthetic":true,"types":["seahorse::KeystoreResources"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()