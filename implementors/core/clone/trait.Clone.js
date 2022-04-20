(function() {var implementors = {};
implementors["seahorse"] = [{"text":"impl&lt;L:&nbsp;Ledger, Key&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/accounts/struct.Account.html\" title=\"struct seahorse::accounts::Account\">Account</a>&lt;L, Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;L: Ledger,<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["seahorse::accounts::Account"]},{"text":"impl&lt;Key:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"seahorse/accounts/trait.KeyPair.html\" title=\"trait seahorse::accounts::KeyPair\">KeyPair</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/accounts/struct.AccountInfo.html\" title=\"struct seahorse::accounts::AccountInfo\">AccountInfo</a>&lt;Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key::<a class=\"type\" href=\"seahorse/accounts/trait.KeyPair.html#associatedtype.PubKey\" title=\"type seahorse::accounts::KeyPair::PubKey\">PubKey</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["seahorse::accounts::AccountInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.Icon.html\" title=\"struct seahorse::asset_library::Icon\">Icon</a>","synthetic":false,"types":["seahorse::asset_library::Icon"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.AssetInfo.html\" title=\"struct seahorse::asset_library::AssetInfo\">AssetInfo</a>","synthetic":false,"types":["seahorse::asset_library::AssetInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.MintInfo.html\" title=\"struct seahorse::asset_library::MintInfo\">MintInfo</a>","synthetic":false,"types":["seahorse::asset_library::MintInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.AssetLibrary.html\" title=\"struct seahorse::asset_library::AssetLibrary\">AssetLibrary</a>","synthetic":false,"types":["seahorse::asset_library::AssetLibrary"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.VerifiedAssetLibrary.html\" title=\"struct seahorse::asset_library::VerifiedAssetLibrary\">VerifiedAssetLibrary</a>","synthetic":false,"types":["seahorse::asset_library::VerifiedAssetLibrary"]},{"text":"impl&lt;Rng:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://rust-random.github.io/rand/rand_core/trait.CryptoRng.html\" title=\"trait rand_core::CryptoRng\">CryptoRng</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/encryption/struct.Cipher.html\" title=\"struct seahorse::encryption::Cipher\">Cipher</a>&lt;Rng&gt;","synthetic":false,"types":["seahorse::encryption::Cipher"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/encryption/struct.CipherText.html\" title=\"struct seahorse::encryption::CipherText\">CipherText</a>","synthetic":false,"types":["seahorse::encryption::CipherText"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"seahorse/events/enum.LedgerEvent.html\" title=\"enum seahorse::events::LedgerEvent\">LedgerEvent</a>&lt;L&gt;","synthetic":false,"types":["seahorse::events::LedgerEvent"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/events/struct.EventIndex.html\" title=\"struct seahorse::events::EventIndex\">EventIndex</a>","synthetic":false,"types":["seahorse::events::EventIndex"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"seahorse/events/enum.EventSource.html\" title=\"enum seahorse::events::EventSource\">EventSource</a>","synthetic":false,"types":["seahorse::events::EventSource"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/hd/struct.KeyTree.html\" title=\"struct seahorse::hd::KeyTree\">KeyTree</a>","synthetic":false,"types":["seahorse::hd::KeyTree"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/hd/struct.Key.html\" title=\"struct seahorse::hd::Key\">Key</a>","synthetic":false,"types":["seahorse::hd::Key"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/io/struct.SharedIO.html\" title=\"struct seahorse::io::SharedIO\">SharedIO</a>","synthetic":false,"types":["seahorse::io::SharedIO"]},{"text":"impl&lt;S:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/io/struct.Tee.html\" title=\"struct seahorse::io::Tee\">Tee</a>&lt;S&gt;","synthetic":false,"types":["seahorse::io::Tee"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/loader/struct.LoaderMetadata.html\" title=\"struct seahorse::loader::LoaderMetadata\">LoaderMetadata</a>","synthetic":false,"types":["seahorse::loader::LoaderMetadata"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"seahorse/reader/enum.Reader.html\" title=\"enum seahorse::reader::Reader\">Reader</a>","synthetic":false,"types":["seahorse::reader::Reader"]},{"text":"impl&lt;S:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://docs.rs/zeroize/1.3.0/zeroize/trait.Zeroize.html\" title=\"trait zeroize::Zeroize\">Zeroize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/hd/struct.Secret.html\" title=\"struct seahorse::hd::Secret\">Secret</a>&lt;S&gt;","synthetic":false,"types":["seahorse::secret::Secret"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T2:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InsufficientBalanceSnafu.html\" title=\"struct seahorse::txn_builder::InsufficientBalanceSnafu\">InsufficientBalanceSnafu</a>&lt;__T0, __T1, __T2&gt;","synthetic":false,"types":["seahorse::txn_builder::InsufficientBalanceSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T2:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T3:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.FragmentationSnafu.html\" title=\"struct seahorse::txn_builder::FragmentationSnafu\">FragmentationSnafu</a>&lt;__T0, __T1, __T2, __T3&gt;","synthetic":false,"types":["seahorse::txn_builder::FragmentationSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T2:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T3:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TooManyOutputsSnafu.html\" title=\"struct seahorse::txn_builder::TooManyOutputsSnafu\">TooManyOutputsSnafu</a>&lt;__T0, __T1, __T2, __T3&gt;","synthetic":false,"types":["seahorse::txn_builder::TooManyOutputsSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T2:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T3:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T4:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InvalidSizeSnafu.html\" title=\"struct seahorse::txn_builder::InvalidSizeSnafu\">InvalidSizeSnafu</a>&lt;__T0, __T1, __T2, __T3, __T4&gt;","synthetic":false,"types":["seahorse::txn_builder::InvalidSizeSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.NoFitKeySnafu.html\" title=\"struct seahorse::txn_builder::NoFitKeySnafu\">NoFitKeySnafu</a>&lt;__T0, __T1&gt;","synthetic":false,"types":["seahorse::txn_builder::NoFitKeySnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.CryptoSnafu.html\" title=\"struct seahorse::txn_builder::CryptoSnafu\">CryptoSnafu</a>","synthetic":false,"types":["seahorse::txn_builder::CryptoSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InvalidAuditorKeySnafu.html\" title=\"struct seahorse::txn_builder::InvalidAuditorKeySnafu\">InvalidAuditorKeySnafu</a>&lt;__T0, __T1&gt;","synthetic":false,"types":["seahorse::txn_builder::InvalidAuditorKeySnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InvalidFreezerKeySnafu.html\" title=\"struct seahorse::txn_builder::InvalidFreezerKeySnafu\">InvalidFreezerKeySnafu</a>&lt;__T0, __T1&gt;","synthetic":false,"types":["seahorse::txn_builder::InvalidFreezerKeySnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.RecordInfo.html\" title=\"struct seahorse::txn_builder::RecordInfo\">RecordInfo</a>","synthetic":false,"types":["seahorse::txn_builder::RecordInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.RecordDatabase.html\" title=\"struct seahorse::txn_builder::RecordDatabase\">RecordDatabase</a>","synthetic":false,"types":["seahorse::txn_builder::RecordDatabase"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"seahorse/txn_builder/enum.TransactionStatus.html\" title=\"enum seahorse::txn_builder::TransactionStatus\">TransactionStatus</a>","synthetic":false,"types":["seahorse::txn_builder::TransactionStatus"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionReceipt.html\" title=\"struct seahorse::txn_builder::TransactionReceipt\">TransactionReceipt</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionReceipt"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.PendingTransaction.html\" title=\"struct seahorse::txn_builder::PendingTransaction\">PendingTransaction</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::PendingTransaction"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionAwaitingMemos.html\" title=\"struct seahorse::txn_builder::TransactionAwaitingMemos\">TransactionAwaitingMemos</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionAwaitingMemos"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionUID.html\" title=\"struct seahorse::txn_builder::TransactionUID\">TransactionUID</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionUID"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionDatabase.html\" title=\"struct seahorse::txn_builder::TransactionDatabase\">TransactionDatabase</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionDatabase"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionHistoryEntry.html\" title=\"struct seahorse::txn_builder::TransactionHistoryEntry\">TransactionHistoryEntry</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionHistoryEntry"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionInfo.html\" title=\"struct seahorse::txn_builder::TransactionInfo\">TransactionInfo</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionInfo"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionState.html\" title=\"struct seahorse::txn_builder::TransactionState\">TransactionState</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionState"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.UndefinedAssetSnafu.html\" title=\"struct seahorse::UndefinedAssetSnafu\">UndefinedAssetSnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::UndefinedAssetSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidBlockSnafu.html\" title=\"struct seahorse::InvalidBlockSnafu\">InvalidBlockSnafu</a>","synthetic":false,"types":["seahorse::InvalidBlockSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.NullifierAlreadyPublishedSnafu.html\" title=\"struct seahorse::NullifierAlreadyPublishedSnafu\">NullifierAlreadyPublishedSnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::NullifierAlreadyPublishedSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.BadMerkleProofSnafu.html\" title=\"struct seahorse::BadMerkleProofSnafu\">BadMerkleProofSnafu</a>&lt;__T0, __T1&gt;","synthetic":false,"types":["seahorse::BadMerkleProofSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.TimedOutSnafu.html\" title=\"struct seahorse::TimedOutSnafu\">TimedOutSnafu</a>","synthetic":false,"types":["seahorse::TimedOutSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.CancelledSnafu.html\" title=\"struct seahorse::CancelledSnafu\">CancelledSnafu</a>","synthetic":false,"types":["seahorse::CancelledSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.CryptoSnafu.html\" title=\"struct seahorse::CryptoSnafu\">CryptoSnafu</a>","synthetic":false,"types":["seahorse::CryptoSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidAddressSnafu.html\" title=\"struct seahorse::InvalidAddressSnafu\">InvalidAddressSnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::InvalidAddressSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.AssetNotAuditableSnafu.html\" title=\"struct seahorse::AssetNotAuditableSnafu\">AssetNotAuditableSnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::AssetNotAuditableSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.AssetNotFreezableSnafu.html\" title=\"struct seahorse::AssetNotFreezableSnafu\">AssetNotFreezableSnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::AssetNotFreezableSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.AssetNotMintableSnafu.html\" title=\"struct seahorse::AssetNotMintableSnafu\">AssetNotMintableSnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::AssetNotMintableSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.ClientConfigSnafu.html\" title=\"struct seahorse::ClientConfigSnafu\">ClientConfigSnafu</a>","synthetic":false,"types":["seahorse::ClientConfigSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.PersistenceSnafu.html\" title=\"struct seahorse::PersistenceSnafu\">PersistenceSnafu</a>","synthetic":false,"types":["seahorse::PersistenceSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.IoSnafu.html\" title=\"struct seahorse::IoSnafu\">IoSnafu</a>","synthetic":false,"types":["seahorse::IoSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.BincodeSnafu.html\" title=\"struct seahorse::BincodeSnafu\">BincodeSnafu</a>","synthetic":false,"types":["seahorse::BincodeSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.EncryptionSnafu.html\" title=\"struct seahorse::EncryptionSnafu\">EncryptionSnafu</a>","synthetic":false,"types":["seahorse::EncryptionSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.MnemonicSnafu.html\" title=\"struct seahorse::MnemonicSnafu\">MnemonicSnafu</a>","synthetic":false,"types":["seahorse::MnemonicSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.KeySnafu.html\" title=\"struct seahorse::KeySnafu\">KeySnafu</a>","synthetic":false,"types":["seahorse::KeySnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.NoSuchAccountSnafu.html\" title=\"struct seahorse::NoSuchAccountSnafu\">NoSuchAccountSnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::NoSuchAccountSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.CannotDecryptMemoSnafu.html\" title=\"struct seahorse::CannotDecryptMemoSnafu\">CannotDecryptMemoSnafu</a>","synthetic":false,"types":["seahorse::CannotDecryptMemoSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.TransactionSnafu.html\" title=\"struct seahorse::TransactionSnafu\">TransactionSnafu</a>","synthetic":false,"types":["seahorse::TransactionSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.UserKeyExistsSnafu.html\" title=\"struct seahorse::UserKeyExistsSnafu\">UserKeyExistsSnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::UserKeyExistsSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.AssetVerificationSnafu.html\" title=\"struct seahorse::AssetVerificationSnafu\">AssetVerificationSnafu</a>","synthetic":false,"types":["seahorse::AssetVerificationSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.FailedSnafu.html\" title=\"struct seahorse::FailedSnafu\">FailedSnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::FailedSnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidFreezerKeySnafu.html\" title=\"struct seahorse::InvalidFreezerKeySnafu\">InvalidFreezerKeySnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::InvalidFreezerKeySnafu"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidAuditorKeySnafu.html\" title=\"struct seahorse::InvalidAuditorKeySnafu\">InvalidAuditorKeySnafu</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::InvalidAuditorKeySnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.KeyStreamState.html\" title=\"struct seahorse::KeyStreamState\">KeyStreamState</a>","synthetic":false,"types":["seahorse::KeyStreamState"]},{"text":"impl&lt;'a, L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.KeystoreState.html\" title=\"struct seahorse::KeystoreState\">KeystoreState</a>&lt;'a, L&gt;","synthetic":false,"types":["seahorse::KeystoreState"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()