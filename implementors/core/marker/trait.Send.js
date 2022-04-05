(function() {var implementors = {};
implementors["seahorse"] = [{"text":"impl&lt;L, Key&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/accounts/struct.Account.html\" title=\"struct seahorse::accounts::Account\">Account</a>&lt;L, Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::accounts::Account"]},{"text":"impl&lt;Key&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/accounts/struct.AccountInfo.html\" title=\"struct seahorse::accounts::AccountInfo\">AccountInfo</a>&lt;Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Key as <a class=\"trait\" href=\"seahorse/accounts/trait.KeyPair.html\" title=\"trait seahorse::accounts::KeyPair\">KeyPair</a>&gt;::<a class=\"type\" href=\"seahorse/accounts/trait.KeyPair.html#associatedtype.PubKey\" title=\"type seahorse::accounts::KeyPair::PubKey\">PubKey</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::accounts::AccountInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.Icon.html\" title=\"struct seahorse::asset_library::Icon\">Icon</a>","synthetic":true,"types":["seahorse::asset_library::Icon"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.AssetInfo.html\" title=\"struct seahorse::asset_library::AssetInfo\">AssetInfo</a>","synthetic":true,"types":["seahorse::asset_library::AssetInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.MintInfo.html\" title=\"struct seahorse::asset_library::MintInfo\">MintInfo</a>","synthetic":true,"types":["seahorse::asset_library::MintInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.AssetLibrary.html\" title=\"struct seahorse::asset_library::AssetLibrary\">AssetLibrary</a>","synthetic":true,"types":["seahorse::asset_library::AssetLibrary"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/asset_library/struct.VerifiedAssetLibrary.html\" title=\"struct seahorse::asset_library::VerifiedAssetLibrary\">VerifiedAssetLibrary</a>","synthetic":true,"types":["seahorse::asset_library::VerifiedAssetLibrary"]},{"text":"impl&lt;'a, C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/cli/struct.Command.html\" title=\"struct seahorse::cli::Command\">Command</a>&lt;'a, C&gt;","synthetic":true,"types":["seahorse::cli::Command"]},{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/cli/struct.ListItem.html\" title=\"struct seahorse::cli::ListItem\">ListItem</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::cli::ListItem"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"seahorse/cli/enum.KeyType.html\" title=\"enum seahorse::cli::KeyType\">KeyType</a>","synthetic":true,"types":["seahorse::cli::KeyType"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"seahorse/encryption/enum.Error.html\" title=\"enum seahorse::encryption::Error\">Error</a>","synthetic":true,"types":["seahorse::encryption::Error"]},{"text":"impl&lt;Rng&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/encryption/struct.Cipher.html\" title=\"struct seahorse::encryption::Cipher\">Cipher</a>&lt;Rng&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Rng: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::encryption::Cipher"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/encryption/struct.CipherText.html\" title=\"struct seahorse::encryption::CipherText\">CipherText</a>","synthetic":true,"types":["seahorse::encryption::CipherText"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"seahorse/events/enum.LedgerEvent.html\" title=\"enum seahorse::events::LedgerEvent\">LedgerEvent</a>&lt;L&gt;","synthetic":true,"types":["seahorse::events::LedgerEvent"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/events/struct.EventIndex.html\" title=\"struct seahorse::events::EventIndex\">EventIndex</a>","synthetic":true,"types":["seahorse::events::EventIndex"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"seahorse/events/enum.EventSource.html\" title=\"enum seahorse::events::EventSource\">EventSource</a>","synthetic":true,"types":["seahorse::events::EventSource"]},{"text":"impl&lt;S&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/hd/struct.Secret.html\" title=\"struct seahorse::hd::Secret\">Secret</a>&lt;S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::secret::Secret"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/hd/struct.KeyTree.html\" title=\"struct seahorse::hd::KeyTree\">KeyTree</a>","synthetic":true,"types":["seahorse::hd::KeyTree"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/hd/struct.Key.html\" title=\"struct seahorse::hd::Key\">Key</a>","synthetic":true,"types":["seahorse::hd::Key"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/io/struct.SharedIO.html\" title=\"struct seahorse::io::SharedIO\">SharedIO</a>","synthetic":true,"types":["seahorse::io::SharedIO"]},{"text":"impl&lt;S&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/io/struct.Tee.html\" title=\"struct seahorse::io::Tee\">Tee</a>&lt;S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::io::Tee"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/loader/struct.LoaderMetadata.html\" title=\"struct seahorse::loader::LoaderMetadata\">LoaderMetadata</a>","synthetic":true,"types":["seahorse::loader::LoaderMetadata"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/loader/struct.Loader.html\" title=\"struct seahorse::loader::Loader\">Loader</a>","synthetic":true,"types":["seahorse::loader::Loader"]},{"text":"impl&lt;'a, L, Meta&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/persistence/struct.AtomicWalletStorage.html\" title=\"struct seahorse::persistence::AtomicWalletStorage\">AtomicWalletStorage</a>&lt;'a, L, Meta&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Meta: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::persistence::AtomicWalletStorage"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"seahorse/reader/enum.Reader.html\" title=\"enum seahorse::reader::Reader\">Reader</a>","synthetic":true,"types":["seahorse::reader::Reader"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"seahorse/txn_builder/enum.TransactionError.html\" title=\"enum seahorse::txn_builder::TransactionError\">TransactionError</a>","synthetic":true,"types":["seahorse::txn_builder::TransactionError"]},{"text":"impl&lt;__T0, __T1, __T2&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InsufficientBalanceSnafu.html\" title=\"struct seahorse::txn_builder::InsufficientBalanceSnafu\">InsufficientBalanceSnafu</a>&lt;__T0, __T1, __T2&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T2: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::txn_builder::InsufficientBalanceSnafu"]},{"text":"impl&lt;__T0, __T1, __T2, __T3&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.FragmentationSnafu.html\" title=\"struct seahorse::txn_builder::FragmentationSnafu\">FragmentationSnafu</a>&lt;__T0, __T1, __T2, __T3&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T2: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T3: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::txn_builder::FragmentationSnafu"]},{"text":"impl&lt;__T0, __T1, __T2, __T3&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TooManyOutputsSnafu.html\" title=\"struct seahorse::txn_builder::TooManyOutputsSnafu\">TooManyOutputsSnafu</a>&lt;__T0, __T1, __T2, __T3&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T2: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T3: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::txn_builder::TooManyOutputsSnafu"]},{"text":"impl&lt;__T0, __T1, __T2, __T3, __T4&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InvalidSizeSnafu.html\" title=\"struct seahorse::txn_builder::InvalidSizeSnafu\">InvalidSizeSnafu</a>&lt;__T0, __T1, __T2, __T3, __T4&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T2: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T3: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T4: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::txn_builder::InvalidSizeSnafu"]},{"text":"impl&lt;__T0, __T1&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.NoFitKeySnafu.html\" title=\"struct seahorse::txn_builder::NoFitKeySnafu\">NoFitKeySnafu</a>&lt;__T0, __T1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::txn_builder::NoFitKeySnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.CryptoSnafu.html\" title=\"struct seahorse::txn_builder::CryptoSnafu\">CryptoSnafu</a>","synthetic":true,"types":["seahorse::txn_builder::CryptoSnafu"]},{"text":"impl&lt;__T0, __T1&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InvalidAuditorKeySnafu.html\" title=\"struct seahorse::txn_builder::InvalidAuditorKeySnafu\">InvalidAuditorKeySnafu</a>&lt;__T0, __T1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::txn_builder::InvalidAuditorKeySnafu"]},{"text":"impl&lt;__T0, __T1&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InvalidFreezerKeySnafu.html\" title=\"struct seahorse::txn_builder::InvalidFreezerKeySnafu\">InvalidFreezerKeySnafu</a>&lt;__T0, __T1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::txn_builder::InvalidFreezerKeySnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.RecordInfo.html\" title=\"struct seahorse::txn_builder::RecordInfo\">RecordInfo</a>","synthetic":true,"types":["seahorse::txn_builder::RecordInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.RecordDatabase.html\" title=\"struct seahorse::txn_builder::RecordDatabase\">RecordDatabase</a>","synthetic":true,"types":["seahorse::txn_builder::RecordDatabase"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"seahorse/txn_builder/enum.TransactionStatus.html\" title=\"enum seahorse::txn_builder::TransactionStatus\">TransactionStatus</a>","synthetic":true,"types":["seahorse::txn_builder::TransactionStatus"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionReceipt.html\" title=\"struct seahorse::txn_builder::TransactionReceipt\">TransactionReceipt</a>&lt;L&gt;","synthetic":true,"types":["seahorse::txn_builder::TransactionReceipt"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.PendingTransaction.html\" title=\"struct seahorse::txn_builder::PendingTransaction\">PendingTransaction</a>&lt;L&gt;","synthetic":true,"types":["seahorse::txn_builder::PendingTransaction"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionAwaitingMemos.html\" title=\"struct seahorse::txn_builder::TransactionAwaitingMemos\">TransactionAwaitingMemos</a>&lt;L&gt;","synthetic":true,"types":["seahorse::txn_builder::TransactionAwaitingMemos"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionUID.html\" title=\"struct seahorse::txn_builder::TransactionUID\">TransactionUID</a>&lt;L&gt;","synthetic":true,"types":["seahorse::txn_builder::TransactionUID"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionDatabase.html\" title=\"struct seahorse::txn_builder::TransactionDatabase\">TransactionDatabase</a>&lt;L&gt;","synthetic":true,"types":["seahorse::txn_builder::TransactionDatabase"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionHistoryEntry.html\" title=\"struct seahorse::txn_builder::TransactionHistoryEntry\">TransactionHistoryEntry</a>&lt;L&gt;","synthetic":true,"types":["seahorse::txn_builder::TransactionHistoryEntry"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionInfo.html\" title=\"struct seahorse::txn_builder::TransactionInfo\">TransactionInfo</a>&lt;L&gt;","synthetic":true,"types":["seahorse::txn_builder::TransactionInfo"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransferSpec.html\" title=\"struct seahorse::txn_builder::TransferSpec\">TransferSpec</a>&lt;'a&gt;","synthetic":true,"types":["seahorse::txn_builder::TransferSpec"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionState.html\" title=\"struct seahorse::txn_builder::TransactionState\">TransactionState</a>&lt;L&gt;","synthetic":true,"types":["seahorse::txn_builder::TransactionState"]},{"text":"impl&lt;L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"seahorse/enum.WalletError.html\" title=\"enum seahorse::WalletError\">WalletError</a>&lt;L&gt;","synthetic":true,"types":["seahorse::WalletError"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.UndefinedAssetSnafu.html\" title=\"struct seahorse::UndefinedAssetSnafu\">UndefinedAssetSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::UndefinedAssetSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidBlockSnafu.html\" title=\"struct seahorse::InvalidBlockSnafu\">InvalidBlockSnafu</a>","synthetic":true,"types":["seahorse::InvalidBlockSnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.NullifierAlreadyPublishedSnafu.html\" title=\"struct seahorse::NullifierAlreadyPublishedSnafu\">NullifierAlreadyPublishedSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::NullifierAlreadyPublishedSnafu"]},{"text":"impl&lt;__T0, __T1&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.BadMerkleProofSnafu.html\" title=\"struct seahorse::BadMerkleProofSnafu\">BadMerkleProofSnafu</a>&lt;__T0, __T1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;__T1: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::BadMerkleProofSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.TimedOutSnafu.html\" title=\"struct seahorse::TimedOutSnafu\">TimedOutSnafu</a>","synthetic":true,"types":["seahorse::TimedOutSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.CancelledSnafu.html\" title=\"struct seahorse::CancelledSnafu\">CancelledSnafu</a>","synthetic":true,"types":["seahorse::CancelledSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.CryptoSnafu.html\" title=\"struct seahorse::CryptoSnafu\">CryptoSnafu</a>","synthetic":true,"types":["seahorse::CryptoSnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidAddressSnafu.html\" title=\"struct seahorse::InvalidAddressSnafu\">InvalidAddressSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::InvalidAddressSnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.AssetNotAuditableSnafu.html\" title=\"struct seahorse::AssetNotAuditableSnafu\">AssetNotAuditableSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::AssetNotAuditableSnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.AssetNotFreezableSnafu.html\" title=\"struct seahorse::AssetNotFreezableSnafu\">AssetNotFreezableSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::AssetNotFreezableSnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.AssetNotMintableSnafu.html\" title=\"struct seahorse::AssetNotMintableSnafu\">AssetNotMintableSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::AssetNotMintableSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.ClientConfigSnafu.html\" title=\"struct seahorse::ClientConfigSnafu\">ClientConfigSnafu</a>","synthetic":true,"types":["seahorse::ClientConfigSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.PersistenceSnafu.html\" title=\"struct seahorse::PersistenceSnafu\">PersistenceSnafu</a>","synthetic":true,"types":["seahorse::PersistenceSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.IoSnafu.html\" title=\"struct seahorse::IoSnafu\">IoSnafu</a>","synthetic":true,"types":["seahorse::IoSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.BincodeSnafu.html\" title=\"struct seahorse::BincodeSnafu\">BincodeSnafu</a>","synthetic":true,"types":["seahorse::BincodeSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.EncryptionSnafu.html\" title=\"struct seahorse::EncryptionSnafu\">EncryptionSnafu</a>","synthetic":true,"types":["seahorse::EncryptionSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.MnemonicSnafu.html\" title=\"struct seahorse::MnemonicSnafu\">MnemonicSnafu</a>","synthetic":true,"types":["seahorse::MnemonicSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.KeySnafu.html\" title=\"struct seahorse::KeySnafu\">KeySnafu</a>","synthetic":true,"types":["seahorse::KeySnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.NoSuchAccountSnafu.html\" title=\"struct seahorse::NoSuchAccountSnafu\">NoSuchAccountSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::NoSuchAccountSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.CannotDecryptMemoSnafu.html\" title=\"struct seahorse::CannotDecryptMemoSnafu\">CannotDecryptMemoSnafu</a>","synthetic":true,"types":["seahorse::CannotDecryptMemoSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.TransactionSnafu.html\" title=\"struct seahorse::TransactionSnafu\">TransactionSnafu</a>","synthetic":true,"types":["seahorse::TransactionSnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.UserKeyExistsSnafu.html\" title=\"struct seahorse::UserKeyExistsSnafu\">UserKeyExistsSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::UserKeyExistsSnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.AssetVerificationSnafu.html\" title=\"struct seahorse::AssetVerificationSnafu\">AssetVerificationSnafu</a>","synthetic":true,"types":["seahorse::AssetVerificationSnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.FailedSnafu.html\" title=\"struct seahorse::FailedSnafu\">FailedSnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::FailedSnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidFreezerKeySnafu.html\" title=\"struct seahorse::InvalidFreezerKeySnafu\">InvalidFreezerKeySnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::InvalidFreezerKeySnafu"]},{"text":"impl&lt;__T0&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidAuditorKeySnafu.html\" title=\"struct seahorse::InvalidAuditorKeySnafu\">InvalidAuditorKeySnafu</a>&lt;__T0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;__T0: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["seahorse::InvalidAuditorKeySnafu"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.KeyStreamState.html\" title=\"struct seahorse::KeyStreamState\">KeyStreamState</a>","synthetic":true,"types":["seahorse::KeyStreamState"]},{"text":"impl&lt;'a, L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.WalletState.html\" title=\"struct seahorse::WalletState\">WalletState</a>&lt;'a, L&gt;","synthetic":true,"types":["seahorse::WalletState"]},{"text":"impl&lt;'a, 'l, L, Backend:&nbsp;?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.StorageTransaction.html\" title=\"struct seahorse::StorageTransaction\">StorageTransaction</a>&lt;'a, 'l, L, Backend&gt;","synthetic":true,"types":["seahorse::StorageTransaction"]},{"text":"impl&lt;'a, L, Backend&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.WalletSession.html\" title=\"struct seahorse::WalletSession\">WalletSession</a>&lt;'a, L, Backend&gt;","synthetic":true,"types":["seahorse::WalletSession"]},{"text":"impl&lt;'a, Backend, L&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.Wallet.html\" title=\"struct seahorse::Wallet\">Wallet</a>&lt;'a, Backend, L&gt;","synthetic":true,"types":["seahorse::Wallet"]},{"text":"impl&lt;'a, L, Backend&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"seahorse/struct.WalletSharedState.html\" title=\"struct seahorse::WalletSharedState\">WalletSharedState</a>&lt;'a, L, Backend&gt;","synthetic":true,"types":["seahorse::WalletSharedState"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()