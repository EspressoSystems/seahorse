(function() {var implementors = {};
implementors["seahorse"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.AssetInfo.html\" title=\"struct seahorse::AssetInfo\">AssetInfo</a>","synthetic":false,"types":["seahorse::asset_library::AssetInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.MintInfo.html\" title=\"struct seahorse::MintInfo\">MintInfo</a>","synthetic":false,"types":["seahorse::asset_library::MintInfo"]},{"text":"impl&lt;Rng:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://rust-random.github.io/rand/rand_core/trait.CryptoRng.html\" title=\"trait rand_core::CryptoRng\">CryptoRng</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/encryption/struct.Cipher.html\" title=\"struct seahorse::encryption::Cipher\">Cipher</a>&lt;Rng&gt;","synthetic":false,"types":["seahorse::encryption::Cipher"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/encryption/struct.CipherText.html\" title=\"struct seahorse::encryption::CipherText\">CipherText</a>","synthetic":false,"types":["seahorse::encryption::CipherText"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"seahorse/events/enum.LedgerEvent.html\" title=\"enum seahorse::events::LedgerEvent\">LedgerEvent</a>&lt;L&gt;","synthetic":false,"types":["seahorse::events::LedgerEvent"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/events/struct.EventIndex.html\" title=\"struct seahorse::events::EventIndex\">EventIndex</a>","synthetic":false,"types":["seahorse::events::EventIndex"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"seahorse/events/enum.EventSource.html\" title=\"enum seahorse::events::EventSource\">EventSource</a>","synthetic":false,"types":["seahorse::events::EventSource"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/hd/struct.KeyTree.html\" title=\"struct seahorse::hd::KeyTree\">KeyTree</a>","synthetic":false,"types":["seahorse::hd::KeyTree"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/hd/struct.Key.html\" title=\"struct seahorse::hd::Key\">Key</a>","synthetic":false,"types":["seahorse::hd::Key"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/io/struct.SharedIO.html\" title=\"struct seahorse::io::SharedIO\">SharedIO</a>","synthetic":false,"types":["seahorse::io::SharedIO"]},{"text":"impl&lt;S:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/io/struct.Tee.html\" title=\"struct seahorse::io::Tee\">Tee</a>&lt;S&gt;","synthetic":false,"types":["seahorse::io::Tee"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/loader/struct.LoaderMetadata.html\" title=\"struct seahorse::loader::LoaderMetadata\">LoaderMetadata</a>","synthetic":false,"types":["seahorse::loader::LoaderMetadata"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"seahorse/reader/enum.Reader.html\" title=\"enum seahorse::reader::Reader\">Reader</a>","synthetic":false,"types":["seahorse::reader::Reader"]},{"text":"impl&lt;S:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://docs.rs/zeroize/1.3.0/zeroize/trait.Zeroize.html\" title=\"trait zeroize::Zeroize\">Zeroize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/hd/struct.Secret.html\" title=\"struct seahorse::hd::Secret\">Secret</a>&lt;S&gt;","synthetic":false,"types":["seahorse::secret::Secret"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T2:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InsufficientBalance.html\" title=\"struct seahorse::txn_builder::InsufficientBalance\">InsufficientBalance</a>&lt;__T0, __T1, __T2&gt;","synthetic":false,"types":["seahorse::txn_builder::InsufficientBalance"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T2:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T3:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.Fragmentation.html\" title=\"struct seahorse::txn_builder::Fragmentation\">Fragmentation</a>&lt;__T0, __T1, __T2, __T3&gt;","synthetic":false,"types":["seahorse::txn_builder::Fragmentation"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T2:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T3:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TooManyOutputs.html\" title=\"struct seahorse::txn_builder::TooManyOutputs\">TooManyOutputs</a>&lt;__T0, __T1, __T2, __T3&gt;","synthetic":false,"types":["seahorse::txn_builder::TooManyOutputs"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T2:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T3:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T4:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InvalidSize.html\" title=\"struct seahorse::txn_builder::InvalidSize\">InvalidSize</a>&lt;__T0, __T1, __T2, __T3, __T4&gt;","synthetic":false,"types":["seahorse::txn_builder::InvalidSize"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.NoFitKey.html\" title=\"struct seahorse::txn_builder::NoFitKey\">NoFitKey</a>&lt;__T0, __T1&gt;","synthetic":false,"types":["seahorse::txn_builder::NoFitKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.CryptoError.html\" title=\"struct seahorse::txn_builder::CryptoError\">CryptoError</a>","synthetic":false,"types":["seahorse::txn_builder::CryptoError"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InvalidAuditorKey.html\" title=\"struct seahorse::txn_builder::InvalidAuditorKey\">InvalidAuditorKey</a>&lt;__T0, __T1&gt;","synthetic":false,"types":["seahorse::txn_builder::InvalidAuditorKey"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.InvalidFreezerKey.html\" title=\"struct seahorse::txn_builder::InvalidFreezerKey\">InvalidFreezerKey</a>&lt;__T0, __T1&gt;","synthetic":false,"types":["seahorse::txn_builder::InvalidFreezerKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.RecordInfo.html\" title=\"struct seahorse::txn_builder::RecordInfo\">RecordInfo</a>","synthetic":false,"types":["seahorse::txn_builder::RecordInfo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.RecordDatabase.html\" title=\"struct seahorse::txn_builder::RecordDatabase\">RecordDatabase</a>","synthetic":false,"types":["seahorse::txn_builder::RecordDatabase"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"seahorse/txn_builder/enum.TransactionStatus.html\" title=\"enum seahorse::txn_builder::TransactionStatus\">TransactionStatus</a>","synthetic":false,"types":["seahorse::txn_builder::TransactionStatus"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionReceipt.html\" title=\"struct seahorse::txn_builder::TransactionReceipt\">TransactionReceipt</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionReceipt"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.PendingTransaction.html\" title=\"struct seahorse::txn_builder::PendingTransaction\">PendingTransaction</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::PendingTransaction"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionAwaitingMemos.html\" title=\"struct seahorse::txn_builder::TransactionAwaitingMemos\">TransactionAwaitingMemos</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionAwaitingMemos"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionUID.html\" title=\"struct seahorse::txn_builder::TransactionUID\">TransactionUID</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionUID"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionDatabase.html\" title=\"struct seahorse::txn_builder::TransactionDatabase\">TransactionDatabase</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionDatabase"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionHistoryEntry.html\" title=\"struct seahorse::txn_builder::TransactionHistoryEntry\">TransactionHistoryEntry</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionHistoryEntry"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionInfo.html\" title=\"struct seahorse::txn_builder::TransactionInfo\">TransactionInfo</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionInfo"]},{"text":"impl&lt;L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionState.html\" title=\"struct seahorse::txn_builder::TransactionState\">TransactionState</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionState"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.UndefinedAsset.html\" title=\"struct seahorse::UndefinedAsset\">UndefinedAsset</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::UndefinedAsset"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidBlock.html\" title=\"struct seahorse::InvalidBlock\">InvalidBlock</a>","synthetic":false,"types":["seahorse::InvalidBlock"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.NullifierAlreadyPublished.html\" title=\"struct seahorse::NullifierAlreadyPublished\">NullifierAlreadyPublished</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::NullifierAlreadyPublished"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, __T1:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.BadMerkleProof.html\" title=\"struct seahorse::BadMerkleProof\">BadMerkleProof</a>&lt;__T0, __T1&gt;","synthetic":false,"types":["seahorse::BadMerkleProof"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.TimedOut.html\" title=\"struct seahorse::TimedOut\">TimedOut</a>","synthetic":false,"types":["seahorse::TimedOut"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.Cancelled.html\" title=\"struct seahorse::Cancelled\">Cancelled</a>","synthetic":false,"types":["seahorse::Cancelled"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.CryptoError.html\" title=\"struct seahorse::CryptoError\">CryptoError</a>","synthetic":false,"types":["seahorse::CryptoError"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.InvalidAddress.html\" title=\"struct seahorse::InvalidAddress\">InvalidAddress</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::InvalidAddress"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.AssetNotAuditable.html\" title=\"struct seahorse::AssetNotAuditable\">AssetNotAuditable</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::AssetNotAuditable"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.AssetNotFreezable.html\" title=\"struct seahorse::AssetNotFreezable\">AssetNotFreezable</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::AssetNotFreezable"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.AssetNotMintable.html\" title=\"struct seahorse::AssetNotMintable\">AssetNotMintable</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::AssetNotMintable"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.ClientConfigError.html\" title=\"struct seahorse::ClientConfigError\">ClientConfigError</a>","synthetic":false,"types":["seahorse::ClientConfigError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.PersistenceError.html\" title=\"struct seahorse::PersistenceError\">PersistenceError</a>","synthetic":false,"types":["seahorse::PersistenceError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.IoError.html\" title=\"struct seahorse::IoError\">IoError</a>","synthetic":false,"types":["seahorse::IoError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.BincodeError.html\" title=\"struct seahorse::BincodeError\">BincodeError</a>","synthetic":false,"types":["seahorse::BincodeError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.EncryptionError.html\" title=\"struct seahorse::EncryptionError\">EncryptionError</a>","synthetic":false,"types":["seahorse::EncryptionError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.KeyError.html\" title=\"struct seahorse::KeyError\">KeyError</a>","synthetic":false,"types":["seahorse::KeyError"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.NoSuchAccount.html\" title=\"struct seahorse::NoSuchAccount\">NoSuchAccount</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::NoSuchAccount"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.CannotDecryptMemo.html\" title=\"struct seahorse::CannotDecryptMemo\">CannotDecryptMemo</a>","synthetic":false,"types":["seahorse::CannotDecryptMemo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.TransactionError.html\" title=\"struct seahorse::TransactionError\">TransactionError</a>","synthetic":false,"types":["seahorse::TransactionError"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.UserKeyExists.html\" title=\"struct seahorse::UserKeyExists\">UserKeyExists</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::UserKeyExists"]},{"text":"impl&lt;__T0:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.Failed.html\" title=\"struct seahorse::Failed\">Failed</a>&lt;__T0&gt;","synthetic":false,"types":["seahorse::Failed"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.BackgroundKeyScan.html\" title=\"struct seahorse::BackgroundKeyScan\">BackgroundKeyScan</a>","synthetic":false,"types":["seahorse::BackgroundKeyScan"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.KeyStreamState.html\" title=\"struct seahorse::KeyStreamState\">KeyStreamState</a>","synthetic":false,"types":["seahorse::KeyStreamState"]},{"text":"impl&lt;'a, L:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Ledger&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"seahorse/struct.WalletState.html\" title=\"struct seahorse::WalletState\">WalletState</a>&lt;'a, L&gt;","synthetic":false,"types":["seahorse::WalletState"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.56.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"seahorse/enum.RoleKeyPair.html\" title=\"enum seahorse::RoleKeyPair\">RoleKeyPair</a>","synthetic":false,"types":["seahorse::RoleKeyPair"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()