(function() {var implementors = {};
implementors["seahorse"] = [{"text":"impl&lt;'de, L:&nbsp;Ledger, Key&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/accounts/struct.Account.html\" title=\"struct seahorse::accounts::Account\">Account</a>&lt;L, Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;L: Ledger,<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,&nbsp;</span>","synthetic":false,"types":["seahorse::accounts::Account"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/asset_library/struct.Icon.html\" title=\"struct seahorse::asset_library::Icon\">Icon</a>","synthetic":false,"types":["seahorse::asset_library::Icon"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/asset_library/struct.AssetInfo.html\" title=\"struct seahorse::asset_library::AssetInfo\">AssetInfo</a>","synthetic":false,"types":["seahorse::asset_library::AssetInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/asset_library/struct.MintInfo.html\" title=\"struct seahorse::asset_library::MintInfo\">MintInfo</a>","synthetic":false,"types":["seahorse::asset_library::MintInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/asset_library/struct.VerifiedAssetLibrary.html\" title=\"struct seahorse::asset_library::VerifiedAssetLibrary\">VerifiedAssetLibrary</a>","synthetic":false,"types":["seahorse::asset_library::VerifiedAssetLibrary"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/encryption/struct.CipherText.html\" title=\"struct seahorse::encryption::CipherText\">CipherText</a>","synthetic":false,"types":["seahorse::encryption::CipherText"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"seahorse/events/enum.LedgerEvent.html\" title=\"enum seahorse::events::LedgerEvent\">LedgerEvent</a>&lt;L&gt;","synthetic":false,"types":["seahorse::events::LedgerEvent"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/events/struct.EventIndex.html\" title=\"struct seahorse::events::EventIndex\">EventIndex</a>","synthetic":false,"types":["seahorse::events::EventIndex"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/loader/struct.MnemonicPasswordLogin.html\" title=\"struct seahorse::loader::MnemonicPasswordLogin\">MnemonicPasswordLogin</a>","synthetic":false,"types":["seahorse::loader::MnemonicPasswordLogin"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/sparse_merkle_tree/struct.SparseMerkleTree.html\" title=\"struct seahorse::sparse_merkle_tree::SparseMerkleTree\">SparseMerkleTree</a>","synthetic":false,"types":["seahorse::sparse_merkle_tree::SparseMerkleTree"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.RecordAmount.html\" title=\"struct seahorse::txn_builder::RecordAmount\">RecordAmount</a>","synthetic":false,"types":["seahorse::txn_builder::RecordAmount"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.RecordInfo.html\" title=\"struct seahorse::txn_builder::RecordInfo\">RecordInfo</a>","synthetic":false,"types":["seahorse::txn_builder::RecordInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.RecordDatabase.html\" title=\"struct seahorse::txn_builder::RecordDatabase\">RecordDatabase</a>","synthetic":false,"types":["seahorse::txn_builder::RecordDatabase"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionReceipt.html\" title=\"struct seahorse::txn_builder::TransactionReceipt\">TransactionReceipt</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionReceipt"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.PendingTransaction.html\" title=\"struct seahorse::txn_builder::PendingTransaction\">PendingTransaction</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::PendingTransaction"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionAwaitingMemos.html\" title=\"struct seahorse::txn_builder::TransactionAwaitingMemos\">TransactionAwaitingMemos</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionAwaitingMemos"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionUID.html\" title=\"struct seahorse::txn_builder::TransactionUID\">TransactionUID</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionUID"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionDatabase.html\" title=\"struct seahorse::txn_builder::TransactionDatabase\">TransactionDatabase</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionDatabase"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionHistoryEntry.html\" title=\"struct seahorse::txn_builder::TransactionHistoryEntry\">TransactionHistoryEntry</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionHistoryEntry"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionInfo.html\" title=\"struct seahorse::txn_builder::TransactionInfo\">TransactionInfo</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionInfo"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/txn_builder/struct.TransactionState.html\" title=\"struct seahorse::txn_builder::TransactionState\">TransactionState</a>&lt;L&gt;","synthetic":false,"types":["seahorse::txn_builder::TransactionState"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/struct.KeyStreamState.html\" title=\"struct seahorse::KeyStreamState\">KeyStreamState</a>","synthetic":false,"types":["seahorse::KeyStreamState"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()