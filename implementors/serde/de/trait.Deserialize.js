(function() {var implementors = {};
implementors["seahorse"] = [{"text":"impl&lt;'de, L:&nbsp;Ledger, Key:&nbsp;KeyPair + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/accounts/struct.Account.html\" title=\"struct seahorse::accounts::Account\">Account</a>&lt;L, Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,&nbsp;</span>","synthetic":false,"types":["seahorse::accounts::Account"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/assets/struct.Icon.html\" title=\"struct seahorse::assets::Icon\">Icon</a>","synthetic":false,"types":["seahorse::assets::Icon"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/assets/struct.MintInfo.html\" title=\"struct seahorse::assets::MintInfo\">MintInfo</a>","synthetic":false,"types":["seahorse::assets::MintInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/assets/struct.VerifiedAssetLibrary.html\" title=\"struct seahorse::assets::VerifiedAssetLibrary\">VerifiedAssetLibrary</a>","synthetic":false,"types":["seahorse::assets::VerifiedAssetLibrary"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/assets/struct.Asset.html\" title=\"struct seahorse::assets::Asset\">Asset</a>","synthetic":false,"types":["seahorse::assets::Asset"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/cli/struct.CLIMerklePath.html\" title=\"struct seahorse::cli::CLIMerklePath\">CLIMerklePath</a>","synthetic":false,"types":["seahorse::cli::CLIMerklePath"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/encryption/struct.CipherText.html\" title=\"struct seahorse::encryption::CipherText\">CipherText</a>","synthetic":false,"types":["seahorse::encryption::CipherText"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"seahorse/events/enum.LedgerEvent.html\" title=\"enum seahorse::events::LedgerEvent\">LedgerEvent</a>&lt;L&gt;","synthetic":false,"types":["seahorse::events::LedgerEvent"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/events/struct.EventIndex.html\" title=\"struct seahorse::events::EventIndex\">EventIndex</a>","synthetic":false,"types":["seahorse::events::EventIndex"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/ledger_state/struct.RecordAmount.html\" title=\"struct seahorse::ledger_state::RecordAmount\">RecordAmount</a>","synthetic":false,"types":["seahorse::ledger_state::RecordAmount"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"seahorse/ledger_state/enum.TransactionStatus.html\" title=\"enum seahorse::ledger_state::TransactionStatus\">TransactionStatus</a>","synthetic":false,"types":["seahorse::ledger_state::TransactionStatus"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/ledger_state/struct.TransactionUID.html\" title=\"struct seahorse::ledger_state::TransactionUID\">TransactionUID</a>&lt;L&gt;","synthetic":false,"types":["seahorse::ledger_state::TransactionUID"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/ledger_state/struct.LedgerState.html\" title=\"struct seahorse::ledger_state::LedgerState\">LedgerState</a>&lt;L&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;L: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["seahorse::ledger_state::LedgerState"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/loader/struct.MnemonicPasswordLogin.html\" title=\"struct seahorse::loader::MnemonicPasswordLogin\">MnemonicPasswordLogin</a>","synthetic":false,"types":["seahorse::loader::MnemonicPasswordLogin"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/lw_merkle_tree/struct.LWMerkleTree.html\" title=\"struct seahorse::lw_merkle_tree::LWMerkleTree\">LWMerkleTree</a>","synthetic":false,"types":["seahorse::lw_merkle_tree::LWMerkleTree"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/records/struct.Record.html\" title=\"struct seahorse::records::Record\">Record</a>","synthetic":false,"types":["seahorse::records::Record"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/transactions/struct.SignedMemos.html\" title=\"struct seahorse::transactions::SignedMemos\">SignedMemos</a>","synthetic":false,"types":["seahorse::transactions::SignedMemos"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/transactions/struct.Transaction.html\" title=\"struct seahorse::transactions::Transaction\">Transaction</a>&lt;L&gt;","synthetic":false,"types":["seahorse::transactions::Transaction"]},{"text":"impl&lt;'de, L:&nbsp;Ledger&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.147/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"seahorse/transactions/struct.TransactionParams.html\" title=\"struct seahorse::transactions::TransactionParams\">TransactionParams</a>&lt;L&gt;","synthetic":false,"types":["seahorse::transactions::TransactionParams"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()