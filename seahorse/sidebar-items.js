initSidebarItems({"enum":[["RoleKeyPair",""],["WalletError",""]],"fn":[["new_key_pair",""]],"macro":[["cli_write","Convenience macro for panicking if output fails."],["cli_writeln","Convenience macro for panicking if output fails."],["command","Create a [Command] from a help string and a function."],["count",""]],"mod":[["cli","The generic CAP Wallet frontend"],["encryption","Symmetric encryption for locally persistent wallet data."],["events","Event definitions for ledger state changes."],["hd","Hierarchical deterministic key generation"],["io","I/O interface for the CLI."],["loader","Traits and types for creating and loading wallets."],["persistence","Ledger-agnostic implementation of [WalletStorage]."],["reader","Interactive input."],["txn_builder","Transaction building."]],"struct":[["AssetInfo","Details about an asset type."],["AssetNotAuditable","SNAFU context selector for the `WalletError::AssetNotAuditable` variant"],["AssetNotFreezable","SNAFU context selector for the `WalletError::AssetNotFreezable` variant"],["AssetNotMintable","SNAFU context selector for the `WalletError::AssetNotMintable` variant"],["BackgroundKeyScan","An in-progress scan of past ledger events."],["BadMerkleProof","SNAFU context selector for the `WalletError::BadMerkleProof` variant"],["BincodeError","SNAFU context selector for the `WalletError::BincodeError` variant"],["Cancelled","SNAFU context selector for the `WalletError::Cancelled` variant"],["CannotDecryptMemo","SNAFU context selector for the `WalletError::CannotDecryptMemo` variant"],["ClientConfigError","SNAFU context selector for the `WalletError::ClientConfigError` variant"],["CryptoError","SNAFU context selector for the `WalletError::CryptoError` variant"],["EncryptionError","SNAFU context selector for the `WalletError::EncryptionError` variant"],["Failed","SNAFU context selector for the `WalletError::Failed` variant"],["InvalidAddress","SNAFU context selector for the `WalletError::InvalidAddress` variant"],["InvalidBlock","SNAFU context selector for the `WalletError::InvalidBlock` variant"],["IoError","SNAFU context selector for the `WalletError::IoError` variant"],["KeyError","SNAFU context selector for the `WalletError::KeyError` variant"],["KeyStreamState","The number of keys of each type which have been generated."],["MintInfo","Information required to mint an asset."],["NoSuchAccount","SNAFU context selector for the `WalletError::NoSuchAccount` variant"],["NullifierAlreadyPublished","SNAFU context selector for the `WalletError::NullifierAlreadyPublished` variant"],["PersistenceError","SNAFU context selector for the `WalletError::PersistenceError` variant"],["StorageTransaction","Interface for atomic storage transactions."],["TimedOut","SNAFU context selector for the `WalletError::TimedOut` variant"],["TransactionError","SNAFU context selector for the `WalletError::TransactionError` variant"],["UndefinedAsset","SNAFU context selector for the `WalletError::UndefinedAsset` variant"],["UserKeyExists","SNAFU context selector for the `WalletError::UserKeyExists` variant"],["Wallet","The generic CAP wallet implementation."],["WalletSession","Transient state derived from the persistent [WalletState]."],["WalletSharedState","Wallet state which is shared with event handling threads."],["WalletState","The data that determines a wallet."]],"trait":[["Captures",""],["SendFuture",""],["WalletBackend","The interface required by the wallet from a specific network/ledger implementation."],["WalletStorage","The interface required by the wallet from the persistence layer."]]});