initSidebarItems({"enum":[["KeystoreError",""]],"fn":[["new_key_pair",""]],"macro":[["cli_write","Convenience macro for panicking if output fails."],["cli_writeln","Convenience macro for panicking if output fails."],["command","Create a [Command] from a help string and a function."],["count",""]],"mod":[["accounts",""],["asset_library","Collections of and information on CAP assets."],["assets","The assets module."],["cli","The generic CAP Keystore frontend"],["encryption","Symmetric encryption for locally persistent keystore data."],["events","Event definitions for ledger state changes."],["hd","Hierarchical deterministic key generation"],["io","I/O interface for the CLI."],["key_value_store","The key-value store."],["loader","Traits and types for creating and loading keystores."],["persistence","Ledger-agnostic implementation of [KeystoreStorage]."],["reader","Interactive input."],["sparse_merkle_tree","A Merkle tree which supports arbitrarily sparse representations."],["transactions","The transaction module."],["txn_builder","Transaction building."]],"struct":[["AssetNotFreezableSnafu","SNAFU context selector for the `KeystoreError::AssetNotFreezable` variant"],["AssetNotMintableSnafu","SNAFU context selector for the `KeystoreError::AssetNotMintable` variant"],["AssetNotViewableSnafu","SNAFU context selector for the `KeystoreError::AssetNotViewable` variant"],["AssetVerificationSnafu","SNAFU context selector for the `KeystoreError::AssetVerificationError` variant"],["BadMerkleProofSnafu","SNAFU context selector for the `KeystoreError::BadMerkleProof` variant"],["BincodeSnafu","SNAFU context selector for the `KeystoreError::BincodeError` variant"],["CancelledSnafu","SNAFU context selector for the `KeystoreError::Cancelled` variant"],["CannotDecryptMemoSnafu","SNAFU context selector for the `KeystoreError::CannotDecryptMemo` variant"],["ClientConfigSnafu","SNAFU context selector for the `KeystoreError::ClientConfigError` variant"],["CryptoSnafu","SNAFU context selector for the `KeystoreError::CryptoError` variant"],["EncryptionSnafu","SNAFU context selector for the `KeystoreError::EncryptionError` variant"],["FailedSnafu","SNAFU context selector for the `KeystoreError::Failed` variant"],["InvalidAddressSnafu","SNAFU context selector for the `KeystoreError::InvalidAddress` variant"],["InvalidBlockSnafu","SNAFU context selector for the `KeystoreError::InvalidBlock` variant"],["InvalidFreezerKeySnafu","SNAFU context selector for the `KeystoreError::InvalidFreezerKey` variant"],["InvalidViewerKeySnafu","SNAFU context selector for the `KeystoreError::InvalidViewerKey` variant"],["IoSnafu","SNAFU context selector for the `KeystoreError::IoError` variant"],["KeySnafu","SNAFU context selector for the `KeystoreError::KeyError` variant"],["KeyStreamState","The number of keys of each type which have been generated."],["KeyValueStoreSnafu","SNAFU context selector for the `KeystoreError::KeyValueStoreError` variant"],["Keystore","The generic CAP keystore implementation."],["KeystoreSession","Transient state derived from the persistent [KeystoreState]."],["KeystoreSharedState","Keystore state which is shared with event handling threads."],["KeystoreState","The data that determines a keystore."],["MnemonicSnafu","SNAFU context selector for the `KeystoreError::MnemonicError` variant"],["NoSuchAccountSnafu","SNAFU context selector for the `KeystoreError::NoSuchAccount` variant"],["NullifierAlreadyPublishedSnafu","SNAFU context selector for the `KeystoreError::NullifierAlreadyPublished` variant"],["PersistenceSnafu","SNAFU context selector for the `KeystoreError::PersistenceError` variant"],["StorageTransaction","Interface for atomic storage transactions."],["TimedOutSnafu","SNAFU context selector for the `KeystoreError::TimedOut` variant"],["TransactionSnafu","SNAFU context selector for the `KeystoreError::TransactionError` variant"],["UndefinedAssetSnafu","SNAFU context selector for the `KeystoreError::UndefinedAsset` variant"],["UserKeyExistsSnafu","SNAFU context selector for the `KeystoreError::UserKeyExists` variant"]],"trait":[["Captures",""],["KeystoreBackend","The interface required by the keystore from a specific network/ledger implementation."],["SendFuture",""]]});