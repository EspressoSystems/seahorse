use super::*;
use rand::distributions::{Alphanumeric, DistString};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reef::cap;
use tempdir::TempDir;

#[test]
fn test_create_loader() {
    let dir = TempDir::new("create-loader").unwrap();
    let mut rng = ChaChaRng::from_seed([0; 32]);
    let mnemonic = KeyTree::random(&mut rng).1;
    let password = Alphanumeric.sample_string(&mut rng, 16);

    // First create some keystore metadata.
    let mut loader = CreateLoader::new(
        &mut rng,
        dir.path().to_owned(),
        mnemonic.clone(),
        password.clone(),
    );
    assert_eq!(
        KeystoreLoader::<cap::Ledger>::location(&loader),
        dir.path().to_owned()
    );
    let (meta, key) = KeystoreLoader::<cap::Ledger>::create(&mut loader).unwrap();
    assert_eq!(
        meta.decrypt_mnemonic(password.as_bytes()),
        Some(mnemonic.clone())
    );
    assert!(meta.check_password(password.as_bytes()));
    assert!(meta.check_mnemonic(&mnemonic));

    // Load it back with a different loader. Make sure we get the same result, and the metadata
    // isn't changed.
    let mut loaded = meta.clone();
    let mut loader = CreateLoader::new(
        &mut rng,
        dir.path().to_owned(),
        mnemonic.clone(),
        password.clone(),
    );
    assert_eq!(
        key,
        KeystoreLoader::<cap::Ledger>::load(&mut loader, &mut loaded).unwrap()
    );
    assert_eq!(meta, loaded);

    // Check that an exclusive loader fails with existing metadata.
    let mut loader = CreateLoader::exclusive(
        &mut rng,
        dir.path().to_owned(),
        mnemonic.clone(),
        password.clone(),
    );
    KeystoreLoader::<cap::Ledger>::load(&mut loader, &mut loaded).unwrap_err();
    assert_eq!(loaded, meta);

    // Check that we fail to open an existing keystore with the wrong password.
    let password = Alphanumeric.sample_string(&mut rng, 16);
    let mut loader = CreateLoader::new(
        &mut rng,
        dir.path().to_owned(),
        mnemonic.clone(),
        password.clone(),
    );
    KeystoreLoader::<cap::Ledger>::load(&mut loader, &mut loaded).unwrap_err();
    assert_eq!(loaded, meta);
}

#[test]
fn test_login_loader() {
    let dir = TempDir::new("login-loader").unwrap();
    let mut rng = ChaChaRng::from_seed([0; 32]);
    let mnemonic = KeyTree::random(&mut rng).1;
    let password = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

    // First create some keystore metadata.
    let meta = MnemonicPasswordLogin::new::<cap::Ledger>(&mut rng, &mnemonic, password.as_bytes())
        .unwrap();

    // Check that we can correctly load a key tree from this metadata using only a password.
    let mut loader = LoginLoader::new(dir.path().to_owned(), password.clone());
    let mut loaded = meta.clone();
    let key = KeystoreLoader::<cap::Ledger>::load(&mut loader, &mut loaded).unwrap();
    assert_eq!(loaded, meta);
    assert_eq!(key, KeyTree::from_mnemonic(&mnemonic));

    // Check that loading fails with the incorrect password.
    let password = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    let mut loader = LoginLoader::new(dir.path().to_owned(), password.clone());
    KeystoreLoader::<cap::Ledger>::load(&mut loader, &mut loaded).unwrap_err();
    assert_eq!(loaded, meta);
}

#[test]
fn test_recovery_loader() {
    let dir = TempDir::new("recovery-loader").unwrap();
    let mut rng = ChaChaRng::from_seed([0; 32]);
    let mnemonic = KeyTree::random(&mut rng).1;
    let password = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

    // If no keystore metadata exists, the loader creates a new keystore with the given mnemonic and
    // password.
    let mut loader = RecoveryLoader::new(
        &mut rng,
        dir.path().to_owned(),
        mnemonic.clone(),
        password.clone(),
    );
    assert_eq!(
        KeystoreLoader::<cap::Ledger>::location(&loader),
        dir.path().to_owned()
    );
    let (mut meta, key) = KeystoreLoader::<cap::Ledger>::create(&mut loader).unwrap();
    assert_eq!(
        meta.decrypt_mnemonic(password.as_bytes()),
        Some(mnemonic.clone())
    );
    assert!(meta.check_password(password.as_bytes()));
    assert!(meta.check_mnemonic(&mnemonic));

    // If keystore files exist, we can load them back and change the password.
    let password = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    let mut loader = RecoveryLoader::new(
        &mut rng,
        dir.path().to_owned(),
        mnemonic.clone(),
        password.clone(),
    );
    assert_eq!(
        key,
        KeystoreLoader::<cap::Ledger>::load(&mut loader, &mut meta).unwrap()
    );
    assert_eq!(
        meta.decrypt_mnemonic(password.as_bytes()),
        Some(mnemonic.clone())
    );
    assert!(meta.check_password(password.as_bytes()));
    assert!(meta.check_mnemonic(&mnemonic));

    // Loading fails if we use the wrong mnemonic.
    let mnemonic = KeyTree::random(&mut rng).1;
    let mut loader = RecoveryLoader::new(
        &mut rng,
        dir.path().to_owned(),
        mnemonic.clone(),
        password.clone(),
    );
    KeystoreLoader::<cap::Ledger>::load(&mut loader, &mut meta).unwrap_err();
}
