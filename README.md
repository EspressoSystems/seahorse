# Seahorse

A ledger-agnostic wallet toolkit for the [CAP](https://cap.docs.espressosys.com) protocol.

[Documentation](https://seahorse.docs.espressosys.com) is in progress.

## Usage

First, make sure you are implementing a decentralized ledger that follows the
[CAP](https://github.com/EspressoSystems/cap) protocol (possibly with some extra features). If not,
this is not the wallet you're looking for.

Next, add to your Cargo.toml:
```toml
reef = { git = "https://github.com/EspressoSystems/reef.git" }
seahorse = { git = "https://github.com/EspressoSystems/seahorse.git" }
```

Implement the [reef](https://github.com/EspressoSystems/reef) traits for your ledger (see
`reef::cap` for an example of implementing the traits, using the basic `cap` types). Implement the
`KeyStoreBackend` trait from this crate. This trait allows the generic wallet functionality to talk to
your specific network.

You can now instantiate `KeyStore` using your implementation of `KeyStoreBackend`. A generic
cryptocurrency wallet interface is available to you for building Rust applications. You can also use
the built-in CLI application (`cli::cli_main`) to interact with your wallet using a command line
REPL.

