# Seahorse

A ledger-agnostic wallet toolkit for the [CAP](https://github.com/EspressoSystems/cap) protocol.

Documentation is in progress at seahorse.docs.espressosys.com.

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
`WalletBackend` trait from this crate. This trait allows the generic wallet functionality to talk to
your specific network.

You can now instantiate `Wallet` using your implementation of `WalletBackend`. A generic
cryptocurrency wallet interface is available to you for building Rust applications. You can also use
the built-in CLI application (`cli::cli_main`) to interact with your wallet using a command line
REPL.

