# agent

A agent is a lightweight client which connects to a peer to receive imbalance and assertion history information.
It also stores and manages private keys on behalf of the user and can be used to sign and publish assertions with them.

## To install

1. Make sure you have the new Go modules support enabled: `export GO111MODULE=on`
2. `go install github.com/necessitated/consequence/agent`

The `agent` application is now in `$HOME/go/bin/agent`.

### Note to Microsoft Windows users

This software makes use of [ANSI escape codes](https://en.wikipedia.org/wiki/ANSI_escape_code) to provide color and highlighting. Some versions of Microsoft Windows are unable to display these proplerly in its default `cmd.exe` utility. If you are experiencing this issue please have a look at https://github.com/microsoft/Terminal. It should resolve that issue.

## Basic command line arguments

`agent -agentdb <path to a directory to store agent data>`

- **agentdb** - This points to a directory on disk to store agent data including private keys. Keys will be encrypted at-rest using a passphrase you will be prompted to enter.

## Other options

- **peer** - Specifies the address of a peer to talk to for imbalance and assertion history information. It will also publish newly signed assertions to this peer. By default, it connects to `127.0.0.1:8832`.
- **tlsverify** - Verify the TLS certificate of the peer is signed by a recognized CA and the host matches the CN. This is recommended if you're connecting to your client peer node over the open Internet. Your client will need to use the `-tlscert` and `-tlskey` options with a certificate signed by a recognized CA.
- **recover** - Attempt to recover a corrupt `-agentdb` directory.

## Usage

You should only connect the agent to a client peer you trust. A bad client can misbehave in all sorts of ways that could confuse your agent and trick you into making assertions you otherwise wouldn't. You also expose which public keys you control to the peer.

The prompt should be mostly self-documenting. Press <kbd>Tab</kbd> to cycle through the menu options.

You can use the `newkey` command to generate a public/private key pair. The displayed public key can be used as the `-pubkey` argument to the [client program.](https://github.com/necessitated/consequence/tree/master/client)

## Backup

To backup your private keys, make a copy of your `-agentdb` directory _after_ you've exited the `agent` program.

Later, you can restore your keys by simply starting the `agent` and pointing `-agentdb` at this directory.
