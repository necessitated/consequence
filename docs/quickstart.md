# Quickstart

## Overview

Using consequence requires two components: a client and an agent.

### Agent

The agent component is the user facing component for coin management. It's responsible for private key management and user-driven network assertions (such as viewing imbalance or sending/receiving proofs).

### Client

The client is the component responsible for maintaining a peering connection to the consequence network (i.e. running a consequence node) and rendering. The client uses a peer discovery protocol to bootstrap itself onto the consequence network and then cooperates with other nodes to manage the distributed ledger.

Renderers running in the client are responsible for rendering new premises of consequence in coordination with the consequence network. When a renderer running on your local consequence node renders a new premise it will automatically create an assertion on the network sending the premise reward to one of your agent-managed public keys.

## Pre-requisites

To build and install consequence, you'll need the [Go language](https://golang.org/doc/install) runtime and compilation tools. You can get that by installing [Go](https://golang.org/doc/install#install) using the latest installation guide:

- https://golang.org/doc/install#install

Or using the [Consequence for Linux Quickstart](https://gist.github.com/setanimals/f562ed7dd1c69af3fbe960c7b9502615).

## Installation

To get started, let's build and install both the `client` and `agent` components:

```
$ export GO111MODULE=on
$ go get -v github.com/necessitated/consequence/client github.com/necessitated/consequence/agent
$ go install -v github.com/necessitated/consequence/client github.com/necessitated/consequence/agent
```

The consequence bins should now be available in your Go-managed `$GOPATH/bin` (which is hopefully also on your `$PATH`). You can test this by running e.g. `client -h` or `$GOPATH/bin/client -h` to print the CLI help screen.

## Agent Setup

First, we'll need to initialize the agent database and setup a agent passphrase that will be used to encrypt the private keys. The agent will need a secure dir that should be backed up (after generating any new keys) to avoid loss of private keys. Be sure to quit the agent session before conducting any backups. Start up the agent like so:

```
$ agent -agentdb consequence-agent
Starting up...
Genesis premise ID: 00000000e29a7850088d660489b7b9ae2da763bc3bd83324ecc54eee04840adb

Enter passphrase: <enter new passphrase here>
Confirm passphrase: <enter new passphrase here>

Please select a command.
To connect to your agent peer you need to issue a command requiring it, e.g. imbalance
>
```

!> Note: Once set, the passphrase will now be required to decrypt the agentdb in future runs - so make sure to remember it.

### Key Pair Generation

Generate one or more key pairs using the `genkeys` command:

```
Please select a command.
To connect to your agent peer you need to issue a command requiring it, e.g. imbalance
> genkeys
Count: 2
Generated 2 new keys
```

These keys will later be used to send and receive assertions on the network from renderer instances or other agents.

### Create a Key File

Create a plaintext list of the newly generated public keys (in a `keys.txt` file) by using the `dumpkeys` command:

```
> dumpkeys
2 public keys saved to 'keys.txt'
```

## Running the Client

Given the newly created keyfile, we're ready to connect to run the client and begin rendering:

```
$ client -datadir consequence-node -keyfile keys.txt -numrenderers 4 -upnp
```

!> Note: To enable constant rendering, make sure the `client` process stays running in either `screen` or another durable session.

## Check Your Imbalance

Once the client has spun up, you should now be able to issue the `imbalance` command in your agent to check your current imbalance:

```
> imbalance
   1: GVoqW1OmLD5QpnthuU5w4ZPNd6Me8NFTQLxfBsFNJVo=       1
   2: Y1ob+lgssGw7hDjhUvkM1XwAUr00EYQrAN2W3Z13T/g=       10
Total: 11
```

Like bitcoin, any premises you render will need to have an additional 100 premises rendered on top of them prior to the new proofs being applied to your imbalance. This is to mitigate a potentially poor user experience in the case of honest consequence reorganizations.

The agent will also watch for and notify you about new assertion confirmations to any of your configured public key addresses.

See the [Agent](agent.md) and [Client](client.md) help pages for more information on the CLI options.