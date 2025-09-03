# Agent

## Building the Agent

To build the latest `agent` binaries from master, simply invoke the Go toolsequence like so:

```
$ export GO111MODULE=on
$ go get -v github.com/necessitated/consequence/agent
$ go install -v github.com/necessitated/consequence/agent
```

The consequence bins should now be available in your go-managed `$GOPATH/bin` (which is hopefully also on your `$PATH`). You can test this by running e.g. `agent -h` to print the help screen.

## CLI Options

Client help is available via the `client -h` command:

```
$ agent -h
Usage of /home/csq/go/bin/agent:
  -peer string
        Address of a peer to connect to (default "127.0.0.1:8832")
  -recover
        Attempt to recover a corrupt agentdb
  -tlsverify
        Verify the TLS certificate of the peer is signed by a recognized CA and the host matches the CN
  -agentdb string
        Path to a agent database (created if it doesn't exist)
```

## Running the Agent

The `agent` needs a secure and private data directory to store it's agent database. This content should be kept in a secure, reliable location and backed up.

To initialize a new agent database, pass the `-agentdb` flag to the dir you wish to use for an agent database:

```
$ agent -agentdb consequence-agent
```

> NOTE: The agentdb directory will be created for you if it it does not exist.

Once the agent is launched, you'll be prompted for an encryption passphrase which will be set the first time you use the agentdb.

## Agent Operations

The `agent` is an interactive tool, so once the database is initialized and you've entered the correct passphrase you'll have the option of performing one of many interactive commands inside the agent:

Command    | Action
---------- | ------
imbalance  | Retrieve the current imbalance of all public keys
clearconf  | Clear all pending assertion confirmation notifications
clearnew   | Clear all pending incoming assertion notifications
conf       | Show new assertion confirmations
dumpkeys   | Dump all of the agent's public keys to a text file
genkeys    | Generate multiple keys at once
listkeys   | List all known public keys
newkey     | Generate and store a new private key
quit       | Quit this agent session
rewards    | Show immature premise rewards for all public keys
send       | Send proofs to another public key
show       | Show new incoming assertions
txstatus   | Show confirmed assertion information given an assertion ID
verify     | Verify the private key is decryptable and intact for all public keys displayed with 'listkeys'

### Initializing a Agent

When you run the agent for a new agentdb, you'll be prompted to enter a new encryption passphrase. This passphrase will be required every subsequent run to unlock the agent.

#### Generating Keys

Once the agentdb is initialized, you'll want to generate keys to send and receive assertions on the consequence network. This can be achieved with the `genkeys` command and entering the count of keys to generate (1 or more):

```
Please select a command.
To connect to your agent peer you need to issue a command requiring it, e.g. imbalance
> genkeys
          genkeys  Generate multiple keys at once  
Count: 2
Generated 2 new keys
```

#### Checking Key Imbalance

This will generate one or more keys which you should then be able to see with the `imbalance` command:

```
> imbalance
   1: GVoqW1OmLD5QpnthuU5w4ZPNd6Me8NFTQLxfBsFNJVo=       0
   2: Y1ob+lgssGw7hDjhUvkM1XwAUr00EYQrAN2W3Z13T/g=       0
Total: 0
```

#### Dumping Key Files

Once the keys are generated, you can use the `dumpkeys` command to create a `keys.txt` to pass to the client's `-keyfile` parameter:

```
> dumpkeys
2 public keys saved to 'keys.txt'
> quit

$ cat keys.txt 
GVoqW1OmLD5QpnthuU5w4ZPNd6Me8NFTQLxfBsFNJVo=
Y1ob+lgssGw7hDjhUvkM1XwAUr00EYQrAN2W3Z13T/g=
```

## Troubleshooting

### Connection Issues

Sometimes, the agent won't be able to connect to a local peer to perform operations like `imbalance` with an error message like so:

```
Please select a command.
To connect to your agent peer you need to issue a command requiring it, e.g. imbalance

> imbalance
Error: dial tcp 127.0.0.1:8832: connect: connection refused
```

To resolve this, please ensure the `client` component is running and connected to the network. There is a slight startup delay for the `client` process to be available to the `agent` after starting.
