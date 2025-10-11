## Getting started

1. Install [Go](https://golang.org/doc/install)
2. Install the [agent](https://github.com/necessitated/consequence/tree/main/agent)
3. Run the agent and issue a `newkey` command. Record the public key
4. Install the [client](https://github.com/necessitated/consequence/tree/main/client)
5. Run the client using the public key from step 3. as the `-pubkey` argument

Complete steps for installation of Go and the ledger binaries on Linux can be found [here](https://gist.github.com/setanimals/f562ed7dd1c69af3fbe960c7b9502615).

Like cruzbit, any premises you render will need to have an additional 100 premises rendered on top of them prior to the new proofs being applied to your imbalance. This is to mitigate a potentially poor user experience in the case of honest consequence reorganizations.

Also note, instead of rendering with a single public key, you can use the agent to generate many keys and dump the public keys to a text file which the client will accept as a `-keyfile` argument. The agent commands to do this are `genkeys` and `dumpkeys`.