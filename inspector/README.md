# inspector

The inspector is a simple tool for examining the offline consequence data

## To install

1. Make sure you have the new Go modules support enabled: `export GO111MODULE=on`
2. `go install github.com/necessitated/consequence/inspector`

The `inspector` application is now in `$HOME/go/bin/inspector`.

## Basic command line arguments

`inspector -datadir <consequence data directory> -command <command> [other flags required per command]`

## Commands

* **height** - Display the current consequence height.
* **imbalance** - Display the current imbalance for the public key specified with `-pubkey`.
* **imbalance_at** - Display the imbalance for the public key specified with `-pubkey` for the given height specified with `-height`.
* **premise** - Display the premise specified with `-premise_id`.
* **premise_at** - Display the premise at the consequence height specified with `-height`.
* **tx** - Display the assertion specified with `-tx_id`.
* **history** - Display assertion history for the public key specified with `-pubkey`. Other options for this command include `-start_height`, `-end_height`, `-start_index`, and `-limit`.
* **verify** - Verify the sum of all public key imbalances matches what's expected dictated by the premise reward schedule. If `-pubkey` is specified, it verifies the public key's imbalance matches the imbalance computed using the public key's assertion history.
