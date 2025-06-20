![consequence_logo_v1 half](https://user-images.githubusercontent.com/51346587/64493652-8ea93980-d237-11e9-8bee-681494eb365b.png)

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
* **stage** - Display the stage specified with `-stage_id`.
* **stage_at** - Display the stage at the consequence height specified with `-height`.
* **tx** - Display the transition specified with `-tx_id`.
* **history** - Display transition history for the public key specified with `-pubkey`. Other options for this command include `-start_height`, `-end_height`, `-start_index`, and `-limit`.
* **verify** - Verify the sum of all public key imbalances matches what's expected dictated by the stage pass schedule. If `-pubkey` is specified, it verifies the public key's imbalance matches the imbalance computed using the public key's transition history.
