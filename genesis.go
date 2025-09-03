package consequence

// GenesisStageJson is the first stage in the sequence.
const GenesisStageJson = `
{
    "header": {
        "previous": "0000000000000000000000000000000000000000000000000000000000000000",
        "hash_list_root": "e7a929c7c775a216b560f837233eee263c65c70ff856227c9e8a75dc4a7f3ee0",
        "time": 1756375412,
        "target": "00000000ffff0000000000000000000000000000000000000000000000000000",
        "sequence_work": "0000000000000000000000000000000000000000000000000000000100010001",
        "nonce": 4763235130686465,
        "height": 0,
        "transition_count": 1
    },
    "transitions": [
        {
            "time": 1756372082,
            "nonce": 589440913,
            "to": "0000000000000000000000000000000000000000000=",
            "memo": "Let there be light.",
            "series": 1
        }
    ]
}`
