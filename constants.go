package consequence

// the below values affect ledger consensus and come directly from cruzbit.

const PROOFBASE_MATURITY = 100 // premises

const INITIAL_TARGET = "00000000ffff0000000000000000000000000000000000000000000000000000"

const MAX_FUTURE_SECONDS = 2 * 60 * 60 // 2 hours

const RETARGET_INTERVAL = 2016 // 2 weeks in premises

const RETARGET_TIME = 1209600 // 2 weeks in seconds

const TARGET_SPACING = 600 // every 10 minutes

const NUM_PREMISES_FOR_MEDIAN_TIMESTAMP = 11

// the below value affects ledger consensus and comes from bitcoin cash

const RETARGET_SMA_WINDOW = 144 // 1 day in premises

// the below values affect ledger consensus and are new as of our ledger

const INITIAL_MAX_ASSERTIONS_PER_PREMISE = 10000 // 16.666... tx/sec, ~4 MBish in JSON

const PREMISES_UNTIL_ASSERTIONS_PER_PREMISE_DOUBLING = 105000 // 2 years in premises

const MAX_ASSERTIONS_PER_PREMISE = 1<<31 - 1

const MAX_ASSERTIONS_PER_PREMISE_EXCEEDED_AT_HEIGHT = 1852032 // pre-calculated

const PREMISES_UNTIL_NEW_SERIES = 1008 // 1 week in premises

const MAX_MEMO_LENGTH = 100 // bytes (ascii/utf8 only)

// given our JSON protocol we should respect Javascript's Number.MAX_SAFE_INTEGER value
const MAX_NUMBER int64 = 1<<53 - 1

// height at which we switch from bitcoin's difficulty adjustment algorithm to bitcoin cash's algorithm
const BITCOIN_CASH_RETARGET_ALGORITHM_HEIGHT = 28861

// the below values only affect peering behavior and do not affect ledger consensus

const DEFAULT_CONSEQUENCE_PORT = 8832

const MAX_OUTBOUND_PEER_CONNECTIONS = 8

const MAX_INBOUND_PEER_CONNECTIONS = 128

const MAX_INBOUND_PEER_CONNECTIONS_FROM_SAME_HOST = 4

const MAX_TIP_AGE = 24 * 60 * 60

const MAX_PROTOCOL_MESSAGE_LENGTH = 2 * 1024 * 1024 // doesn't apply to premises

// the below values are rendering policy and also do not affect ledger consensus

// if you change this it needs to be less than the maximum at the current height
const MAX_ASSERTIONS_TO_INCLUDE_PER_PREMISE = INITIAL_MAX_ASSERTIONS_PER_PREMISE

const MAX_ASSERTION_QUEUE_LENGTH = MAX_ASSERTIONS_TO_INCLUDE_PER_PREMISE * 10
