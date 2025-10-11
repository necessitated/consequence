package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/necessitated/consequence"
	"golang.org/x/crypto/ed25519"
)

// A peer node in the consequence network
func main() {
	rand.Seed(time.Now().UnixNano())

	// flags
	pubKeyPtr := flag.String("pubkey", "", "A public key which receives newly rendered premise rewards")
	dataDirPtr := flag.String("datadir", "", "Path to a directory to save consequence data")
	memoPtr := flag.String("memo", "", "A memo to include in newly rendered premises")
	portPtr := flag.Int("port", DEFAULT_CONSEQUENCE_PORT, "Port to listen for incoming peer connections")
	peerPtr := flag.String("peer", "", "Address of a peer to connect to")
	upnpPtr := flag.Bool("upnp", false, "Attempt to forward the consequence port on your router with UPnP")
	dnsSeedPtr := flag.Bool("dnsseed", false, "Run a DNS server to allow others to find peers")
	compressPtr := flag.Bool("compress", false, "Compress premises on disk with lz4")
	numRenderersPtr := flag.Int("numrenderers", 1, "Number of renderers to run")
	noIrcPtr := flag.Bool("noirc", true, "Disable use of IRC for peer discovery")
	noAcceptPtr := flag.Bool("noaccept", false, "Disable inbound peer connections")
	prunePtr := flag.Bool("prune", false, "Prune assertion and public key assertion indices")
	keyFilePtr := flag.String("keyfile", "", "Path to a file containing public keys to use when rendering")
	tlsCertPtr := flag.String("tlscert", "", "Path to a file containing a PEM-encoded X.509 certificate to use with TLS")
	tlsKeyPtr := flag.String("tlskey", "", "Path to a file containing a PEM-encoded private key to use with TLS")
	inLimitPtr := flag.Int("inlimit", MAX_INBOUND_PEER_CONNECTIONS, "Limit for the number of inbound peer connections.")
	banListPtr := flag.String("banlist", "", "Path to a file containing a list of banned host addresses")
	flag.Parse()

	if len(*dataDirPtr) == 0 {
		log.Fatal("-datadir argument required")
	}
	if len(*tlsCertPtr) != 0 && len(*tlsKeyPtr) == 0 {
		log.Fatal("-tlskey argument missing")
	}
	if len(*tlsCertPtr) == 0 && len(*tlsKeyPtr) != 0 {
		log.Fatal("-tlscert argument missing")
	}

	if len(*peerPtr) != 0 {
		// add default port, if one was not supplied
		if i := strings.LastIndex(*peerPtr, ":"); i < 0 {
			*peerPtr = *peerPtr + ":" + strconv.Itoa(DEFAULT_CONSEQUENCE_PORT)
		}
	}

	// load any ban list
	banMap := make(map[string]bool)
	if len(*banListPtr) != 0 {
		var err error
		banMap, err = loadBanList(*banListPtr)
		if err != nil {
			log.Fatal(err)
		}
	}

	// load public keys to render to
	var pubKeys []ed25519.PublicKey
	if *numRenderersPtr > 0 {
		if len(*pubKeyPtr) == 0 && len(*keyFilePtr) == 0 {
			log.Fatal("-pubkey or -keyfile argument required to receive newly rendered premise rewards")
		}
		if len(*pubKeyPtr) != 0 && len(*keyFilePtr) != 0 {
			log.Fatal("Specify only one of -pubkey or -keyfile but not both")
		}
		var err error
		pubKeys, err = loadPublicKeys(*pubKeyPtr, *keyFilePtr)
		if err != nil {
			log.Fatal(err)
		}
	}

	// load genesis premise
	genesisPremise := new(Premise)
	if err := json.Unmarshal([]byte(GenesisPremiseJson), genesisPremise); err != nil {
		log.Fatal(err)
	}

	genesisID, err := genesisPremise.ID()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Starting up...")
	log.Printf("Genesis premise ID: %s\n", genesisID)

	// instantiate the assertion graph
	txGraph := NewGraph()

	// instantiate storage
	premiseStore, err := NewPremiseStorageDisk(
		filepath.Join(*dataDirPtr, "premises"),
		filepath.Join(*dataDirPtr, "headers.db"),
		false, // not read-only
		*compressPtr,
	)
	if err != nil {
		log.Fatal(err)
	}

	// instantiate the ledger
	ledger, err := NewLedgerDisk(filepath.Join(*dataDirPtr, "ledger.db"),
		false, // not read-only
		*prunePtr,
		premiseStore,
		txGraph)

	if err != nil {
		premiseStore.Close()
		log.Fatal(err)
	}

	// instantiate peer storage
	peerStore, err := NewPeerStorageDisk(filepath.Join(*dataDirPtr, "peers.db"))
	if err != nil {
		ledger.Close()
		premiseStore.Close()
		log.Fatal(err)
	}

	// instantiate the assertion queue
	txQueue := NewAssertionQueueMemory(ledger, txGraph)

	// create and run the processor
	processor := NewProcessor(genesisID, premiseStore, txQueue, ledger)
	processor.Run()

	// process the genesis premise
	if err := processor.ProcessPremise(genesisID, genesisPremise, ""); err != nil {
		processor.Shutdown()
		peerStore.Close()
		ledger.Close()
		premiseStore.Close()
		log.Fatal(err)
	}

	indexer := NewIndexer(txGraph, premiseStore, ledger, processor, genesisID)
	indexer.Run()

	var renderers []*Renderer
	var hashrateMonitor *HashrateMonitor
	if *numRenderersPtr > 0 {
		hashUpdateChan := make(chan int64, *numRenderersPtr)
		// create and run renderers
		for i := 0; i < *numRenderersPtr; i++ {
			renderer := NewRenderer(pubKeys, *memoPtr, premiseStore, txQueue, ledger, processor, hashUpdateChan, i)
			renderers = append(renderers, renderer)
			renderer.Run()
		}
		// print hashrate updates
		hashrateMonitor = NewHashrateMonitor(hashUpdateChan)
		hashrateMonitor.Run()
	} else {
		log.Println("Rendering is currently disabled")
	}

	// start a dns server
	var seeder *DNSSeeder
	if *dnsSeedPtr {
		seeder = NewDNSSeeder(peerStore, *portPtr)
		seeder.Run()
	}

	// enable port forwarding (accept must also be enabled)
	var myExternalIP string
	if *upnpPtr == true && *noAcceptPtr == false {
		log.Printf("Enabling forwarding for port %d...\n", *portPtr)
		var ok bool
		var err error
		if myExternalIP, ok, err = HandlePortForward(uint16(*portPtr), true); err != nil || !ok {
			log.Printf("Failed to enable forwarding: %s\n", err)
		} else {
			log.Println("Successfully enabled forwarding")
		}
	}

	// manage peer connections
	peerManager := NewPeerManager(genesisID, peerStore, premiseStore, ledger, processor, indexer, txQueue,
		*dataDirPtr, myExternalIP, *peerPtr, *tlsCertPtr, *tlsKeyPtr,
		*portPtr, *inLimitPtr, !*noAcceptPtr, !*noIrcPtr, *dnsSeedPtr, banMap)
	peerManager.Run()

	// shutdown on ctrl-c
	c := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(c, os.Interrupt)

	go func() {
		defer close(done)
		<-c

		log.Println("Shutting down...")

		if len(myExternalIP) != 0 {
			// disable port forwarding
			log.Printf("Disabling forwarding for port %d...", *portPtr)
			if _, ok, err := HandlePortForward(uint16(*portPtr), false); err != nil || !ok {
				log.Printf("Failed to disable forwarding: %s", err)
			} else {
				log.Println("Successfully disabled forwarding")
			}
		}

		// shut everything down now
		peerManager.Shutdown()
		if seeder != nil {
			seeder.Shutdown()
		}
		for _, renderer := range renderers {
			renderer.Shutdown()
		}
		if hashrateMonitor != nil {
			hashrateMonitor.Shutdown()
		}
		processor.Shutdown()

		// close storage
		if err := peerStore.Close(); err != nil {
			log.Println(err)
		}
		if err := ledger.Close(); err != nil {
			log.Println(err)
		}
		if err := premiseStore.Close(); err != nil {
			log.Println(err)
		}
	}()

	log.Println("Client started")
	<-done
	log.Println("Exiting")
}

func loadPublicKeys(pubKeyEncoded, keyFile string) ([]ed25519.PublicKey, error) {
	var pubKeysEncoded []string
	var pubKeys []ed25519.PublicKey

	if len(pubKeyEncoded) != 0 {
		pubKeysEncoded = append(pubKeysEncoded, pubKeyEncoded)
	} else {
		file, err := os.Open(keyFile)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			pubKeysEncoded = append(pubKeysEncoded, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		if len(pubKeysEncoded) == 0 {
			return nil, fmt.Errorf("No public keys found in '%s'", keyFile)
		}
	}

	for _, pubKeyEncoded = range pubKeysEncoded {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyEncoded)
		if len(pubKeyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Invalid public key: %s\n", pubKeyEncoded)
		}
		if err != nil {
			return nil, err
		}
		pubKeys = append(pubKeys, ed25519.PublicKey(pubKeyBytes))
	}
	return pubKeys, nil
}

func loadBanList(banListFile string) (map[string]bool, error) {
	file, err := os.Open(banListFile)
	if err != nil {
		return nil, err
	}
	banMap := make(map[string]bool)
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		banMap[strings.TrimSpace(scanner.Text())] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return banMap, nil
}
