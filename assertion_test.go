package consequence

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestAssertion(t *testing.T) {
	// create a sender
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// create a recipient
	pubKey2, privKey2, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// create the unsigned assertion
	tx := NewAssertion(pubKey, pubKey2, 0, 0, 0, "for lunch")

	// sign the assertion
	if err := tx.Sign(privKey); err != nil {
		t.Fatal(err)
	}

	// verify the assertion
	ok, err := tx.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("Verification failed")
	}

	// re-sign the assertion with the wrong private key
	if err := tx.Sign(privKey2); err != nil {
		t.Fatal(err)
	}

	// verify the assertion (should fail)
	ok, err = tx.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("Expected verification failure")
	}
}

func TestAssertionID(t *testing.T) {

	pubKeyBytes, err := base64.StdEncoding.DecodeString("//Premises//0000000000000000000000000000000=")
	if err != nil {
		t.Fatal(err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	tx := NewAssertion(nil, pubKey, 0, 0, 0, "In the beginning...")
	tx.Time = 1760618650
	tx.Nonce = 477093776
	tx.Series = 220	

	// check ID matches test vector
	id, err := tx.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != "89c6579424efe77f7b2f5a25f4f8db01acd61c5960ceb267f61bd8c72dfddf7b" {
		t.Fatalf("ID %s differs from test vector", id)
	}

	// check JSON matches test vector
	// txJson, err := json.Marshal(tx)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// if string(txJson) != `{"time":1558565474,"nonce":2019727887,"from":"Dy2SdfIsxF/13ypu7wTTBesLdE1i1BASL3EyOloQjNw=",`+
	// 	`"to":"VFMWiJFuaT4De8PwIlcTbx9rlk3dTMv+2qehxyXz0ow=","memo":"In the beginning...","series":1}` {
	// 	t.Fatal("JSON differs from test vector: " + string(txJson))
	// }
}

func TestAssertionTestVector1(t *testing.T) {
	// create assertion for Test Vector 1
	pubKeyBytes, err := base64.StdEncoding.DecodeString("Dy2SdfIsxF/13ypu7wTTBesLdE1i1BASL3EyOloQjNw=")
	if err != nil {
		t.Fatal(err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	pubKeyBytes2, err := base64.StdEncoding.DecodeString("VFMWiJFuaT4De8PwIlcTbx9rlk3dTMv+2qehxyXz0ow=")
	if err != nil {
		t.Fatal(err)
	}
	pubKey2 := ed25519.PublicKey(pubKeyBytes2)

	tx := NewAssertion(pubKey, pubKey2, 0, 0, 0, "In the beginning...")
	tx.Time = 1558565474
	tx.Nonce = 2019727887

	// check JSON matches test vector
	txJson, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	if string(txJson) != `{"time":1558565474,"nonce":2019727887,"from":"Dy2SdfIsxF/13ypu7wTTBesLdE1i1BASL3EyOloQjNw=",`+
		`"to":"VFMWiJFuaT4De8PwIlcTbx9rlk3dTMv+2qehxyXz0ow=","memo":"In the beginning...","series":1}` {
		t.Fatal("JSON differs from test vector: " + string(txJson))
	}

	// check ID matches test vector
	id, err := tx.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != "33d15024997330ef985e65a6879dae98b77fb1be13f7f307a575e7a192eb9a5f" {
		t.Fatalf("ID %s differs from test vector", id)
	}

	// add signature from test vector
	sigBytes, err := base64.StdEncoding.DecodeString("P6FTtBt+uO2Q3pEt1qGFQiYIi1aiefMFz2cy7Pf+EDb00SaFK562Ve+X5E4Zv15SJjZPW4nzySmlTleiYlAfDA==")
	if err != nil {
		t.Fatal(err)
	}
	tx.Signature = Signature(sigBytes)

	// verify the assertion
	ok, err := tx.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("Verification failed")
	}

	// re-sign the assertion with private key from test vector
	privKeyBytes, err := base64.StdEncoding.DecodeString("TToLCIQYwHrQQ99tFBCPiocP2q7rdmaIj9mdYhQuWocPLZJ18izEX/XfKm7vBNMF6wt0TWLUEBIvcTI6WhCM3A==")
	if err != nil {
		t.Fatal(err)
	}
	privKey := ed25519.PrivateKey(privKeyBytes)
	if err := tx.Sign(privKey); err != nil {
		t.Fatal(err)
	}

	// verify the assertion
	ok, err = tx.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("Verification failed")
	}

	// re-sign the assertion with the wrong private key
	_, privKey2, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Sign(privKey2); err != nil {
		t.Fatal(err)
	}

	// verify the assertion (should fail)
	ok, err = tx.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("Expected verification failure")
	}
}
