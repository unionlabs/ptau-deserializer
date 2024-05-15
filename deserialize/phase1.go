package deserializer

import (
	"bytes"
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
)

// Generate R in G₂ as Hash(gˢ, gˢˣ, challenge, dst)
func genR(sG1, sxG1 curve.G1Affine, challenge []byte, dst byte) curve.G2Affine {
	var buf bytes.Buffer
	buf.Grow(len(challenge) + curve.SizeOfG1AffineUncompressed*2)
	buf.Write(sG1.Marshal())
	buf.Write(sxG1.Marshal())
	buf.Write(challenge)
	spG2, err := curve.HashToG2(buf.Bytes(), []byte{dst})
	if err != nil {
		panic(err)
	}
	return spG2
}

func newPublicKey(x fr.Element, challenge []byte, dst byte) mpcsetup.PublicKey {
	var pk mpcsetup.PublicKey
	_, _, g1, _ := curve.Generators()

	var s fr.Element
	var sBi big.Int
	s.SetRandom()
	s.BigInt(&sBi)
	pk.SG.ScalarMultiplication(&g1, &sBi)

	// compute x*sG1
	var xBi big.Int
	x.BigInt(&xBi)
	pk.SXG.ScalarMultiplication(&pk.SG, &xBi)

	// generate R based on sG1, sxG1, challenge, and domain separation tag (tau, alpha or beta)
	R := genR(pk.SG, pk.SXG, challenge, dst)

	// compute x*spG2
	pk.XR.ScalarMultiplication(&R, &xBi)
	return pk
}

func ConvertPtauToPhase1(ptau Ptau) (phase1 mpcsetup.Phase1, err error) {
	tauG1 := make([]curve.G1Affine, len(ptau.PTauPubKey.TauG1))
	for i, g1 := range ptau.PTauPubKey.TauG1 {
		g1Affine := curve.G1Affine{}
		x := bytesToElement(g1[0].Bytes())
		g1Affine.X = x
		y := bytesToElement(g1[1].Bytes())
		g1Affine.Y = y
		// fmt.Printf("X: %v \n", g1Affine.X.String())
		// fmt.Printf("Y: %v \n", g1Affine.Y.String())
		// fmt.Printf("g1Affine: %v \n", g1Affine)
		if !g1Affine.IsOnCurve() {
			fmt.Printf("tauG1: \n index: %v g1Affine.X: %v \n g1Affine.Y: %v \n", i, g1Affine.X.String(), g1Affine.Y.String())
			panic("g1Affine is not on curve")
		}
		tauG1[i] = g1Affine
	}

	alphaTauG1 := make([]curve.G1Affine, len(ptau.PTauPubKey.AlphaTauG1))
	for i, g1 := range ptau.PTauPubKey.AlphaTauG1 {
		g1Affine := curve.G1Affine{}
		x := bytesToElement(g1[0].Bytes())
		g1Affine.X = x
		y := bytesToElement(g1[1].Bytes())
		g1Affine.Y = y
		if !g1Affine.IsOnCurve() {
			fmt.Printf("alphaTauG1: \n index: %v g1Affine.X: %v \n g1Affine.Y: %v \n", i, g1Affine.X.String(), g1Affine.Y.String())
			panic("g1Affine is not on curve")
		}
		alphaTauG1[i] = g1Affine
	}
	// fmt.Printf("alphaTauG1: %v \n", alphaTauG1)

	betaTauG1 := make([]curve.G1Affine, len(ptau.PTauPubKey.BetaTauG1))

	for i, g1 := range ptau.PTauPubKey.BetaTauG1 {
		g1Affine := curve.G1Affine{}
		x := bytesToElement(g1[0].Bytes())
		g1Affine.X = x
		y := bytesToElement(g1[1].Bytes())
		g1Affine.Y = y
		if !g1Affine.IsOnCurve() {
			fmt.Printf("betaTauG1: \n index: %v, g1Affine.X: %v \n g1Affine.Y: %v \n", i, g1Affine.X.String(), g1Affine.Y.String())
			panic("g1Affine is not on curve")
		}
		betaTauG1[i] = g1Affine
	}
	// fmt.Printf("betaTauG1: %v \n", betaTauG1)

	// fmt.Printf("tauG1: %v \n", tauG1)

	tauG2 := make([]curve.G2Affine, len(ptau.PTauPubKey.TauG2))
	for i, g2 := range ptau.PTauPubKey.TauG2 {
		g2Affine := curve.G2Affine{}
		x0 := bytesToElement(g2[0].Bytes())
		x1 := bytesToElement(g2[1].Bytes())
		g2Affine.X.A0 = x0
		g2Affine.X.A1 = x1
		y0 := bytesToElement(g2[2].Bytes())
		y1 := bytesToElement(g2[3].Bytes())
		g2Affine.Y.A0 = y0
		g2Affine.Y.A1 = y1

		// fmt.Printf("X: %v \n", g2Affine.X.String())
		// fmt.Printf("Y: %v \n", g2Affine.Y.String())
		// fmt.Printf("g2Affine %v: %v \n", i, g2Affine)
		if !g2Affine.IsOnCurve() {
			fmt.Printf("tauG2: \n index: %v, g2Affine.X.A0: %v \n g2Affine.X.A1: %v \n g2Affine.Y.A0: %v \n g2Affine.Y.A1 %v \n", i, g2Affine.X.A0.String(), g2Affine.X.A1.String(), g2Affine.Y.A0.String(), g2Affine.Y.A1.String())
			panic("g2Affine is not on curve")
		}
		tauG2[i] = g2Affine
	}

	// fmt.Printf("tauG2: %v \n", tauG2)

	betaG2 := curve.G2Affine{}
	{
		g2 := ptau.PTauPubKey.BetaG2

		x0 := bytesToElement(g2[0].Bytes())
		x1 := bytesToElement(g2[1].Bytes())
		betaG2.X.A0 = x0
		betaG2.X.A1 = x1
		y0 := bytesToElement(g2[2].Bytes())
		y1 := bytesToElement(g2[3].Bytes())
		betaG2.Y.A0 = y0
		betaG2.Y.A1 = y1

		if !betaG2.IsOnCurve() {
			fmt.Printf("g2Affine.X.A0: %v \n g2Affine.X.A1: %v \n g2Affine.Y.A0: %v \n g2Affine.Y.A1 %v \n", betaG2.X.A0.String(), betaG2.X.String(), betaG2.Y.A0.String(), betaG2.Y.A1.String())
			panic("g2Affine is not on curve")
		}
	}

	// Generate key pairs
	var tau, alpha, beta fr.Element
	tau.SetRandom()
	alpha.SetRandom()
	beta.SetRandom()
	phase1.PublicKeys.Tau = newPublicKey(tau, phase1.Hash[:], 1)
	phase1.PublicKeys.Alpha = newPublicKey(alpha, phase1.Hash[:], 2)
	phase1.PublicKeys.Beta = newPublicKey(beta, phase1.Hash[:], 3)

	phase1.Parameters.G1.Tau = tauG1
	phase1.Parameters.G2.Tau = tauG2
	phase1.Parameters.G1.AlphaTau = alphaTauG1
	phase1.Parameters.G1.BetaTau = betaTauG1
	phase1.Parameters.G2.Beta = betaG2

	return phase1, nil
}
