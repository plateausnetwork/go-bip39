package bip39_test

import (
	"encoding/hex"
	"log"

	"github.com/rhizomplatform/go-bip39"
)

func ExampleNewMnemonic() {
	// the entropy can be any byte slice, generated how pleased,
	// as long its bit size is a multiple of 32 and is within
	// the inclusive range of {128,256}
	entropy, _ := hex.DecodeString("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad")

	// generate a mnemomic
	mnemomic, _ := bip39.NewMnemonic(entropy)
	log.Println(mnemomic)
	// output:
	// agua fita inquilino entrada herdar editar ficcao agosto ataque extra exercito habilidade misericordia membro camera levantar girar investir parede embarcacao pulso adiante planta palacio
}

func ExampleNewSeed() {
	seed := bip39.NewSeed("agua fita inquilino entrada herdar editar ficcao agosto ataque extra exercito habilidade misericordia membro camera levantar girar investir parede embarcacao pulso adiante planta palacio", "TREZOR", false)
	log.Println(hex.EncodeToString(seed))
	// output:
	// e9ba894700dbc996b82446b30d4a2f2d56adc6c07f3d1602c3d24e516a344affac43a05f895d416902fcc78ae734d1622edf69e923532fee8d93d359780ac34a
}
