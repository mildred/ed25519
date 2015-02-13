package main;
import (
    "fmt"
    "encoding/hex"
    ed "github.com/mildred/ed25519/src"
);

func main() {
    seed, err := ed.CreateSeed();
    if err != nil {
        fmt.Println(err)
        return
    }

    pub, priv := ed.CreateKeypair(seed);

    fmt.Printf("Public Key (hex):  %s\n", hex.EncodeToString(pub[:]));
    fmt.Printf("Private Key (hex): %s\n", hex.EncodeToString(priv[:]));
}