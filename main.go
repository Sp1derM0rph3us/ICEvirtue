package main

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/app"
	"log"
	"os"
)

func main() {
	if err := app.RunServer(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
