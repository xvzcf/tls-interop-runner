package main

import (
	"log"
)

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s\n", msg, err)
	}
}
