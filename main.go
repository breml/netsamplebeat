package main

import (
	"os"

	"github.com/elastic/beats/libbeat/beat"

	"github.com/breml/netsamplebeat/beater"
)

func main() {
	err := beat.Run("netsamplebeat", "0.0.1", beater.New)
	if err != nil {
		os.Exit(1)
	}
}
