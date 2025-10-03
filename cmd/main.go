package main

import (
	"context"
	"log"

	"flowgrid/internal/api"
)

func main() {
	if err := api.Run(context.Background()); err != nil {
		log.Fatalf("serviço encerrado com erro: %v", err)
	}
}
