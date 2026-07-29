package main

import (
	"os"

	"github.com/MB3R-Lab/Procrustes/internal/app"
)

func main() {
	os.Exit(app.New(os.Stdout, os.Stderr).Run(os.Args[1:]))
}
