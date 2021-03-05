package main

import (
	"github.com/containerd/containerd/runtime/v2/shim"

	v2 "github.com/nyanpassu/systemd-shim/v2"
)

func main() {
	// init and execute the shim
	shim.Run("io.containerd.systemd.v1", v2.New)
}
