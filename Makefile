.PHONY: binary

binary:
	go build -o containerd-shim-eru-v2 shim.go

install:
	cp containerd-shim-eru-v2 /usr/local/bin/