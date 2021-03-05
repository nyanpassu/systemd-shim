package process

import (
	"fmt"
	"path/filepath"
	"sync/atomic"

	"github.com/nyanpassu/systemd-shim/runc"
)

const (
	// RuncRoot is the path to the root runc state directory
	RuncRoot = "/run/containerd/runc"
	// InitPidFile name of the file that contains the init pid
	InitPidFile = "init.pid"
)

type atomicBool int32

func (ab *atomicBool) set(b bool) {
	if b {
		atomic.StoreInt32((*int32)(ab), 1)
	} else {
		atomic.StoreInt32((*int32)(ab), 0)
	}
}

func (ab *atomicBool) get() bool {
	return atomic.LoadInt32((*int32)(ab)) == 1
}

type pidFile struct {
	path string
}

func newPidFile(bundle string) *pidFile {
	return &pidFile{
		path: filepath.Join(bundle, InitPidFile),
	}
}

func newExecPidFile(bundle, id string) *pidFile {
	return &pidFile{
		path: filepath.Join(bundle, fmt.Sprintf("%s.pid", id)),
	}
}

func (p *pidFile) Path() string {
	return p.path
}

func (p *pidFile) Read() (int, error) {
	return runc.ReadPidFile(p.path)
}
