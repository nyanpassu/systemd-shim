package runc

import (
	"context"
	"time"

	"github.com/containerd/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type impl struct{}

func New(root, path, namespace, runtime, criu string, systemd bool) Runc {
	return nil
}

func (runc *impl) List(context context.Context) ([]*Container, error) {
	return nil, errdefs.ErrNotImplemented
}

func (runc *impl) State(context context.Context, id string) (*Container, error) {
	return nil, errdefs.ErrNotImplemented
}

func (runc *impl) Create(context context.Context, id, bundle string, opts *CreateOpts) error {
	return errdefs.ErrNotImplemented
}

func (runc *impl) Start(context context.Context, id string) error {
	return errdefs.ErrNotImplemented
}

func (runc *impl) Exec(context context.Context, id string, spec specs.Process, opts *ExecOpts) error {
	return errdefs.ErrNotImplemented
}

func (runc *impl) Run(context context.Context, id, bundle string, opts *CreateOpts) (int, error) {
	return 0, errdefs.ErrNotImplemented
}

func (runc *impl) Delete(context context.Context, id string, opts *DeleteOpts) error {
	return errdefs.ErrNotImplemented
}

func (runc *impl) Kill(context context.Context, id string, sig int, opts *KillOpts) error {
	return errdefs.ErrNotImplemented
}

func (runc *impl) Stats(context context.Context, id string) (*Stats, error) {
	return nil, errdefs.ErrNotImplemented
}

func (runc *impl) Events(context context.Context, id string, interval time.Duration) (chan *Event, error) {
	return nil, errdefs.ErrNotImplemented
}

func (runc *impl) Pause(context context.Context, id string) error {
	return errdefs.ErrNotImplemented
}

func (runc *impl) Resume(context context.Context, id string) error {
	return errdefs.ErrNotImplemented
}

func (runc *impl) Ps(context context.Context, id string) ([]int, error) {
	return nil, errdefs.ErrNotImplemented
}

func (runc *impl) Top(context context.Context, id string, psOptions string) (*TopResults, error) {
	return nil, errdefs.ErrNotImplemented
}

func (runc *impl) Checkpoint(context context.Context, id string, opts *CheckpointOpts, actions ...CheckpointAction) error {
	return errdefs.ErrNotImplemented
}

func (runc *impl) Restore(context context.Context, id, bundle string, opts *RestoreOpts) (int, error) {
	return 0, errdefs.ErrNotImplemented
}

func (runc *impl) Update(context context.Context, id string, resources *specs.LinuxResources) error {
	return errdefs.ErrNotImplemented
}

func (runc *impl) Version(context context.Context) (Version, error) {
	return Version{}, errdefs.ErrNotImplemented
}

func GetLastRuntimeError(r Runc) (string, error) {
	return "", nil
}
