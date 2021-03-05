// +build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package v2

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/cgroups"
	cgroupsv2 "github.com/containerd/cgroups/v2"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/containerd/runtime/v2/shim"
	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/proto"
	"github.com/juju/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/oom"
	oomv1 "github.com/containerd/containerd/pkg/oom/v1"
	oomv2 "github.com/containerd/containerd/pkg/oom/v2"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	ptypes "github.com/gogo/protobuf/types"

	"github.com/nyanpassu/systemd-shim/container"
	"github.com/nyanpassu/systemd-shim/events"
	"github.com/nyanpassu/systemd-shim/process"
	"github.com/nyanpassu/systemd-shim/reaper"
	"github.com/nyanpassu/systemd-shim/runc"
	"github.com/nyanpassu/systemd-shim/stdio"
)

// var (
// 	// check to make sure the *service implements the GRPC API
// 	_ = (taskAPI.TaskService)(&service{})
// 	// common response type
// 	empty = &ptypes.Empty{}
// )

var groupLabels = []string{
	"io.containerd.runc.v2.group",
	"io.kubernetes.cri.sandbox-id",
}

type spec struct {
	Annotations map[string]string `json:"annotations,omitempty"`
}

// New returns a new shim service
func New(ctx context.Context, id string, publisher shim.Publisher, shutdown func()) (shim.Shim, error) {
	var (
		ep  oom.Watcher
		err error
	)
	if cgroups.Mode() == cgroups.Unified {
		ep, err = oomv2.New(publisher)
	} else {
		ep, err = oomv1.New(publisher)
	}
	if err != nil {
		return nil, err
	}
	go ep.Run(ctx)
	s := &service{
		id:      id,
		context: ctx,
		events:  make(chan interface{}, 128),
		ec:      reaper.Default.Subscribe(),
		// ep:         ep,
		// cancel:     shutdown,
		containers: make(map[string]*container.Container),
	}
	go s.processExits()
	// runcC.Monitor = reaper.Default

	if err := s.initPlatform(); err != nil {
		shutdown()
		return nil, errors.Maskf(err, "failed to initialized platform behavior")
	}
	go s.forward(ctx, publisher)

	if address, err := shim.ReadAddress("address"); err == nil {
		s.shimAddress = address
	}
	return s, nil
}

type service struct {
	id string

	mu          sync.Mutex
	eventSendMu sync.Mutex

	platform   stdio.Platform
	containers map[string]*container.Container

	events chan interface{}

	context context.Context
	ec      chan runc.Exit

	shimAddress string
}

// StartShim is a binary call that executes a new shim returning the address
func (s *service) StartShim(ctx context.Context, id, containerdBinary, containerdAddress, containerdTTRPCAddress string) (_ string, retErr error) {
	cmd, err := newCommand(ctx, id, containerdBinary, containerdAddress, containerdTTRPCAddress)
	if err != nil {
		return "", err
	}
	grouping := id
	spec, err := readSpec()
	if err != nil {
		return "", err
	}
	for _, group := range groupLabels {
		if groupID, ok := spec.Annotations[group]; ok {
			grouping = groupID
			break
		}
	}
	address, err := shim.SocketAddress(ctx, containerdAddress, grouping)
	if err != nil {
		return "", err
	}

	socket, err := shim.NewSocket(address)
	if err != nil {
		// the only time where this would happen is if there is a bug and the socket
		// was not cleaned up in the cleanup method of the shim or we are using the
		// grouping functionality where the new process should be run with the same
		// shim as an existing container
		if !shim.SocketEaddrinuse(err) {
			return "", errors.Maskf(err, "create new shim socket")
		}
		if shim.CanConnect(address) {
			if err := shim.WriteAddress("address", address); err != nil {
				return "", errors.Maskf(err, "write existing socket for shim")
			}
			return address, nil
		}
		if err := shim.RemoveSocket(address); err != nil {
			return "", errors.Maskf(err, "remove pre-existing socket")
		}
		if socket, err = shim.NewSocket(address); err != nil {
			return "", errors.Maskf(err, "try create new shim socket 2x")
		}
	}
	defer func() {
		if retErr != nil {
			socket.Close()
			_ = shim.RemoveSocket(address)
		}
	}()
	f, err := socket.File()
	if err != nil {
		return "", err
	}

	cmd.ExtraFiles = append(cmd.ExtraFiles, f)

	if err := cmd.Start(); err != nil {
		f.Close()
		return "", err
	}
	defer func() {
		if retErr != nil {
			cmd.Process.Kill()
		}
	}()
	// make sure to wait after start
	go cmd.Wait()
	if err := shim.WriteAddress("address", address); err != nil {
		return "", err
	}
	if data, err := ioutil.ReadAll(os.Stdin); err == nil {
		if len(data) > 0 {
			var any ptypes.Any
			if err := proto.Unmarshal(data, &any); err != nil {
				return "", err
			}
			v, err := typeurl.UnmarshalAny(&any)
			if err != nil {
				return "", err
			}
			if opts, ok := v.(*options.Options); ok {
				if opts.ShimCgroup != "" {
					if cgroups.Mode() == cgroups.Unified {
						if err := cgroupsv2.VerifyGroupPath(opts.ShimCgroup); err != nil {
							return "", errors.Maskf(err, "failed to verify cgroup path %q", opts.ShimCgroup)
						}
						cg, err := cgroupsv2.LoadManager("/sys/fs/cgroup", opts.ShimCgroup)
						if err != nil {
							return "", errors.Maskf(err, "failed to load cgroup %s", opts.ShimCgroup)
						}
						if err := cg.AddProc(uint64(cmd.Process.Pid)); err != nil {
							return "", errors.Maskf(err, "failed to join cgroup %s", opts.ShimCgroup)
						}
					} else {
						cg, err := cgroups.Load(cgroups.V1, cgroups.StaticPath(opts.ShimCgroup))
						if err != nil {
							return "", errors.Maskf(err, "failed to load cgroup %s", opts.ShimCgroup)
						}
						if err := cg.Add(cgroups.Process{
							Pid: cmd.Process.Pid,
						}); err != nil {
							return "", errors.Maskf(err, "failed to join cgroup %s", opts.ShimCgroup)
						}
					}
				}
			}
		}
	}
	if err := shim.AdjustOOMScore(cmd.Process.Pid); err != nil {
		return "", errors.Wrap(err, errors.New("failed to adjust OOM score for shim"))
	}
	return address, nil
}

// Cleanup is a binary call that cleans up any resources used by the shim when the service crashes
func (s *service) Cleanup(ctx context.Context) (*taskAPI.DeleteResponse, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Dir(cwd), s.id)
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	runtime, err := container.ReadRuntime(path)
	if err != nil {
		return nil, err
	}
	opts, err := container.ReadOptions(path)
	if err != nil {
		return nil, err
	}
	root := process.RuncRoot
	if opts != nil && opts.Root != "" {
		root = opts.Root
	}

	r := runc.New(root, path, ns, runtime, "", false)
	if err := r.Delete(ctx, s.id, &runc.DeleteOpts{
		Force: true,
	}); err != nil {
		logrus.WithError(err).Warn("failed to remove runc container")
	}
	if err := mount.UnmountAll(filepath.Join(path, "rootfs"), 0); err != nil {
		logrus.WithError(err).Warn("failed to cleanup rootfs mount")
	}
	return &taskAPI.DeleteResponse{
		ExitedAt:   time.Now(),
		ExitStatus: 128 + uint32(unix.SIGKILL),
	}, nil
}

// Create a new container
func (s *service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (_ *taskAPI.CreateTaskResponse, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	container, err := container.NewContainer(ctx, s.platform, r)
	if err != nil {
		return nil, err
	}

	s.containers[r.ID] = container

	s.send(&eventstypes.TaskCreate{
		ContainerID: r.ID,
		Bundle:      r.Bundle,
		Rootfs:      r.Rootfs,
		IO: &eventstypes.TaskIO{
			Stdin:    r.Stdin,
			Stdout:   r.Stdout,
			Stderr:   r.Stderr,
			Terminal: r.Terminal,
		},
		Checkpoint: r.Checkpoint,
		Pid:        uint32(container.Pid()),
	})

	return &taskAPI.CreateTaskResponse{
		Pid: uint32(container.Pid()),
	}, nil
}

// Start the primary user process inside the container
func (s *service) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

// Delete a process or container
func (s *service) Delete(ctx context.Context, r *taskAPI.DeleteRequest) (*taskAPI.DeleteResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

// Exec an additional process inside the container
func (s *service) Exec(ctx context.Context, r *taskAPI.ExecProcessRequest) (*ptypes.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

// ResizePty of a process
func (s *service) ResizePty(ctx context.Context, r *taskAPI.ResizePtyRequest) (*ptypes.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

// State returns runtime state of a process
func (s *service) State(ctx context.Context, r *taskAPI.StateRequest) (*taskAPI.StateResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

// Pause the container
func (s *service) Pause(ctx context.Context, r *taskAPI.PauseRequest) (*ptypes.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

// Resume the container
func (s *service) Resume(ctx context.Context, r *taskAPI.ResumeRequest) (*ptypes.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

// Kill a process
func (s *service) Kill(ctx context.Context, r *taskAPI.KillRequest) (*ptypes.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

// Pids returns all pids inside the container
func (s *service) Pids(ctx context.Context, r *taskAPI.PidsRequest) (*taskAPI.PidsResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

// CloseIO of a process
func (s *service) CloseIO(ctx context.Context, r *taskAPI.CloseIORequest) (*ptypes.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

// Checkpoint the container
func (s *service) Checkpoint(ctx context.Context, r *taskAPI.CheckpointTaskRequest) (*ptypes.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

// Connect returns shim information of the underlying service
func (s *service) Connect(ctx context.Context, r *taskAPI.ConnectRequest) (*taskAPI.ConnectResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

// Shutdown is called after the underlying resources of the shim are cleaned up and the service can be stopped
func (s *service) Shutdown(ctx context.Context, r *taskAPI.ShutdownRequest) (*ptypes.Empty, error) {
	os.Exit(0)
	return nil, nil
}

// Stats returns container level system stats for a container and its processes
func (s *service) Stats(ctx context.Context, r *taskAPI.StatsRequest) (*taskAPI.StatsResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

// Update the live container
func (s *service) Update(ctx context.Context, r *taskAPI.UpdateTaskRequest) (*ptypes.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

// Wait for a process to exit
func (s *service) Wait(ctx context.Context, r *taskAPI.WaitRequest) (*taskAPI.WaitResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *service) send(evt interface{}) {
	s.events <- evt
}

func (s *service) processExits() {
	for e := range s.ec {
		s.checkProcesses(e)
	}
}

// initialize a single epoll fd to manage our consoles. `initPlatform` should
// only be called once.
func (s *service) initPlatform() error {
	if s.platform != nil {
		return nil
	}
	p, err := stdio.NewPlatform()
	if err != nil {
		return err
	}
	s.platform = p
	return nil
}

func (s *service) forward(ctx context.Context, publisher shim.Publisher) {
	ns, _ := namespaces.Namespace(ctx)
	ctx = namespaces.WithNamespace(context.Background(), ns)
	for e := range s.events {
		err := publisher.Publish(ctx, events.GetTopic(e), e)
		if err != nil {
			logrus.WithError(err).Error("post event")
		}
	}
	publisher.Close()
}

func (s *service) sendL(evt interface{}) {
	s.eventSendMu.Lock()
	s.events <- evt
	s.eventSendMu.Unlock()
}

func (s *service) checkProcesses(e runc.Exit) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range s.containers {
		if !c.HasPid(e.Pid) {
			continue
		}

		for _, p := range c.All() {
			if p.Pid() != e.Pid {
				continue
			}

			if ip, ok := p.(*process.Init); ok {
				// Ensure all children are killed
				if container.ShouldKillAllOnExit(s.context, c.Bundle) {
					if err := ip.KillAll(s.context); err != nil {
						logrus.WithError(err).WithField("id", ip.ID()).
							Error("failed to kill init's children")
					}
				}
			}

			p.SetExited(e.Status)
			s.sendL(&eventstypes.TaskExit{
				ContainerID: c.ID,
				ID:          p.ID(),
				Pid:         uint32(e.Pid),
				ExitStatus:  uint32(e.Status),
				ExitedAt:    p.ExitedAt(),
			})
			return
		}
		return
	}
}

func newCommand(ctx context.Context, id, containerdBinary, containerdAddress, containerdTTRPCAddress string) (*exec.Cmd, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-namespace", ns,
		"-id", id,
		"-address", containerdAddress,
	}
	cmd := exec.Command(self, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GOMAXPROCS=4")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd, nil
}

func readSpec() (*spec, error) {
	f, err := os.Open("config.json")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s spec
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}
