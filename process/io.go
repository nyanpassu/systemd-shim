package process

import (
	// "sync"
	"context"
	"net/url"

	// "os"

	// "github.com/juju/errors"

	"github.com/nyanpassu/systemd-shim/runc"
	"github.com/nyanpassu/systemd-shim/stdio"
)

type processIO struct {
	io runc.IO

	uri   *url.URL
	copy  bool
	stdio stdio.Stdio
}

func (p *processIO) Close() error {
	if p.io != nil {
		return p.io.Close()
	}
	return nil
}

func (p *processIO) IO() runc.IO {
	return p.io
}

// func (p *processIO) Copy(ctx context.Context, wg *sync.WaitGroup) error {
// 	if !p.copy {
// 		return nil
// 	}
// 	var cwg sync.WaitGroup
// 	if err := copyPipes(ctx, p.IO(), p.stdio.Stdin, p.stdio.Stdout, p.stdio.Stderr, wg, &cwg); err != nil {
// 		return errors.Maskf(err, "unable to copy pipes")
// 	}
// 	cwg.Wait()
// 	return nil
// }

// func copyPipes(ctx context.Context, rio runc.IO, stdin, stdout, stderr string, wg, cwg *sync.WaitGroup) error {
// 	var sameFile *countingWriteCloser
// 	for _, i := range []struct {
// 		name string
// 		dest func(wc io.WriteCloser, rc io.Closer)
// 	}{
// 		{
// 			name: stdout,
// 			dest: func(wc io.WriteCloser, rc io.Closer) {
// 				wg.Add(1)
// 				cwg.Add(1)
// 				go func() {
// 					cwg.Done()
// 					p := bufPool.Get().(*[]byte)
// 					defer bufPool.Put(p)
// 					if _, err := io.CopyBuffer(wc, rio.Stdout(), *p); err != nil {
// 						log.G(ctx).Warn("error copying stdout")
// 					}
// 					wg.Done()
// 					wc.Close()
// 					if rc != nil {
// 						rc.Close()
// 					}
// 				}()
// 			},
// 		}, {
// 			name: stderr,
// 			dest: func(wc io.WriteCloser, rc io.Closer) {
// 				wg.Add(1)
// 				cwg.Add(1)
// 				go func() {
// 					cwg.Done()
// 					p := bufPool.Get().(*[]byte)
// 					defer bufPool.Put(p)
// 					if _, err := io.CopyBuffer(wc, rio.Stderr(), *p); err != nil {
// 						log.G(ctx).Warn("error copying stderr")
// 					}
// 					wg.Done()
// 					wc.Close()
// 					if rc != nil {
// 						rc.Close()
// 					}
// 				}()
// 			},
// 		},
// 	} {
// 		ok, err := sys.IsFifo(i.name)
// 		if err != nil {
// 			return err
// 		}
// 		var (
// 			fw io.WriteCloser
// 			fr io.Closer
// 		)
// 		if ok {
// 			if fw, err = fifo.OpenFifo(ctx, i.name, syscall.O_WRONLY, 0); err != nil {
// 				return errors.Wrapf(err, "containerd-shim: opening w/o fifo %q failed", i.name)
// 			}
// 			if fr, err = fifo.OpenFifo(ctx, i.name, syscall.O_RDONLY, 0); err != nil {
// 				return errors.Wrapf(err, "containerd-shim: opening r/o fifo %q failed", i.name)
// 			}
// 		} else {
// 			if sameFile != nil {
// 				sameFile.count++
// 				i.dest(sameFile, nil)
// 				continue
// 			}
// 			if fw, err = os.OpenFile(i.name, syscall.O_WRONLY|syscall.O_APPEND, 0); err != nil {
// 				return errors.Wrapf(err, "containerd-shim: opening file %q failed", i.name)
// 			}
// 			if stdout == stderr {
// 				sameFile = &countingWriteCloser{
// 					WriteCloser: fw,
// 					count:       1,
// 				}
// 			}
// 		}
// 		i.dest(fw, fr)
// 	}
// 	if stdin == "" {
// 		return nil
// 	}
// 	f, err := fifo.OpenFifo(context.Background(), stdin, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
// 	if err != nil {
// 		return fmt.Errorf("containerd-shim: opening %s failed: %s", stdin, err)
// 	}
// 	cwg.Add(1)
// 	go func() {
// 		cwg.Done()
// 		p := bufPool.Get().(*[]byte)
// 		defer bufPool.Put(p)

// 		io.CopyBuffer(rio.Stdin(), f, *p)
// 		rio.Stdin().Close()
// 		f.Close()
// 	}()
// 	return nil
// }

func createIO(ctx context.Context, id string, ioUID, ioGID int, stdio stdio.Stdio) (*processIO, error) {
	pio := &processIO{
		stdio: stdio,
	}
	i, err := runc.NewNullIO()
	if err != nil {
		return nil, err
	}
	pio.io = i
	return pio, nil
	// if stdio.IsNull() {
	// 	i, err := runc.NewNullIO()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	pio.io = i
	// 	return pio, nil
	// }
	// u, err := url.Parse(stdio.Stdout)
	// if err != nil {
	// 	return nil, errors.Maskf(err, "unable to parse stdout uri")
	// }
	// if u.Scheme == "" {
	// 	u.Scheme = "fifo"
	// }
	// pio.uri = u
	// switch u.Scheme {
	// case "fifo":
	// 	pio.copy = true
	// 	pio.io, err = runc.NewPipeIO(ioUID, ioGID, withConditionalIO(stdio))
	// case "binary":
	// 	pio.io, err = NewBinaryIO(ctx, id, u)
	// case "file":
	// 	filePath := u.Path
	// 	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
	// 		return nil, err
	// 	}
	// 	var f *os.File
	// 	f, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	f.Close()
	// 	pio.stdio.Stdout = filePath
	// 	pio.stdio.Stderr = filePath
	// 	pio.copy = true
	// 	pio.io, err = runc.NewPipeIO(ioUID, ioGID, withConditionalIO(stdio))
	// default:
	// 	return nil, errors.Errorf("unknown STDIO scheme %s", u.Scheme)
	// }
	// if err != nil {
	// 	return nil, err
	// }
	// return pio, nil
}
