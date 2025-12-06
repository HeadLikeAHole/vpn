package tun

import (
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// interface flags (IFF[...])
const (
	// create a TUN device
	IFFTUN = 0x0001
	// multiple queues for parallel packet processing
	IFFMULTIQUEUE = 0x0100
	// don't add packet info header
	IFFNOPI = 0x1000
)

type Tun struct {
	name string
	io.ReadWriteCloser
}

func New(name string) (*Tun, error) {
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fdPtr := uintptr(fd)
	name, err = setupFD(fdPtr, name)
	if err != nil {
		return nil, err
	}
	return &Tun{
		name:            name,
		ReadWriteCloser: os.NewFile(fdPtr, "tun"),
	}, nil
}

func (t *Tun) Name() string {
	return t.name
}

// The Linux kernel API requires struct ifreq to be exactly
// 40 bytes for historical compatibility reasons.
// name: 16 bytes (0x10 = 16)
// flags: 2 bytes
// pad: 22 bytes (0x28 - 0x10 - 2 = 40 - 16 - 2 = 22)
// total: 40 bytes (0x28 = 40)
type ifReq struct {
	name  [0x10]byte // null-terminated C string
	flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func setupFD(fd uintptr, name string) (string, error) {
	var req ifReq
	copy(req.name[:], name)
	req.flags = IFFTUN | IFFMULTIQUEUE | IFFNOPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return "", os.NewSyscallError("ioctl", errno)
	}
	// trim c-string
	name = strings.Trim(string(req.name[:]), "\x00")
	return name, nil
}
