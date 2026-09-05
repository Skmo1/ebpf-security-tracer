// Command detector charge le programme eBPF et affiche/alerte sur les
// événements suspects (execve suivi de connect dans une courte fenêtre).
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" detector ../../bpf/detector.bpf.c -- -I../../bpf

// event doit correspondre exactement au layout de la struct C côté kernel.
type event struct {
	Pid      uint32
	Ppid     uint32
	Type     uint8
	_        [3]byte // padding pour alignement
	Comm     [16]byte
	Filename [256]byte
	Daddr    uint32
	Dport    uint16
	_        [2]byte
}

// recentExec garde en mémoire les process récemment exécutés,
// pour détecter un connect() qui suit un execve() suspect.
var recentExec = map[uint32]time.Time{}

const suspicionWindow = 5 * time.Second

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("suppression de la limite memlock: %v", err)
	}

	objs := detectorObjects{}
	if err := loadDetectorObjects(&objs, nil); err != nil {
		log.Fatalf("chargement des objets eBPF: %v", err)
	}
	defer objs.Close()

	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("attache tracepoint execve: %v", err)
	}
	defer tpExec.Close()

	kpConnect, err := link.Kprobe("tcp_v4_connect", objs.TraceConnect, nil)
	if err != nil {
		log.Fatalf("attache kprobe connect: %v", err)
	}
	defer kpConnect.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ouverture du ring buffer: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		rd.Close()
	}()

	fmt.Println("Détecteur eBPF démarré. Ctrl+C pour arrêter.")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("erreur lecture ring buffer: %v", err)
			continue
		}

		var e event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("erreur parsing événement: %v", err)
			continue
		}

		handleEvent(&e)
	}
}

func handleEvent(e *event) {
	comm := cString(e.Comm[:])

	switch e.Type {
	case 0: // execve
		filename := cString(e.Filename[:])
		fmt.Printf("[EXEC] pid=%d ppid=%d comm=%s file=%s\n", e.Pid, e.Ppid, comm, filename)
		recentExec[e.Pid] = time.Now()

	case 1: // connect
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, e.Daddr)
		fmt.Printf("[CONNECT] pid=%d comm=%s dst=%s:%d\n", e.Pid, comm, ip, e.Dport)

		if t, ok := recentExec[e.Pid]; ok && time.Since(t) < suspicionWindow {
			fmt.Printf("  ⚠️  ALERTE: pid=%d (%s) a exécuté un programme puis "+
				"ouvert une connexion réseau en moins de %s — pattern suspect\n",
				e.Pid, comm, suspicionWindow)
		}
	}
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
