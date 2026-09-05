.PHONY: all generate build run clean vmlinux

BINARY := detector

all: generate build

# Génère vmlinux.h à partir du kernel local (BTF requis: /sys/kernel/btf/vmlinux)
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Génère le code Go collé au programme eBPF via bpf2go
generate:
	cd cmd/detector && go generate ./...

build:
	go build -o bin/$(BINARY) ./cmd/detector

run: build
	sudo ./bin/$(BINARY)

clean:
	rm -rf bin cmd/detector/detector_bpfe*.go cmd/detector/detector_bpfe*.o
