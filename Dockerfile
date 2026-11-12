# SPDX-License-Identifier: Apache-2.0
#
# dra-xsk-driver image.
#
# Build:
#   docker build -t quay.io/fabiendupont/dra-xsk-driver:latest .
#
# The optional xgl_check gate binary is not baked in (it comes from
# xdp-graph-lib); mount it via hostPath and set --xgl-check-bin in
# the DaemonSet instead — see docker/README.md.
#
# The HSR/PRP RedBox BPF objects (node_hsr_ingress.bpf.o,
# node_hsr_egress.bpf.o) are built from the published xdp-hsr-prp
# repository and installed into /usr/lib/xsk-dra/hsrprp (override
# with --hsrprp-obj-dir).

FROM golang:1.26 AS build
WORKDIR /src

# Dependency layer (cached)
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/dra-xsk ./cmd/driver && \
    CGO_ENABLED=0 go build -trimpath -o /out/hsrbox ./cmd/hsrbox

# xdp-hsr-prp BPF objects (node-local RedBox dataplane). Pinned to a
# commit for reproducibility; bump deliberately. Trixie (not the Go
# stage's bookworm) for a meson/clang new enough for the BPF sources;
# only the .o files are copied out, so the builder distro does not
# affect the runtime image.
FROM debian:trixie-slim AS hsrprp
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        meson ninja-build clang llvm libbpf-dev libxdp-dev pkg-config git ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/fabiendupont/xdp-hsr-prp /src/xdp-hsr-prp
# clang -target bpf does not search the multiarch include dir where
# the kernel UAPI headers' <asm/types.h> lives; expose it explicitly.
RUN ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm
WORKDIR /src/xdp-hsr-prp
RUN meson setup builddir . && \
    ninja -C builddir node_hsr_ingress.bpf.o node_hsr_egress.bpf.o && \
    mkdir -p /out/hsrprp && \
    cp builddir/node_hsr_ingress.bpf.o builddir/node_hsr_egress.bpf.o /out/hsrprp/

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dra-xsk /usr/bin/dra-xsk
COPY --from=build /out/hsrbox /usr/bin/hsrbox
COPY --from=hsrprp /out/hsrprp /usr/lib/xsk-dra/hsrprp

# CAP_BPF and CAP_NET_ADMIN are granted via the DaemonSet
# securityContext; the binary itself needs no other privileges.
USER 65532
ENTRYPOINT ["/usr/bin/dra-xsk"]
