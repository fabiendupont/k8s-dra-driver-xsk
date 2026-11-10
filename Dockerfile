# SPDX-License-Identifier: Apache-2.0
#
# dra-xsk-driver image.
#
# Build:
#   docker build -t quay.io/fabiendupont/dra-xsk-driver:latest .
#
# The optional xgl_check gate binary is not baked in (it comes from
# xdp-graph-lib, an internal dependency); mount it via hostPath and
# set --xgl-check-bin in the DaemonSet instead — see docker/README.md.

FROM golang:1.26 AS build
WORKDIR /src

# Dependency layer (cached)
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/dra-xsk ./cmd/driver

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dra-xsk /usr/bin/dra-xsk

# CAP_BPF and CAP_NET_ADMIN are granted via the DaemonSet
# securityContext; the binary itself needs no other privileges.
USER 65532
ENTRYPOINT ["/usr/bin/dra-xsk"]
