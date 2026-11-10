# Optional xgl_check gate binary

The driver's deterministic graph-validation gate uses the
`xgl_check` binary from [xdp-graph-lib]. It is not baked into the
image (xdp-graph-lib is a separate repository); mount it instead:

1. Compile it (standalone C, no dependencies):

   ```sh
   cc -I <xdp-graph-lib>/include -o /usr/local/bin/xgl_check \
      <xdp-graph-lib>/tools/xgl_check.c \
      <xdp-graph-lib>/src/userspace/xgl_check.c
   ```

2. Mount it into the driver pod and point the driver at it:

   ```yaml
   # in the DaemonSet
   args:
     - --xgl-check-bin=/usr/local/bin/xgl_check
   volumes:
     - name: xgl-check
       hostPath:
         path: /usr/local/bin/xgl_check
         type: File
   volumeMounts:
     - name: xgl-check
       mountPath: /usr/local/bin/xgl_check
       readOnly: true
   ```

Without the binary the gate is disabled; the driver still enforces
queue uniqueness through its allocation state, but the offline
graph checks (filter disjointness, resource dedication, declared
topology) run only with the gate enabled.

[xdp-graph-lib]: https://github.com/fabiendupont/xdp-graph-lib
