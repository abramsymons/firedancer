# Runtime image for a vseqd binary built on the host (make -j vseqd).
# The binary only needs libc and libm.  It is built with -march=native,
# so the image runs on the machine that built it.
FROM ubuntu:24.04
COPY vseqd /usr/local/bin/vseqd
RUN mkdir -p /data
ENTRYPOINT ["/usr/local/bin/vseqd"]
