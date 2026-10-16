# Runtime image only — the binary is compiled on the host to sidestep the
# QEMU/network issues we hit when running the Go toolchain inside the finch
# build sandbox on Apple Silicon.
FROM public.ecr.aws/docker/library/alpine:3.22
RUN adduser -D -u 10001 quic
COPY quic-server /usr/local/bin/quic-server
USER 10001:10001
EXPOSE 3000/udp
ENTRYPOINT ["/usr/local/bin/quic-server"]
