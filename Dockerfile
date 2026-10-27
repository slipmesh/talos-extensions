# Carries the binaries to talos-installer, which takes the daemons from this image by digest.
# They are built beforehand for the image's arch and staged at target/<TARGETARCH>/release/.
FROM scratch
ARG TARGETARCH
COPY target/${TARGETARCH}/release/awg \
     target/${TARGETARCH}/release/router \
     target/${TARGETARCH}/release/nftables \
     target/${TARGETARCH}/release/slipmesh-taloscfg \
     /usr/local/bin/
