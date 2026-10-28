# Carries the daemons to talos-installer, which takes them from this image by digest. Each
# daemon's extension-service spec rides along, so a binary and the paths it expects always
# come from the same commit. The binaries are built beforehand for the image's arch and staged
# at target/<TARGETARCH>/release/.
FROM scratch
ARG TARGETARCH
COPY target/${TARGETARCH}/release/awg \
     target/${TARGETARCH}/release/router \
     target/${TARGETARCH}/release/nftables \
     target/${TARGETARCH}/release/slipmesh-taloscfg \
     /usr/local/bin/
COPY extension-services/awg.yaml \
     extension-services/router.yaml \
     extension-services/nftables.yaml \
     /usr/local/etc/containers/
