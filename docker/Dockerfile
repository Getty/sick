# syntax=docker/dockerfile:1
#
# The sick image: Perl, SICK and SICK-Target-CiscoSB, and the programs a run
# calls - step, acme.sh (with its deploy hooks), openssl, ssh.
#
# Build context: a directory that holds both source trees side by side,
#
#   <context>/sick/                   this repository
#   <context>/sick-target-ciscosb/    SICK-Target-CiscoSB
#
# which is what "docker compose -f docker/compose.yml build" uses when the
# two checkouts are neighbours (see README.md). Only what is copied below is
# sent to the builder: Dockerfile.dockerignore keeps everything else out.
#
# Once the distributions are on CPAN: --build-arg SICK_FROM=cpan. The source
# of SICK-Target-CiscoSB is not needed then.

ARG DEBIAN_RELEASE=trixie
ARG STEP_VERSION=0.30.2
ARG SICK_FROM=local

FROM smallstep/step-cli:${STEP_VERSION} AS step

FROM debian:${DEBIAN_RELEASE}-slim AS base

# perl brings every core module SICK uses; YAML::PP is its one dependency.
# curl is for the deploy hooks of acme.sh that talk to an HTTP API,
# openssh-client for SICK-Target-CiscoSB and for hooks that use ssh and scp.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl libyaml-pp-perl openssh-client openssl perl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=step /usr/local/bin/step /usr/local/bin/step

# acme.sh is here for its deploy hooks only. It is unpacked, not installed:
# no cron job, no account, nothing in a home directory. The hooks are looked
# for next to the real file, so the script stays beside its deploy/
# directory and gets on the PATH through a symbolic link.
ARG ACME_SH_VERSION=3.1.6
ARG ACME_SH_SHA256=0d3f9000ac44a6331314742a88c475f79134e24fc991997883652adc59efc486
RUN curl -fsSL -o /tmp/acme.sh.tar.gz \
      "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_VERSION}.tar.gz" \
 && echo "${ACME_SH_SHA256}  /tmp/acme.sh.tar.gz" | sha256sum -c - \
 && mkdir /opt/acme.sh \
 && tar -xzf /tmp/acme.sh.tar.gz -C /opt/acme.sh --strip-components=1 \
      "acme.sh-${ACME_SH_VERSION}/acme.sh" \
      "acme.sh-${ACME_SH_VERSION}/deploy" \
      "acme.sh-${ACME_SH_VERSION}/LICENSE.md" \
 && rm /tmp/acme.sh.tar.gz \
 && ln -s /opt/acme.sh/acme.sh /usr/local/bin/acme.sh

# SICK and its targets, from the source trees of the build context ...
FROM base AS from-local
COPY sick/lib/ /usr/local/lib/site_perl/
COPY sick-target-ciscosb/lib/ /usr/local/lib/site_perl/
COPY --chmod=0755 sick/bin/sick /usr/local/bin/sick

# ... or from CPAN
FROM base AS from-cpan
RUN apt-get update \
 && apt-get install -y --no-install-recommends cpanminus make \
 && cpanm --notest SICK SICK::Target::CiscoSB \
 && rm -rf /var/lib/apt/lists/* /root/.cpanm

FROM from-${SICK_FROM}

COPY --chmod=0755 sick/docker/entrypoint.sh /usr/local/bin/sick-entrypoint

# ssh remembers host keys in the state directory - for SICK-Target-CiscoSB
# as for every acme.sh hook that uses ssh or scp. The home of root is on the
# read-only file system of the container, and ssh takes it from the password
# database, not from $HOME.
RUN mkdir -p /etc/sick /var/lib/sick /srv/trust \
 && printf 'Host *\n    UserKnownHostsFile /var/lib/sick/known_hosts\n' >/etc/ssh/ssh_config.d/sick.conf \
 && sick --version \
 && perl -MSICK::Target::CiscoSB -e 'print "SICK::Target::CiscoSB ", SICK::Target::CiscoSB->VERSION, "\n"' \
 && step version \
 && acme.sh --version \
 && test -r /opt/acme.sh/deploy/localcopy.sh

ENV SICK_CONFIG=/etc/sick/sick.yml \
    SICK_TRUST_DIR=/srv/trust \
    HOME=/var/lib/sick \
    TMPDIR=/tmp

ENTRYPOINT ["sick-entrypoint"]
