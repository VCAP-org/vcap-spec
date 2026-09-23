#!/bin/sh
# Is the vcap-spec corpus a consumer is pinned to still the one upstream has?
# Run from the consumer's own suite; `$1` is the path to its
# `conformance-pin.json` (default: the one in the working directory).
#
# The spec checkout to inspect is not an argument: it is the directory this
# script was delivered into. A consumer runs `spec/tools/corpus-drift.sh`, or
# `verifier/spec/tools/corpus-drift.sh` when the corpus arrives through
# vcap-verifier, and in both cases the checkout one level up is the pinned one.
# That is also why hosting the check inside the repository it checks is sound:
# it reads the submodule checkout's own git data, whose `origin` is vcap-spec,
# and never the working copy it happens to sit in. Run inside a development
# checkout of vcap-spec itself there is no pin to compare, and it skips.
#
# Why it exists: `git submodule update --init` checks out the *pinned* commit,
# so a pin nobody moved keeps the suite green forever against an old contract.
# Three repositories sat two weeks behind and nothing said so — the drift was
# found by hand, during a documentation audit.
#
# Why it stays quiet: it compares only the numbered vector directories, which
# are the behaviour this repository is checked against. Upstream churn in
# CHANGELOG.md, README.md, the tooling or the `_watermark/` decoder fixtures
# moves no vector and prints nothing here. When this fails, something the suite
# actually runs has changed.
#
# Why it can be believed: no network is a SKIP, never a failure, so it cannot
# train anyone to ignore red. A real failure has exactly two ways out — take
# the new corpus, or write down why you are not taking it — and both are a
# dated line in `conformance-pin.json` that a reviewer reads. Waiting is not
# one of them.
#
# Why one copy: this was three identical copies, one per consumer, and a drift
# detector that can itself drift means different things in different
# repositories — the exact failure it exists to catch. The consequence of
# living here is that a consumer runs the version its submodule pins, so a fix
# reaches it when it bumps; bumping is the act this check exists to force.
set -eu

spec=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pin=${1:-conformance-pin.json}

say() { echo "[vcap] $*"; }

# One string field out of the pin record. A `null` reads as empty, which is
# what "no exception recorded" has to mean.
field() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$pin" | head -1
}

sha() { if command -v shasum >/dev/null 2>&1; then shasum -a 256; else sha256sum; fi | cut -d' ' -f1; }

# The numbered vectors of a revision, as git's own content ids. Reading the
# tree rather than the working copy is what lets the same digest be taken of a
# commit that is not checked out.
tab=$(printf '\t')
digest() { git -C "$spec" ls-tree -r "$1" -- vectors/ | grep "${tab}vectors/[0-9]" | sha; }

[ -f "$pin" ] || { say "SKIP corpus drift: no $pin in this repository"; exit 0; }
if ! git -C "$spec" rev-parse --git-dir >/dev/null 2>&1; then
  say "SKIP corpus drift: $spec is not a checkout (git submodule update --init --recursive)"
  exit 0
fi

here=$(digest HEAD)
recorded=$(field vectors_sha256)
if [ "$recorded" != "$here" ]; then
  say "PIN NOT RECORDED — $spec is at numbered vectors $here, conformance-pin.json says $recorded."
  say "  A submodule bump is only done when the pin that describes it is updated in the same commit."
  exit 1
fi

# Upstream is the question this check exists for, and it is the only part that
# needs the network. Not having it is a fact about the machine, not about the
# corpus, so it is said out loud and passed.
if ! git -C "$spec" fetch --quiet origin main 2>/dev/null; then
  say "SKIP corpus drift: cannot reach vcap-spec. The pin was not compared with upstream."
  exit 0
fi

there=$(digest FETCH_HEAD)
version=$(field corpus_version)

if [ "$here" = "$there" ]; then
  say "corpus $version is vcap-spec main's numbered corpus (vectors $here)"
  # The corpus can be renamed without a vector moving — 1.1.0 became 1.3.0 on
  # decoder fixtures and prose alone. That is a stale label and not a stale
  # gate, so it is a note and never a failure: making it red would teach people
  # that red can mean nothing.
  upstream_version=$(git -C "$spec" show FETCH_HEAD:vectors/VERSION 2>/dev/null | tr -d '[:space:]')
  if [ -n "$upstream_version" ] && [ "$upstream_version" != "$version" ]; then
    say "note: upstream calls the same vectors $upstream_version. Bumping the submodule changes the label and nothing this suite runs."
  fi
  exit 0
fi

if [ "$(field accepted_upstream_vectors_sha256)" = "$there" ]; then
  say "corpus $version is behind vcap-spec main on purpose: $(field reason_for_staying_behind)"
  say "  recorded $(field reviewed_on) against upstream vectors $there"
  exit 0
fi

say "CORPUS DRIFT — the numbered vectors moved upstream and this repository is pinned behind them."
say "  pinned    corpus $version, vectors $here"
say "  upstream  vcap-spec main, vectors $there"
say "  vector directories that differ:"
git -C "$spec" diff --name-only HEAD FETCH_HEAD -- vectors/ |
  sed -n 's#^vectors/\([0-9][^/]*\)/.*#\1#p' | sort -u | sed 's/^/[vcap]     /'
say "  Two ways out, both a dated line in conformance-pin.json that a reviewer reads:"
say "    take it    — move $spec to vcap-spec main, run this script, record the digests it prints"
say "    refuse it  — set accepted_upstream_vectors_sha256 to $there and say why in reason_for_staying_behind"
exit 1
