# Building and publishing the wolfTrust manual

`docs/` is the manual source. `mkdocs.yml` defines the page order and
navigation. The adapter in `tools/docs_manual.py` passes those pages to the
shared MkDocs theme and Pandoc/LaTeX PDF rules in
[`wolfSSL/documentation`](https://github.com/wolfSSL/documentation). Keep manual
content and its navigation in wolfTrust; generated files stay under `build/`.

Keep documentation links in `README.md` pointed at the source pages under
`docs/`. Within the manual, use relative links to other manual pages so the
same source works on GitHub and in generated HTML and PDF. Link source files
outside `docs/` to their location in the wolfTrust GitHub repository.

Every top-level Markdown page in `docs/` must appear exactly once in
`mkdocs.yml`. Add new guides and other pages to the README and manual index
too. The adapter refuses missing or duplicate navigation entries; strict
MkDocs builds check the generated HTML links, and PDF preparation checks
manual heading references. The PDF layout reserves wider number columns
for multi-digit subsection labels and limits image height to leave room for
captions above the footer.

## Local build

Clone the documentation build tools at the revision used by wolfTrust CI:

```sh
git clone --recurse-submodules https://github.com/wolfSSL/documentation.git build/documentation
git -C build/documentation checkout "$(cat tools/docs-manual/documentation-rev)"
docker build --pull -t wolftrust-docs:local docker/docs
docker run --rm --user "$(id -u):$(id -g)" --env HOME=/tmp \
    --mount "type=bind,source=$PWD,target=/work/wolfTrust" \
    --workdir /work/wolfTrust wolftrust-docs:local \
    python3 tools/docs_manual.py build \
        --documentation-root /work/wolfTrust/build/documentation \
        --source-root /work/wolfTrust --target all
```

The outputs are `build/documentation/wolfTrust/html/` and
`build/documentation/wolfTrust/wolfTrust-Manual.pdf`. The container includes
MkDocs, Pandoc, LaTeX, and the fonts used by the shared build rules. On a
wolfTrust pull request, `docs-site.yml` checks out the pinned documentation
revision, builds both outputs, runs MkDocs in strict mode, and uploads them as
one artifact. It also runs after documentation changes merge to `main`.
CI pulls the versioned builder image from GHCR, or builds it from
`docker/docs/` if that image is unavailable. No host package installation or
website credentials are needed for this check.

For an HTML preview, first run the build above, then run:

```sh
docker run --rm --user "$(id -u):$(id -g)" --env HOME=/tmp -p 8000:8000 \
    --mount "type=bind,source=$PWD,target=/work/wolfTrust" \
    --workdir /work/wolfTrust/build/documentation/wolfTrust \
    wolftrust-docs:local mkdocs serve -a 0.0.0.0:8000 -f mkdocs.yml
```

The architecture diagram is maintained in `docs/assets/architecture.mmd`.
Regenerate its static image after editing it so HTML and PDF show the same
labels:

```sh
npx --yes @mermaid-js/mermaid-cli@12.0.0 \
    -i docs/assets/architecture.mmd \
    -o docs/assets/architecture.png \
    -b white -c docs/assets/architecture.config.json -s 2
```

## Website update

The planned public locations are:

- [Full wolfTrust manual (HTML)](https://www.wolfssl.com/documentation/manuals/wolftrust/)
- [wolfTrust Manual (PDF)](https://www.wolfssl.com/documentation/manuals/wolftrust/wolfTrust-Manual.pdf)

These links become the public copies after the integration and website upload
are enabled. Before then, `docs/` and the `wolftrust-manual` CI artifact are
the available documentation.

The one-time integration in `wolfSSL/documentation` adds a `wolfTrust` manual
target beside wolfBoot and wolfHSM
([documentation PR #283](https://github.com/wolfSSL/documentation/pull/283)).
It clones `wolfSSL/wolfTrust` **main**, runs
the adapter from that checkout, and exports `wolfTrust-html/` and
`wolfTrust-Manual.pdf` through the documentation repository's existing Docker
build. Merge the wolfTrust adapter before that integration so its source is
available on `main`.

After both changes are merged, the existing nightly documentation build should
pick up `wolftrust` through the documentation repository's `all` target. No
manual trigger is needed for the normal update. Check the first nightly result
at `https://www.wolfssl.com/documentation/manuals/wolftrust/` and its
`wolfTrust-Manual.pdf`. The website upload rules are outside these public
repositories; if the nightly publishes an explicit list of manuals instead of
all build output, that list will need a one-time addition. Subsequent merged
wolfTrust documentation changes are read from wolfTrust `main` on the next
nightly run. Pull requests only build review artifacts.
