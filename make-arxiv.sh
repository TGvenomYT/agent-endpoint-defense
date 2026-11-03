#!/bin/sh
# Build the arXiv source package (pdfLaTeX sources + pre-built .bbl).
# Usage: ./make-arxiv.sh [output.tar.gz]      (needs tectonic for the .bbl)
set -eu
cd "$(dirname "$0")"
OUT=${1:-arxiv-submission.tar.gz}
SRC="main.tex preamble.tex mirage.tex mirage-data.tex realtraffic.tex"

for f in $SRC refs.bib; do
  [ -f "$f" ] || { echo "missing $f (realtraffic.tex comes from artifact/gen_realtraffic_tex.py)" >&2; exit 1; }
done
if grep -n '\\placeholder{' main.tex mirage.tex | grep -v newcommand; then
  echo "unresolved \\placeholder above" >&2; exit 1
fi
head -1 main.tex | grep -q 'pdfoutput=1' || { echo "line 1 of main.tex must carry pdfoutput=1" >&2; exit 1; }

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cp $SRC refs.bib "$W/"
(cd "$W" && tectonic -X compile --keep-intermediates main.tex >/dev/null 2>&1) \
  || { echo "tectonic build failed" >&2; exit 1; }

mkdir "$W/pkg"
# arXiv always uses pdfLaTeX: make line 1 a plain \pdfoutput=1 (it must sit in the first 5 lines).
sed '1s/.*/\\pdfoutput=1/' main.tex > "$W/pkg/main.tex"
cp preamble.tex mirage.tex mirage-data.tex realtraffic.tex "$W/main.bbl" "$W/pkg/"
# COPYFILE_DISABLE keeps macOS AppleDouble (._*) files out of the archive.
COPYFILE_DISABLE=1 tar -czf "$OUT" -C "$W/pkg" main.tex preamble.tex mirage.tex mirage-data.tex realtraffic.tex main.bbl
echo "wrote $OUT:"; tar -tzf "$OUT"
