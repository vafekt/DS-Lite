#!/bin/bash
# export.sh — refresh testbed/attack_trees/ from the QuADTool build pipeline.
# The trees are defined in results/adtool_trees/build_trees.py and rendered by
# results/adtool_trees/render_with_quadtool.sh; this script copies the QuADTool
# exports (.dot/.prism/.xml) and the rendered figures into this folder so the
# testbed carries a self-contained ADTree bundle.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC_Q="$ROOT/results/adtool_trees/quadtool"
SRC_FIG="$ROOT/paper-cose/submission"
DEST="$ROOT/testbed/attack_trees"

mkdir -p "$DEST/quadtool" "$DEST/figures"
cp "$SRC_Q"/t*.dot "$SRC_Q"/t*.prism "$SRC_Q"/t*.xml "$DEST/quadtool/" 2>/dev/null || true

for n in $(seq 1 15); do
    cp "$SRC_FIG/fig_adtree_t${n}.pdf" "$DEST/figures/t${n}.pdf" 2>/dev/null || true
    command -v magick >/dev/null 2>&1 && \
        magick -density 120 "$DEST/figures/t${n}.pdf" "$DEST/figures/t${n}.png" 2>/dev/null || true
done

echo "exported $(ls "$DEST"/quadtool/*.dot 2>/dev/null | wc -l) QuADTool trees + "\
"$(ls "$DEST"/figures/*.pdf 2>/dev/null | wc -l) figures to $DEST"
