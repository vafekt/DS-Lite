#!/bin/bash
# export.sh — refresh testbed/attack_trees/ from the QuADTool build pipeline.
#
# The trees are DEFINED in results/adtool_trees/build_trees.py (single source of
# truth for structure) and CONVERTED to QuADTool .dot/.prism/.xml by
# results/adtool_trees/build_quadtool.py. This script (1) regenerates that
# conversion, (2) copies the .dot/.prism/.xml triple into this folder, and (3)
# renders one figure per tree with QuADTool's OWN GraphFrame renderer (headless,
# via QRender + xvfb) so the testbed carries a self-contained, up-to-date ADTree
# bundle. It writes ONLY inside testbed/attack_trees/ — it never touches the
# paper (paper-cose/), whose single camera-ready figure is managed separately.
#
# The tree id set is discovered from the emitted .dot files (t1..t12, t9b,
# tS1..tS3), so adding/removing a tree in build_trees.py needs no edit here.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
JAR="$ROOT/QuADTool.jar"
Q="$ROOT/results/adtool_trees"
SRC_Q="$Q/quadtool"
DEST="$ROOT/testbed/attack_trees"
mkdir -p "$DEST/quadtool" "$DEST/figures"

# 1. (re)generate the QuADTool .dot/.prism/.xml from the source-of-truth dict.
python3 "$Q/build_quadtool.py" >/dev/null

# 2. copy the formal artifacts (drop any stale ones first so the dir mirrors the
#    current tree set exactly).
rm -f "$DEST"/quadtool/t*.dot "$DEST"/quadtool/t*.prism "$DEST"/quadtool/t*.xml
cp "$SRC_Q"/t*.dot "$SRC_Q"/t*.prism "$SRC_Q"/t*.xml "$DEST/quadtool/"

# 3. render one figure per tree with QuADTool's GraphFrame (needs a display ->
#    xvfb; PNG -> PDF via ImageMagick). Skip gracefully if the tooling is absent.
have_render=1
command -v xvfb-run >/dev/null 2>&1 || have_render=0
command -v magick   >/dev/null 2>&1 || command -v convert >/dev/null 2>&1 || have_render=0
IM="$(command -v magick || command -v convert)"

if [ "$have_render" = 1 ]; then
    javac -cp "$JAR" -d /tmp "$Q/QRender.java"
    rm -f "$DEST"/figures/t*.pdf "$DEST"/figures/t*.png
    n=0
    for dot in "$SRC_Q"/t*.dot; do
        id="$(basename "$dot" .dot)"        # t1 .. t12, t9b, tS1..tS3
        timeout 90 xvfb-run -a java -cp "$JAR:/tmp" QRender \
            "$dot" "/tmp/q_${id}.png" >/dev/null 2>&1 || { echo "render $id failed"; continue; }
        "$IM" "/tmp/q_${id}.png" "$DEST/figures/${id}.pdf" 2>/dev/null || true
        "$IM" -density 120 "/tmp/q_${id}.png" "$DEST/figures/${id}.png" 2>/dev/null \
            || cp "/tmp/q_${id}.png" "$DEST/figures/${id}.png"
        n=$((n+1))
    done
    echo "rendered $n tree figures"
else
    echo "NOTE: xvfb-run/ImageMagick not found — copied .dot/.prism/.xml only, figures not re-rendered."
fi

echo "exported $(ls "$DEST"/quadtool/*.dot 2>/dev/null | wc -l) QuADTool trees + "\
"$(ls "$DEST"/figures/*.pdf 2>/dev/null | wc -l) figures to $DEST"
