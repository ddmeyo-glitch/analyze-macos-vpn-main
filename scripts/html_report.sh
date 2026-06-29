#!/bin/bash
set -euo pipefail
REPORT_DIR="${REPORT_DIR:-reports}"
OUT="$REPORT_DIR/Security_Report.html"
mkdir -p "$REPORT_DIR"
cat >"$OUT"<<'EOF'
<!doctype html><html><head><meta charset="utf-8"><title>DeveloperID Dashboard</title>
<style>
body{font-family:Arial;background:#f4f6f9;margin:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.card{background:#fff;border-radius:8px;padding:14px;box-shadow:0 1px 4px #ccc}
.ok{color:#0a8f3d}.warn{color:#d98200}
details{background:#fff;margin:10px 0;padding:10px;border-radius:8px}
pre{white-space:pre-wrap}
input{width:100%;padding:8px}
</style>
<script>
function f(){let q=document.getElementById("q").value.toLowerCase();document.querySelectorAll("details").forEach(d=>d.style.display=d.innerText.toLowerCase().includes(q)?"block":"none");}
</script></head><body>
<h1>DeveloperID Forensics Dashboard</h1>
<div class="grid">
<div class="card"><h3>Risk</h3><div class="ok">LOW</div></div>
<div class="card"><h3>Code Sign</h3><div class="ok">CHECK</div></div>
<div class="card"><h3>NetworkExtension</h3><div class="ok">Detected</div></div>
<div class="card"><h3>Go Runtime</h3><div>Auto</div></div>
</div>
<p><input id="q" onkeyup="f()" placeholder="Search..."></p>
EOF
for f in "$REPORT_DIR"/*.md; do
[ -f "$f" ] || continue
n=$(basename "$f")
echo "<details open><summary><b>$n</b></summary><pre>" >>"$OUT"
sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' "$f" >>"$OUT"
echo "</pre></details>" >>"$OUT"
done
echo "</body></html>" >>"$OUT"
echo "Generated $OUT"
