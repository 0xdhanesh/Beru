#!/usr/bin/env bash
# Build C/C++ lab sources in Docker; never execute the resulting program.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
image="${BERU_COMPILER_IMAGE:-beru-compiler:local}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -eq 0 ]]; then
    cat <<'HELP'
Usage: ./scripts/compile.sh [options] SOURCE [SOURCE ...]

Compile repository C/C++ files into both profiles in Docker.
  --target TARGET       linux-x86, linux-x86_64 (default), linux-arm,
                        linux-arm64, windows-x86, windows-x86_64, or all
  --profile PROFILE     both (default), unprotected, or hardened
  --name NAME           Output basename (default: first source stem)
  --include DIR         Repository-relative include directory; repeatable
  --define NAME[=VALUE]  Preprocessor definition; repeatable
  --library NAME        Link library, e.g. m; repeatable
  --pthread             Compile/link with thread support

Outputs: build/TARGET/PROFILE/NAME[.exe] and NAME[.exe].json.
Paths are relative to the repository root, even when run elsewhere.

Environment:
  BERU_OUTPUT_DIR        Host output directory (default: <repo>/build)
  BERU_COMPILER_IMAGE    Docker image tag (default: beru-compiler:local)
  BERU_SKIP_IMAGE_BUILD  Set to 1 to reuse an already-built image
HELP
    exit 0
fi

command -v docker >/dev/null || { echo 'Docker is required.' >&2; exit 1; }
output_dir="${BERU_OUTPUT_DIR:-$repo_root/build}"
if [[ "$output_dir" != /* ]]; then
    output_dir="$repo_root/$output_dir"
fi
mkdir -p -- "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"
if [[ "$output_dir" == "$repo_root" ]]; then
    echo 'BERU_OUTPUT_DIR must be a separate output directory.' >&2
    exit 1
fi

if [[ "${BERU_SKIP_IMAGE_BUILD:-0}" != 1 ]]; then
    docker build --tag "$image" "$repo_root/docker/compiler"
fi

exec docker run --rm --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,nosuid,nodev,size=512m \
    --mount "type=bind,source=$repo_root,target=/src,readonly" \
    --mount "type=bind,source=$output_dir,target=/out" \
    "$image" "$@"
