#!/usr/bin/env bash
# Builds Keyfort from the local git checkout and unpacks it into a stable
# local directory. Re-run this script to update: it git-pulls first, so
# there's no need to wait for a GitHub release/CI run.
# Use --remote to instead download the latest GitHub release zip (for
# machines without a clone of this repo).
set -euo pipefail

REPO="Aqudi/keyfort"
DEST="${KEYFORT_EXT_DIR:-$HOME/.keyfort-extension}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

rm -rf "$DEST"
mkdir -p "$DEST"

if [ "${1:-}" = "--remote" ]; then
  command -v gh >/dev/null 2>&1 || { echo "gh CLI가 필요합니다: https://cli.github.com" >&2; exit 1; }
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  gh release download --repo "$REPO" --pattern '*.zip' --dir "$tmp" --clobber
  unzip -q "$tmp"/*.zip -d "$DEST"
else
  repo_root="$(cd "$SCRIPT_DIR/.." && pwd)"
  git -C "$repo_root" pull --ff-only
  cp -R "$repo_root/manifest.json" "$repo_root/src" "$repo_root/icons" "$DEST/"
fi

echo "설치 완료: $DEST"
echo "최초 1회: chrome://extensions -> 개발자 모드 켜기 -> '압축해제된 확장 프로그램을 로드합니다' -> $DEST 선택"
echo "다음부터 업데이트: 이 스크립트를 다시 실행한 뒤 chrome://extensions 에서 Keyfort 카드의 새로고침 버튼만 누르면 됩니다."
