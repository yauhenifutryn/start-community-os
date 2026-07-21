# Social and submission media

- `og-start-community-os.svg` is the editable 1200 x 630 source for the live Open Graph card.
- `community-os-gradient.png` is the approved generated 1200 x 630 background. The Devpost SVG crops it into its 1200 x 800 canvas with `preserveAspectRatio="xMidYMid slice"`.
- `community-os-gradient-og.png` is a byte-identical 1200 x 630 alias used by the Open Graph SVG.
- `devpost-thumbnail.svg` is the editable 1200 x 800 source for Devpost.
- `devpost-thumbnail.png` is the rendered 1200 x 800, 3:2 upload asset for Devpost.
- `start-warsaw-white.png` is a 240 x 140 raster rendered from the checked-in `assets/brand/start-warsaw-white.svg` source.
- `openai-wordmark-white.png` is a 1158 x 312 transparent raster copied byte-for-byte from the earlier START hackathon-card project. The original file has no further source metadata in either repository, so this project does not make a provenance claim beyond that copy.
- `public/og-start-community-os.png` is the rendered social image bound by the public release manifest.

The generated background was approved outside this public snapshot; its generation prompt and model record are not included here. START Warsaw and OpenAI marks remain third-party marks as described in [NOTICE.md](../../NOTICE.md).

Regenerate the live PNG from the SVG with:

```bash
rsvg-convert --width 240 --height 140 --format png \
  --output assets/social/start-warsaw-white.png \
  assets/brand/start-warsaw-white.svg

rsvg-convert --width 1200 --height 630 --format png \
  --output public/og-start-community-os.png \
  assets/social/og-start-community-os.svg

rsvg-convert --width 1200 --height 800 --format png \
  --output assets/social/devpost-thumbnail.png \
  assets/social/devpost-thumbnail.svg
```

After regeneration, the public release manifest hashes must be refreshed and the repository productization tests must pass before publication.
