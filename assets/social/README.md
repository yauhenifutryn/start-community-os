# Social and submission media

- `og-start-community-os.svg` is the editable 1200 x 630 source for the live Open Graph card.
- `devpost-thumbnail.png` is the 1200 x 800, 3:2 upload asset for Devpost.
- `public/og-start-community-os.png` is the rendered social image bound by the public release manifest.

Regenerate the live PNG from the SVG with:

```bash
rsvg-convert --width 1200 --height 630 --format png \
  --output public/og-start-community-os.png \
  assets/social/og-start-community-os.svg
```

After regeneration, the public release manifest hashes must be refreshed and the repository productization tests must pass before publication.
