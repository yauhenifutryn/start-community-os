# Public partner report deployment

Deploy only the directory produced by `community_os.publication.stage_publication`. Never deploy `output/real`, the operator root, or a directory containing `private`, `protected`, QA, audit, source, cache, or override files.

The checked-in `_headers` file is a warning sentinel, not a deployment template, and must not be copied into a public bundle. Inline script and style hashes depend on the exact approved `index.html`; a host adapter must derive a hash-pinned policy from those bytes. The supported PostHog/Vercel path generates `vercel.json` during `community_os.postpublication_analytics.prepare_analytics_publication_bundle`. A Cloudflare or Netlify adapter remains unsupported until it generates equivalent hashes from the approved artifact.

Verify the final response headers, browser network log, report/PDF hashes, and allowed analytics events after deployment. Keep analytics disabled until publication approval and deployed parity checks pass.
