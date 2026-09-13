// @ts-check
import { defineConfig } from 'astro/config';

/*
  Pages that used to live on this domain and now live on docs.authkestra.com.

  authkestra.com served the Starlight documentation until the docs moved to
  their own repository and this landing page took the apex domain. Every link
  in the wild — READMEs, crates.io, blog posts, someone's bookmarks — still
  points at the old paths, and on a static host a missing path is a 404 with
  no explanation. So each one is kept as a redirect.

  The list is derived from what the docs site actually publishes; if a page is
  added or renamed over there it does NOT need an entry here, because it never
  existed on this domain. This list only ever shrinks, once the traffic dies.
*/
const MOVED_TO_DOCS = [
  'advanced/instrumentation',
  'advanced/op-server',
  'advanced/resource-server',
  'concepts/architecture',
  'concepts/typestate-builder',
  'guides/device-attestation',
  'guides/framework-integration',
  'guides/quickstart',
  'guides/wired-endpoints',
  'providers/bot-protection',
  'providers/client-credentials',
  'providers/device-flow',
  'providers/device-signatures',
  'providers/oauth2',
  'providers/oidc',
  'providers/passkeys',
  'providers/totp',
  'storage/implementing-stores',
  'storage/kv-store',
  'storage/overview',
  'storage/sql-store',
];

const docsRedirects = Object.fromEntries(
  MOVED_TO_DOCS.map((slug) => [`/${slug}`, `https://docs.authkestra.com/${slug}/`]),
);

// https://astro.build/config
export default defineConfig({
  site: 'https://authkestra.com',

  redirects: {
    ...docsRedirects,

    /*
      The comparison did not move to the docs — it moved onto this page, which
      is where someone weighing Authkestra against the alternatives actually
      is. So this one is the only redirect that stays on this domain.
    */
    '/concepts/comparison': '/#comparison',
  },
});
