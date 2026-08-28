# Authkestra documentation site

The source for <https://authkestra.com>, built with [Astro](https://astro.build) and
[Starlight](https://starlight.astro.build).

## 🚀 Project Structure

```
.
├── public/                     # favicon and other static assets
├── src/
│   ├── assets/                 # images referenced from Markdown
│   ├── content/
│   │   └── docs/               # every page on the site
│   ├── styles/
│   └── content.config.ts
├── astro.config.mjs            # site config + the sidebar definition
├── package.json
└── tsconfig.json
```

Starlight looks for `.md` or `.mdx` files in `src/content/docs/`. Each file is exposed as a route
based on its file name — but a new page only appears in the navigation once it is added to the
`sidebar` array in `astro.config.mjs`.

Images go in `src/assets/` and are embedded with a relative link. Static assets, like favicons,
go in `public/`.

## 🧞 Commands

All commands are run from this directory:

| Command           | Action                                       |
| :---------------- | :------------------------------------------- |
| `pnpm install`    | Installs dependencies                        |
| `pnpm dev`        | Starts local dev server at `localhost:4321`  |
| `pnpm build`      | Build the production site to `./dist/`       |
| `pnpm preview`    | Preview the build locally, before deploying  |
| `pnpm astro ...`  | Run CLI commands like `astro add`, `astro check` |

## ✍️ Writing docs

Code samples on this site are not compiled by CI, so they drift easily. When you change a public
API in `crates/`, grep this directory for the old name before opening the PR. Where a runnable
example exists under `crates/authkestra/examples/`, link to it and quote its `cargo run` command
rather than inventing a fresh snippet — the examples *are* compiled.

## 👀 Want to learn more?

Check out [Starlight's docs](https://starlight.astro.build/) or read
[the Astro documentation](https://docs.astro.build).
