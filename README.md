# Tech Blog

A markdown-first personal blog built with Next.js (Pages Router) and Tailwind CSS. Content lives in the repo, so you can ship without a CMS.

## Highlights

- Next.js 15 Pages Router with static posts/pages
- Server-side pagination at `/page/[page]`
- Tag pages at `/tags/[tag]`
- Auto table of contents for `h2` to `h4` headings
- Post stats (read time, word count, headings, code blocks, images)
- Prism-powered code highlighting + copy-to-clipboard
- Markdown extras: GFM, math (KaTeX), emoji shortcodes
- Content asset pipeline for `content/images` and `content/assets`
- Light/dark theme with persisted preference
- Optional open-source status widget (GitHub API)

## Requirements

- Node.js 22.x (per `package.json` engines)
- npm

## Quick start

```bash
git clone https://github.com/sondt99/Tech-Blog.git
cd Tech-Blog
npm install
npm run dev
```

Open `http://localhost:3000`.

## Project structure

```
content/
  images/
  assets/
  pages/
public/
src/
  components/
  layouts/
  lib/
  pages/
  styles/
```

Note: `content/` is not recursive. Only `content/*.md` are treated as posts.

## Content & routing

- Posts: `content/*.md` -> `/posts/<slug>`
- Pages: `content/pages/*.md` -> `/<slug>`
- Tags: frontmatter `tags` -> `/tags/<tag>`
- Assets: `content/images/*`, `content/assets/*` -> `/api/content/<path>`

Slug comes from the filename. Example: `content/hello-world.md` -> `/posts/hello-world`.

## Post frontmatter

```yaml
---
title: "Your Post Title"
date: "YYYY-MM-DD"
excerpt: "Short description for the post"
featured: "/images/featured.jpg"
tags:
  - security
  - systems
---
```

Notes:
- `date` controls sorting (newest first).
- `featured` is optional and powers the hero image.
- `tags` can be an array or a comma-separated string.

## Page frontmatter

```yaml
---
title: "About"
lastUpdated: "YYYY-MM-DD"
---
```

### Optional timeline block

```yaml
---
title: "About"
lastUpdated: "YYYY-MM-DD"
timeline:
  - year: "2024"
    category: "Work"
    place: "Company Name"
    role: "Security Engineer"
    detail: "Team focus and highlights."
  - year: "2022"
    category: "Study"
    place: "University Name"
    role: "B.Sc. in Information Security"
---
```

## Assets & images

Place images in `content/images/` and other files in `content/assets/`.
You can reference them in Markdown or frontmatter using any of:

- `/images/...` or `images/...`
- `/assets/...` or `assets/...`

The pipeline rewrites those to `/api/content/...` and serves them from disk.
Markdown files are blocked by the API route.

## Markdown pipeline & features

Markdown is processed in:

- `src/pages/posts/[slug].tsx`
- `src/pages/[slug].tsx`

Enabled features:
- `remark-gfm` (tables, task lists, strikethrough, footnotes)
- `remark-math` + `rehype-katex` (math)
- `remark-emoji`
- Prism-based syntax highlighting
- TOC generated from `h2`-`h4`

Raw HTML in Markdown is not rendered. If you need it, add `rehype-raw` and enable `allowDangerousHtml` in the pipeline (and keep sanitization in mind).

## Open-source status (optional)

The home page can show an open-source status card. Configure it in `site.config.ts` under `openSource`.

- The API route is `src/pages/api/open-source-status.ts`.
- Set `GITHUB_TOKEN` (or `GITHUB_API_TOKEN`, `GH_TOKEN`) to avoid GitHub rate limits.
- If you want commit comparison, set `VERCEL_GIT_COMMIT_SHA` or `GIT_COMMIT_SHA` in the environment.

## Configuration

- Site metadata, nav, labels: `site.config.ts`
- Home hero + pagination size: `src/pages/index.tsx` (`POSTS_PER_PAGE`)
- Post layout, stats, TOC: `src/pages/posts/[slug].tsx`
- Page layout + timeline: `src/pages/[slug].tsx`
- Theme tokens + typography: `src/styles/globals.css` and `tailwind.config.ts`

## Scripts

- `npm run dev`: start dev server
- `npm run build`: build for production
- `npm start`: run production server
- `npm run lint`: lint
- `npm run clean`: remove `.next` and `node_modules`

## Deployment

`/page/[page]` uses `getServerSideProps`, so you need a Node runtime (no `next export`).
Standard Next.js deployments work: `npm run build` then `npm start`, or deploy on Vercel with SSR enabled.

## Troubleshooting

- Post not showing: ensure the file is in `content/` (not a subfolder) and ends with `.md`.
- Wrong order: check the `date` frontmatter value.
- Images not loading: use `/images/...` or `/assets/...` and put files in `content/images` or `content/assets`.
- Tags not linking: ensure `tags` is a list or comma-separated string.

## License

[MIT License](LICENSE)

## Author

- Thai Son Dinh ([@_sondt_](https://x.com/_sondt_))
