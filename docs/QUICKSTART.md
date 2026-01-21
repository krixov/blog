# Quickstart

This guide helps you run the project quickly, add posts/pages, and adjust the main pieces.

## Requirements

- Node.js 20.x (per `package.json`)
- npm (recommended because `package-lock.json` is present)

## Install

```bash
git clone https://github.com/sondt1337/Tech-Blog.git
cd Tech-Blog
npm install
```

## Run locally

```bash
npm run dev
```

Open `http://localhost:3000`.

## Build & run production

```bash
npm run build
npm start
```

## Lint & cleanup

```bash
npm run lint
npm run clean
```

## Content layout

- `content/*.md`: posts (route: `/posts/<slug>`)
- `content/pages/*.md`: static pages (route: `/<slug>`)
- `public/images/*`: static images (use in Markdown or `featured`)

Slug comes from the filename. Example: `content/hello-world.md` -> `/posts/hello-world`.

## Post frontmatter

`content/*.md` needs these fields:

```yaml
---
title: "Your Post Title"
date: "YYYY-MM-DD"
excerpt: "Short description for the post"
featured: "/images/featured.jpg"
---
```

Notes:
- `date` is used for sorting (newest first). Use `YYYY-MM-DD`.
- `featured` is optional; if missing, the post renders without a hero image.

## Page frontmatter

`content/pages/*.md` needs these fields:

```yaml
---
title: "About"
lastUpdated: "YYYY-MM-DD"
---
```

## Markdown pipeline & features

Markdown is processed in:
- `src/pages/posts/[slug].tsx`
- `src/pages/[slug].tsx`

Current pipeline:
- `remark-parse`, `remark-gfm` (tables, task lists, footnotes)
- `remark-math` + `rehype-katex` (math)
- `remark-emoji` (emoji shortcodes)

Notes:
- TOC is generated from `h2`, `h3`, `h4`. Use clean headings for best results.
- Code blocks include a copy button. Language comes from the fence: ```js, ```python, etc.
- Raw HTML in Markdown (e.g. `<details>`) is not rendered; enable `allowDangerousHtml` + `rehype-raw` if you need it.

## Quick customization

- Home hero content: `src/pages/index.tsx`
- Posts per page: `POSTS_PER_PAGE` in `src/pages/index.tsx`
- Header/footer/meta: `src/layouts/Layout.tsx`
- Theme, fonts, animations: `src/styles/globals.css` and `tailwind.config.ts`

## Deploy

`/page/[page]` uses `getServerSideProps`, so you need a Node runtime (no `next export`).
Standard Next.js deployment: `npm run build` + `npm start` or Vercel.

## Troubleshooting

- Post not showing: ensure the file is in `content/` (not a subfolder) and ends with `.md`.
- Wrong order: check `date` in frontmatter.
- Images not loading: use absolute paths like `/images/...` and put files in `public/images/`.
