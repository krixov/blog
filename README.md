# Tech Blog

Minimal personal blog built with Next.js, Tailwind CSS, and Markdown.

## Features

- Clean responsive layout with light/dark themes
- Markdown posts and pages
- Rich Markdown: tables, task lists, footnotes, math (KaTeX)
- Automatic table of contents
- SEO-friendly metadata
- Simple pagination

## Requirements

- Node.js 20.x
- npm (recommended because `package-lock.json` is present)

## Quick Start

```bash
git clone https://github.com/sondt1337/Tech-Blog.git
cd Tech-Blog
npm install
npm run dev
```

Open `http://localhost:3000`.

## Content Layout

- `content/*.md`: posts at `/posts/<slug>`
- `content/pages/*.md`: pages at `/<slug>`
- `content/images/*`: post images, served via `/api/content/images`
- `public/*`: static assets like favicon and site icons

## Writing Posts

Create a new file in `content/` with frontmatter:

```yaml
---
title: "Your Post Title"
date: "YYYY-MM-DD"
excerpt: "Short description for the post"
featured: "/images/featured.jpg"
---
```

Notes:
- `date` is used for sorting (newest first).
- `featured` is optional.
- Put images in `content/images` and reference them as `/images/...` or `images/...`.

## Writing Pages

Create a new file in `content/pages/` with frontmatter:

```yaml
---
title: "About"
lastUpdated: "YYYY-MM-DD"
---
```

## Markdown Pipeline

Markdown processing happens in:

- `src/pages/posts/[slug].tsx`
- `src/pages/[slug].tsx`

Enabled features:
- `remark-gfm` (tables, task lists, footnotes)
- `remark-math` + `rehype-katex`
- `remark-emoji`

Raw HTML in Markdown is not rendered by default. Add `rehype-raw` if you need it.

## Project Structure

```
Tech-Blog/
├── content/
│   ├── images/
│   └── pages/
├── public/
└── src/
    ├── components/
    ├── layouts/
    ├── lib/
    ├── pages/
    └── styles/
```

## Scripts

- `npm run dev`: start dev server
- `npm run build`: build production bundle
- `npm start`: run production server
- `npm run lint`: lint
- `npm run clean`: remove `.next` and `node_modules`

## Deployment

`/page/[page]` uses `getServerSideProps`, so you need a Node runtime (not `next export`).

## License

[MIT License](LICENSE)

## Author

- Thai Son Dinh ([@_sondt_](https://x.com/_sondt_))
