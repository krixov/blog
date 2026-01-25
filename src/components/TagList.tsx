import Link from 'next/link';

interface TagListProps {
  tags: string[];
  className?: string;
  activeTag?: string;
}

export default function TagList({ tags, className, activeTag }: TagListProps) {
  if (!tags || tags.length === 0) return null;

  const containerClassName = className
    ? `flex flex-wrap gap-2 ${className}`
    : 'flex flex-wrap gap-2';
  const baseTagClassName =
    'inline-flex items-center rounded-full border border-neutral-300/70 bg-neutral-100/70 px-3 py-1 text-[10px] font-mono tracking-widest text-neutral-600 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400/70 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:border-neutral-700 dark:bg-neutral-900/50 dark:text-neutral-400 dark:focus-visible:ring-neutral-500 dark:focus-visible:ring-offset-neutral-950';
  const hoverTagClassName =
    'hover:border-neutral-400 hover:bg-neutral-200 hover:text-neutral-900 dark:hover:border-neutral-500 dark:hover:bg-neutral-800 dark:hover:text-neutral-100';
  const activeTagClassName =
    'border-neutral-900 bg-neutral-900 text-neutral-100 dark:border-neutral-200 dark:bg-neutral-100 dark:text-neutral-900';

  return (
    <div className={containerClassName}>
      {tags.map((tag) => {
        const isActive =
          typeof activeTag === 'string' &&
          tag.toLowerCase() === activeTag.toLowerCase();
        const tagClassName = `${baseTagClassName} ${
          isActive ? activeTagClassName : hoverTagClassName
        }`;

        return (
          <Link
            key={tag}
            href={`/tags/${encodeURIComponent(tag)}`}
            className={tagClassName}
            aria-current={isActive ? 'true' : undefined}
          >
            {tag}
          </Link>
        );
      })}
    </div>
  );
}
