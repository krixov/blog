import type { TimelineEntry } from '@/types/timeline';

type TimelineProps = {
  entries: TimelineEntry[];
  title?: string;
};

export default function Timeline({ entries, title = 'Timeline' }: TimelineProps) {
  if (entries.length === 0) return null;

  return (
    <section className="mt-12">
      <div className="flex items-center gap-3 text-xs font-mono uppercase tracking-widest text-neutral-500 dark:text-neutral-400">
        <span className="h-px w-8 bg-neutral-400 dark:bg-neutral-600" aria-hidden="true" />
        <span>{title}</span>
      </div>

      <div className="relative mt-8">
        <span
          aria-hidden="true"
          className="absolute left-2 top-0 h-full w-px bg-gradient-to-b from-neutral-400/80 via-neutral-300/50 to-transparent dark:from-neutral-600/90 dark:via-neutral-700/70 dark:to-transparent"
        />
        <ol className="space-y-6 pl-8">
          {entries.map((entry, index) => (
            <li
              key={`${entry.year}-${entry.place}-${index}`}
              className="relative rise-in"
              style={{ animationDelay: `${200 + index * 90}ms` }}
            >
              <span className="absolute left-2 top-6 h-3 w-3 -translate-x-1/2 rounded-full border border-neutral-900/80 bg-neutral-100 shadow-sm dark:border-neutral-100/80 dark:bg-neutral-900" />
              <div className="surface-card rounded-2xl p-5 sm:p-6">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center rounded-full border border-neutral-900/80 bg-neutral-900 px-3 py-1 text-[10px] font-mono uppercase tracking-widest text-neutral-100 dark:border-neutral-100/80 dark:bg-neutral-100 dark:text-neutral-900">
                    {entry.year}
                  </span>
                  {entry.category ? (
                    <span className="inline-flex items-center rounded-full border border-neutral-300/80 bg-neutral-100/70 px-3 py-1 text-[10px] font-mono uppercase tracking-widest text-neutral-500 dark:border-neutral-700 dark:bg-neutral-900/50 dark:text-neutral-400">
                      {entry.category}
                    </span>
                  ) : null}
                </div>
                <h3 className="mt-4 text-lg font-semibold text-neutral-900 dark:text-white">
                  {entry.place}
                </h3>
                {entry.role ? (
                  <p className="mt-2 text-xs font-mono uppercase tracking-widest text-neutral-500 dark:text-neutral-400">
                    {entry.role}
                  </p>
                ) : null}
                {entry.detail ? (
                  <p className="mt-3 text-sm text-neutral-600 dark:text-neutral-300">
                    {entry.detail}
                  </p>
                ) : null}
              </div>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
