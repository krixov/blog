const ENV_KEYS = ['VERCEL_GIT_COMMIT_SHA', 'GIT_COMMIT_SHA'] as const;

export function getSiteCommitFromEnv(): string | null {
  for (const key of ENV_KEYS) {
    const value = process.env[key];
    if (value && value.trim()) {
      return value.trim();
    }
  }
  return null;
}
