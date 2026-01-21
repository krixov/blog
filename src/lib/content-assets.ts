const CONTENT_API_PREFIX = '/api/content';
const CONTENT_FOLDER_NAMES = ['images', 'assets'];

function isExternalUrl(value: string) {
  const lower = value.toLowerCase();
  return (
    lower.startsWith('http://') ||
    lower.startsWith('https://') ||
    lower.startsWith('//') ||
    lower.startsWith('data:')
  );
}

function splitUrlSuffix(value: string) {
  const index = value.search(/[?#]/);
  if (index === -1) {
    return { path: value, suffix: '' };
  }
  return { path: value.slice(0, index), suffix: value.slice(index) };
}

function isContentPath(value: string) {
  return CONTENT_FOLDER_NAMES.some((folder) => value === folder || value.startsWith(`${folder}/`));
}

export function resolveContentAssetUrl(value?: string | null) {
  if (!value) return null;
  if (typeof value !== 'string') return null;

  const trimmed = value.trim();
  if (!trimmed) return null;
  if (isExternalUrl(trimmed) || trimmed.startsWith(`${CONTENT_API_PREFIX}/`)) {
    return trimmed;
  }

  const { path, suffix } = splitUrlSuffix(trimmed);
  const normalizedPath = path.replace(/\\/g, '/');

  if (normalizedPath.startsWith('/')) {
    const withoutSlash = normalizedPath.replace(/^\/+/, '');
    if (isContentPath(withoutSlash)) {
      return `${CONTENT_API_PREFIX}/${withoutSlash}${suffix}`;
    }
    return trimmed;
  }

  const withoutDots = normalizedPath.replace(/^(\.\.\/|\.\/)+/, '');
  if (isContentPath(withoutDots)) {
    return `${CONTENT_API_PREFIX}/${withoutDots}${suffix}`;
  }

  return trimmed;
}

export { CONTENT_API_PREFIX };
