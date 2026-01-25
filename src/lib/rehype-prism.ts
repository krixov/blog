import { Prism } from 'prism-react-renderer';

type Node = {
  type?: string;
  tagName?: string;
  properties?: Record<string, unknown>;
  children?: Node[];
  value?: string;
};

type PrismToken = {
  type: string;
  content: PrismTokenContent;
  alias?: string | string[];
};

type PrismTokenContent = string | PrismToken | PrismToken[];

const LANGUAGE_PREFIX = 'language-';
const IGNORED_LANGUAGES = new Set(['none', 'plain', 'plaintext', 'text']);
const LANGUAGE_ALIASES: Record<string, string> = {
  js: 'javascript',
  jsx: 'jsx',
  ts: 'typescript',
  tsx: 'tsx',
  html: 'markup',
  xml: 'markup',
  svg: 'markup',
  yml: 'yaml',
  py: 'python',
  rb: 'ruby',
  sh: 'bash',
  shell: 'bash',
  zsh: 'bash'
};
const LANGUAGE_LABELS: Record<string, string> = {
  javascript: 'JS',
  typescript: 'TS',
  markdown: 'MD',
  md: 'MD',
  csharp: 'C#',
  cpp: 'CPP'
};

const isElement = (node: Node, tagName: string) =>
  node.type === 'element' && node.tagName === tagName;

const getClassNames = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string');
  }
  if (typeof value === 'string') {
    return value.split(/\s+/).filter(Boolean);
  }
  return [];
};

const getLanguage = (node: Node): string | null => {
  const classNames = getClassNames(node.properties?.className);
  const languageClass = classNames.find((name) => name.startsWith(LANGUAGE_PREFIX));
  if (!languageClass) return null;
  return languageClass.slice(LANGUAGE_PREFIX.length).toLowerCase();
};

const getText = (node: Node): string => {
  if (node.type === 'text') {
    return node.value ?? '';
  }
  if (!Array.isArray(node.children)) return '';
  return node.children.map(getText).join('');
};

const toNodes = (token: PrismTokenContent): Node[] => {
  if (typeof token === 'string') {
    return [{ type: 'text', value: token }];
  }

  if (Array.isArray(token)) {
    return token.flatMap((item) => toNodes(item));
  }

  const classNames = ['token', token.type];
  if (token.alias) {
    if (Array.isArray(token.alias)) {
      classNames.push(...token.alias);
    } else {
      classNames.push(token.alias);
    }
  }

  return [
    {
      type: 'element',
      tagName: 'span',
      properties: { className: classNames },
      children: toNodes(token.content)
    }
  ];
};

const resolveLanguage = (language: string): string => {
  return LANGUAGE_ALIASES[language] ?? language;
};

const formatLanguageLabel = (language: string): string => {
  const normalized = language.toLowerCase();
  return (LANGUAGE_LABELS[normalized] ?? normalized).toUpperCase();
};

export default function rehypePrism() {
  return (tree: Node) => {
    const visit = (node: Node) => {
      if (isElement(node, 'pre') && Array.isArray(node.children)) {
        const codeNode = node.children.find((child) => isElement(child, 'code'));
        if (codeNode) {
          const rawLanguage = getLanguage(codeNode);
          if (rawLanguage && !IGNORED_LANGUAGES.has(rawLanguage)) {
            node.properties = {
              ...(node.properties ?? {}),
              'data-language': formatLanguageLabel(rawLanguage)
            };
          }
          if (rawLanguage && !IGNORED_LANGUAGES.has(rawLanguage)) {
            const language = resolveLanguage(rawLanguage);
            const grammar =
              Prism.languages[language] || Prism.languages[rawLanguage];
            if (grammar) {
              const code = getText(codeNode);
              const tokens = Prism.tokenize(code, grammar);
              codeNode.children = toNodes(tokens as PrismTokenContent);
            }
          }
        }
      }

      if (Array.isArray(node.children)) {
        node.children.forEach(visit);
      }
    };

    visit(tree);
  };
}
