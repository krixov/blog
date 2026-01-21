import { resolveContentAssetUrl } from '@/lib/content-assets';

type Node = {
  type?: string;
  tagName?: string;
  properties?: Record<string, unknown>;
  children?: Node[];
};

export default function rehypeContentAssets() {
  return (tree: Node) => {
    const visit = (node: Node) => {
      if (node.type === 'element' && node.tagName === 'img') {
        const properties = node.properties ?? {};
        const src = properties.src;
        if (typeof src === 'string') {
          const resolved = resolveContentAssetUrl(src);
          if (resolved) {
            properties.src = resolved;
            node.properties = properties;
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
