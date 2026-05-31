import { Helmet } from "react-helmet-async";
import type { SeoMetadata } from "@/api/types";

// PLATFORM-005: <SeoHead> renders SEO / OpenGraph / Twitter / canonical /
// JSON-LD tags into <head> via react-helmet-async. It accepts either an
// explicit set of props or a SeoMetadata document fetched from the backend
// `/seo/metadata` endpoint (see useSeoMeta / seoMetadata.ts).

export interface SeoHeadProps {
  title?: string;
  description?: string;
  ogType?: string;
  image?: string | null;
  canonicalUrl?: string;
  twitterCard?: string;
  siteName?: string;
  locale?: string;
  jsonLd?: Record<string, unknown> | null;
  /** When supplied, fields are derived from a backend SeoMetadata document. */
  metadata?: SeoMetadata | null;
}

const DEFAULT_SITE_NAME = "Control Panel";
const DEFAULT_TITLE = "Control Panel";
const DEFAULT_DESCRIPTION =
  "Your all-in-one platform for messaging, commerce, and content creation.";

export function SeoHead(props: SeoHeadProps) {
  const m = props.metadata ?? null;

  const title = props.title ?? m?.title ?? DEFAULT_TITLE;
  const description = props.description ?? m?.description ?? DEFAULT_DESCRIPTION;
  const ogType = props.ogType ?? m?.og?.["og:type"] ?? "website";
  const image = props.image ?? m?.image ?? null;
  const canonicalUrl = props.canonicalUrl ?? m?.canonical_url ?? undefined;
  const siteName = props.siteName ?? m?.site_name ?? DEFAULT_SITE_NAME;
  const locale = props.locale ?? m?.locale ?? "en_US";
  const twitterCard =
    props.twitterCard ??
    m?.twitter?.["twitter:card"] ??
    (image ? "summary_large_image" : "summary");
  const jsonLd = props.jsonLd ?? m?.json_ld ?? null;

  return (
    <Helmet>
      <title>{title}</title>
      <meta name="description" content={description} />
      <meta property="og:title" content={title} />
      <meta property="og:description" content={description} />
      <meta property="og:type" content={ogType} />
      <meta property="og:site_name" content={siteName} />
      <meta property="og:locale" content={locale} />
      {canonicalUrl && <meta property="og:url" content={canonicalUrl} />}
      {image && <meta property="og:image" content={image} />}
      <meta name="twitter:card" content={twitterCard} />
      <meta name="twitter:title" content={title} />
      <meta name="twitter:description" content={description} />
      {image && <meta name="twitter:image" content={image} />}
      {canonicalUrl && <link rel="canonical" href={canonicalUrl} />}
      {jsonLd && (
        <script type="application/ld+json">{JSON.stringify(jsonLd)}</script>
      )}
    </Helmet>
  );
}

export default SeoHead;
