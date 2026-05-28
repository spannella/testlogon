import { Helmet } from "react-helmet-async";

interface PageMetaProps {
  title: string;
  description?: string;
  image?: string | null;
  type?: string;
  url?: string;
  twitterCard?: "summary" | "summary_large_image";
}

/**
 * Reusable component for setting page-level meta tags via react-helmet-async.
 * Appends " | Control Panel" to the title automatically.
 */
export function PageMeta({
  title,
  description,
  image,
  type = "website",
  url,
  twitterCard = "summary",
}: PageMetaProps) {
  const fullTitle = title ? `${title} | Control Panel` : "Control Panel";
  const desc = description || "Your all-in-one platform for messaging, commerce, and content creation.";

  return (
    <Helmet>
      <title>{fullTitle}</title>
      <meta name="description" content={desc} />
      <meta property="og:title" content={fullTitle} />
      <meta property="og:description" content={desc} />
      <meta property="og:type" content={type} />
      {image && <meta property="og:image" content={image} />}
      {url && <meta property="og:url" content={url} />}
      {url && <link rel="canonical" href={url} />}
      <meta name="twitter:card" content={twitterCard} />
      <meta name="twitter:title" content={fullTitle} />
      <meta name="twitter:description" content={desc} />
      {image && <meta name="twitter:image" content={image} />}
    </Helmet>
  );
}
