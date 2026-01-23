import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";

import messages from "../translations/messages";

const navOrder = [
  { key: "locations", anchor: "locations" },
  { key: "items", anchor: "items" },
  { key: "tags", anchor: "tags" },
  { key: "events", anchor: "events" },
  { key: "audit", anchor: "audit" },
];

export default function Home() {
  const router = useRouter();
  const locale = router.locale ?? "en";
  const t = messages[locale] ?? messages.en;

  const currentPath = router.asPath.includes("?")
    ? router.asPath.split("?")[0]
    : router.asPath;

  const switchLocale = (targetLocale) => {
    if (targetLocale === locale) {
      return;
    }
    router.push(currentPath, currentPath, { locale: targetLocale });
  };

  return (
    <>
      <Head>
        <title>{t.home.title}</title>
        <meta name="description" content={t.home.summary} />
      </Head>
      <div style={containerStyle}>
        <header style={headerStyle}>
          <div>
            <p style={taglineStyle}>{t.home.subtitle}</p>
            <h1 style={titleStyle}>{t.home.title}</h1>
            <p style={summaryStyle}>{t.home.summary}</p>
          </div>
          <div style={switcherStyle}>
            {["en", "pt"].map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => switchLocale(option)}
                style={{
                  ...switcherButtonStyle,
                  ...(locale === option ? switcherActiveStyle : {}),
                }}
                aria-pressed={locale === option}
              >
                {t.lang[option]}
              </button>
            ))}
          </div>
        </header>

        <nav style={navStyle}>
          {navOrder.map(({ key, anchor }) => (
            <Link
              key={key}
              href={`#${anchor}`}
              locale={locale}
              style={navLinkStyle}
            >
              {t.nav[key]}
            </Link>
          ))}
        </nav>

        <section style={heroStyle}>
          <p>
            API base:{" "}
            <code>
              {process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://backend:8000"}
            </code>
          </p>
        </section>

        <div style={gridStyle}>
          {navOrder.map(({ key, anchor }) => (
            <article key={key} id={anchor} style={cardStyle}>
              <h2>{t.nav[key]}</h2>
              <p>{t.sections[key]}</p>
              <Link
                href={`#${anchor}`}
                locale={locale}
                style={ctaStyle}
                aria-label={`${t.nav[key]} section`}
              >
                {t.cta}
              </Link>
            </article>
          ))}
        </div>
      </div>
    </>
  );
}

const containerStyle = {
  minHeight: "100vh",
  padding: "2rem",
  fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
  background:
    "linear-gradient(180deg, rgba(20,34,64,0.9), rgba(11,17,33,0.95))",
  color: "#fff",
};

const headerStyle = {
  display: "flex",
  justifyContent: "space-between",
  flexWrap: "wrap",
  alignItems: "center",
  gap: "1rem",
};

const taglineStyle = {
  margin: 0,
  fontSize: "1rem",
  letterSpacing: "0.12em",
  textTransform: "uppercase",
};

const titleStyle = {
  margin: "0.25rem 0",
  fontSize: "clamp(2.4rem, 4vw, 3.5rem)",
};

const summaryStyle = {
  maxWidth: "30rem",
  margin: "0",
};

const switcherStyle = {
  display: "flex",
  gap: "0.5rem",
};

const switcherButtonStyle = {
  background: "transparent",
  border: "1px solid rgba(255,255,255,0.4)",
  borderRadius: "999px",
  padding: "0.5rem 1rem",
  color: "#fff",
  cursor: "pointer",
  transition: "background 0.2s ease",
};

const switcherActiveStyle = {
  background: "#fff",
  color: "#0b0d14",
};

const navStyle = {
  marginTop: "1.5rem",
  display: "flex",
  flexWrap: "wrap",
  gap: "1rem",
  borderTop: "1px solid rgba(255,255,255,0.2)",
  paddingTop: "0.5rem",
};

const navLinkStyle = {
  color: "#9ed0ff",
  textDecoration: "none",
  fontWeight: "500",
};

const heroStyle = {
  marginTop: "2rem",
  padding: "1.5rem",
  borderRadius: "16px",
  background: "rgba(255, 255, 255, 0.08)",
  border: "1px solid rgba(255, 255, 255, 0.2)",
};

const gridStyle = {
  marginTop: "2.5rem",
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
  gap: "1.25rem",
};

const cardStyle = {
  padding: "1.5rem",
  borderRadius: "16px",
  background: "rgba(255,255,255,0.05)",
  border: "1px solid rgba(255,255,255,0.15)",
};

const ctaStyle = {
  display: "inline-block",
  marginTop: "1rem",
  color: "#9ed0ff",
  textDecoration: "none",
  fontWeight: "600",
};
