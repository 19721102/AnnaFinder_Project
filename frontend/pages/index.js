export default function Home() {
  return (
    <main
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        alignItems: "center",
        fontFamily: "system-ui, sans-serif",
        textAlign: "center",
        padding: "2rem",
      }}
    >
      <h1>AnnaFinder Frontend (Next.js dev)</h1>
      <p>Hot reload enabled via <code>next dev</code> inside the Compose stack.</p>
      <p>
        API base:{" "}
        <code>{process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://backend:8000"}</code>
      </p>
    </main>
  );
}
