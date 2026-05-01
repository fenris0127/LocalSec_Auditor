import { useEffect, useMemo, useState } from "react";
import type { ReactElement } from "react";

import { API_BASE_URL } from "./config/api";
import { Dashboard } from "./pages/Dashboard";
import { NewScan } from "./pages/NewScan";
import { ScanDetail } from "./pages/ScanDetail";

type Route = "dashboard" | "new-scan" | "scan-detail";

const ROUTES: Record<Route, string> = {
  dashboard: "#/",
  "new-scan": "#/new-scan",
  "scan-detail": "#/scans/demo",
};

function getRouteFromHash(hash: string): Route {
  if (hash.startsWith("#/new-scan")) {
    return "new-scan";
  }
  if (hash.startsWith("#/scans/")) {
    return "scan-detail";
  }
  return "dashboard";
}

function getScanIdFromHash(hash: string): string | null {
  if (!hash.startsWith("#/scans/")) {
    return null;
  }
  const scanId = hash.replace("#/scans/", "").trim();
  return scanId ? decodeURIComponent(scanId) : null;
}

function App(): ReactElement {
  const [route, setRoute] = useState<Route>(() => getRouteFromHash(window.location.hash));
  const [scanId, setScanId] = useState<string | null>(() => getScanIdFromHash(window.location.hash));

  useEffect(() => {
    const handleHashChange = () => {
      setRoute(getRouteFromHash(window.location.hash));
      setScanId(getScanIdFromHash(window.location.hash));
    };
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  const page = useMemo(() => {
    if (route === "new-scan") {
      return <NewScan />;
    }
    if (route === "scan-detail") {
      return <ScanDetail scanId={scanId} />;
    }
    return <Dashboard />;
  }, [route, scanId]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <p className="product-label">LocalSec Auditor</p>
          <p className="product-copy">Local security scan workspace</p>
        </div>
        <nav aria-label="Primary navigation">
          <a className={route === "dashboard" ? "active" : ""} href={ROUTES.dashboard}>
            Dashboard
          </a>
          <a className={route === "new-scan" ? "active" : ""} href={ROUTES["new-scan"]}>
            New Scan
          </a>
          <a className={route === "scan-detail" ? "active" : ""} href={ROUTES["scan-detail"]}>
            Scan Detail
          </a>
        </nav>
        <div className="api-box">
          <span>API</span>
          <code>{API_BASE_URL}</code>
        </div>
      </aside>
      <main>{page}</main>
    </div>
  );
}

export default App;
