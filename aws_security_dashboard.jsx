import { useState, useCallback, useMemo } from "react";

// ─── Sample data for demo mode ────────────────────────────────────────────
const DEMO_REPORT = {
  meta: {
    account_id: "123456789012",
    caller_arn: "arn:aws:iam::123456789012:user/audit-user",
    region: "us-east-1",
    scan_time: new Date().toISOString(),
    total_findings: 14,
  },
  summary: { CRITICAL: 3, HIGH: 5, MEDIUM: 4, LOW: 2, INFO: 0 },
  findings: [
    { id: "IAM-0012", severity: "CRITICAL", service: "IAM", resource: "Root account", title: "MFA not enabled on root account", description: "The AWS root account does not have MFA enabled, making it highly vulnerable.", recommendation: "Enable a hardware or virtual MFA device on the root account immediately.", timestamp: new Date().toISOString() },
    { id: "S3-1423", severity: "CRITICAL", service: "S3", resource: "s3://prod-data-backup-2024", title: "Bucket ACL grants public access", description: "The bucket ACL grants 'READ' to 'AllUsers' group.", recommendation: "Remove the public grant from the bucket ACL and use bucket policies instead.", timestamp: new Date().toISOString() },
    { id: "EC2-5501", severity: "CRITICAL", service: "EC2", resource: "sg/sg-0ab1234c (launch-wizard-1)", title: "Security group allows ALL inbound traffic from internet", description: "The security group has a rule allowing all protocols from 0.0.0.0/0.", recommendation: "Remove the all-traffic rule and add only the specific ports required.", timestamp: new Date().toISOString() },
    { id: "EC2-2234", severity: "HIGH", service: "EC2", resource: "sg/sg-0cd5678e (web-servers)", title: "SSH port 22 open to the internet", description: "Port 22 (SSH) is accessible from 0.0.0.0/0.", recommendation: "Restrict port 22 to known IP ranges or use VPN/bastion host access.", timestamp: new Date().toISOString() },
    { id: "EC2-3312", severity: "HIGH", service: "EC2", resource: "sg/sg-0ef9012a (database-sg)", title: "MySQL port 3306 open to the internet", description: "Port 3306 (MySQL) is accessible from 0.0.0.0/0.", recommendation: "Restrict port 3306 to known IP ranges or use VPN/bastion host access.", timestamp: new Date().toISOString() },
    { id: "IAM-7734", severity: "HIGH", service: "IAM", resource: "iam::user/developer-john", title: "Console user 'developer-john' has no MFA", description: "This user has console access but no MFA device configured.", recommendation: "Require MFA for all users with console access via an IAM policy.", timestamp: new Date().toISOString() },
    { id: "RDS-8821", severity: "HIGH", service: "RDS", resource: "prod-mysql-db", title: "RDS instance 'prod-mysql-db' is publicly accessible", description: "The instance endpoint is publicly reachable from the internet.", recommendation: "Set PubliclyAccessible=false and place the instance in a private subnet.", timestamp: new Date().toISOString() },
    { id: "CT-0044", severity: "HIGH", service: "CloudTrail", resource: "arn:aws:cloudtrail:us-east-1:123456789012:trail/main", title: "Trail 'main' is not logging", description: "This CloudTrail trail exists but logging is currently disabled.", recommendation: "Enable logging on the trail immediately.", timestamp: new Date().toISOString() },
    { id: "S3-2231", severity: "MEDIUM", service: "S3", resource: "s3://dev-static-assets", title: "Default encryption not enabled", description: "The bucket does not have default server-side encryption configured.", recommendation: "Enable default SSE-S3 or SSE-KMS encryption on the bucket.", timestamp: new Date().toISOString() },
    { id: "EBS-1102", severity: "MEDIUM", service: "EBS", resource: "vol-0a1b2c3d4e5f67890", title: "EBS volume is not encrypted", description: "Volume vol-0a1b2c3d4e5f67890 (in-use, 100GB) is not encrypted at rest.", recommendation: "Enable EBS encryption by default in account settings.", timestamp: new Date().toISOString() },
    { id: "EBS-1103", severity: "MEDIUM", service: "EBS", resource: "vol-0f9e8d7c6b5a43210", title: "EBS volume is not encrypted", description: "Volume vol-0f9e8d7c6b5a43210 (available, 20GB) is not encrypted at rest.", recommendation: "Enable EBS encryption by default in account settings.", timestamp: new Date().toISOString() },
    { id: "RDS-9934", severity: "MEDIUM", service: "RDS", resource: "staging-postgres", title: "RDS instance 'staging-postgres' storage is not encrypted", description: "The RDS instance is not using encrypted storage.", recommendation: "Enable storage encryption via snapshot restore.", timestamp: new Date().toISOString() },
    { id: "CT-0045", severity: "LOW", service: "CloudTrail", resource: "arn:aws:cloudtrail:us-east-1:123456789012:trail/main", title: "Trail 'main' is not multi-region", description: "This trail only logs events in a single region.", recommendation: "Convert to a multi-region trail.", timestamp: new Date().toISOString() },
    { id: "S3-3341", severity: "LOW", service: "S3", resource: "s3://logs-archive-bucket", title: "Versioning not enabled", description: "Object versioning is disabled, making accidental deletions unrecoverable.", recommendation: "Enable versioning to protect against accidental deletion.", timestamp: new Date().toISOString() },
  ],
};

// ─── Config ───────────────────────────────────────────────────────────────
const SEV_CONFIG = {
  CRITICAL: { color: "#ff3b5c", bg: "#ff3b5c18", label: "Critical" },
  HIGH:     { color: "#ff8c42", bg: "#ff8c4218", label: "High" },
  MEDIUM:   { color: "#ffd166", bg: "#ffd16618", label: "Medium" },
  LOW:      { color: "#06d6a0", bg: "#06d6a018", label: "Low" },
  INFO:     { color: "#74b9ff", bg: "#74b9ff18", label: "Info" },
};

const SERVICE_ICONS = {
  S3: "🪣", IAM: "🔑", EC2: "🖥️", EBS: "💾", CloudTrail: "📋", RDS: "🗄️",
};

// ─── Components ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }) {
  const cfg = SEV_CONFIG[severity] || SEV_CONFIG.INFO;
  return (
    <span style={{
      display: "inline-block",
      padding: "2px 10px",
      borderRadius: "4px",
      fontSize: "11px",
      fontWeight: 700,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: cfg.color,
      background: cfg.bg,
      border: `1px solid ${cfg.color}44`,
      fontFamily: "'JetBrains Mono', monospace",
    }}>{cfg.label}</span>
  );
}

function StatCard({ label, value, color, bg }) {
  return (
    <div style={{
      background: bg,
      border: `1px solid ${color}33`,
      borderTop: `3px solid ${color}`,
      borderRadius: "8px",
      padding: "18px 20px",
      minWidth: 110,
      flex: "1 1 0",
      textAlign: "center",
    }}>
      <div style={{ fontSize: "32px", fontWeight: 800, color, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: "11px", color: "#8899aa", marginTop: 6, letterSpacing: "0.1em", textTransform: "uppercase", fontFamily: "'JetBrains Mono', monospace" }}>{label}</div>
    </div>
  );
}

function MiniBar({ count, total, color }) {
  const pct = total ? (count / total) * 100 : 0;
  return (
    <div style={{ height: 6, background: "#1e2a3a", borderRadius: 3, overflow: "hidden", marginTop: 6 }}>
      <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 3, transition: "width 0.6s ease" }} />
    </div>
  );
}

function FindingRow({ f, expanded, onToggle }) {
  const cfg = SEV_CONFIG[f.severity] || SEV_CONFIG.INFO;
  const icon = SERVICE_ICONS[f.service] || "⚡";

  return (
    <div style={{
      borderBottom: "1px solid #1a2535",
      background: expanded ? "#0d1926" : "transparent",
      transition: "background 0.15s",
    }}>
      <div
        onClick={onToggle}
        style={{
          display: "grid",
          gridTemplateColumns: "40px 100px 80px 1fr 110px",
          alignItems: "center",
          gap: 12,
          padding: "12px 20px",
          cursor: "pointer",
          userSelect: "none",
        }}
        onMouseEnter={e => { if (!expanded) e.currentTarget.style.background = "#0a1420"; }}
        onMouseLeave={e => { if (!expanded) e.currentTarget.style.background = "transparent"; }}
      >
        <span style={{ fontSize: 18, textAlign: "center" }}>{icon}</span>
        <SeverityBadge severity={f.severity} />
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#4a9eff" }}>{f.service}</span>
        <span style={{ color: "#c8d8e8", fontSize: 13, fontWeight: 500 }}>{f.title}</span>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#4a5568", textAlign: "right" }}>{f.id}</span>
      </div>

      {expanded && (
        <div style={{ padding: "0 20px 16px 72px", display: "grid", gap: 12 }}>
          <div>
            <div style={{ fontSize: 11, color: "#4a9eff", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 4, fontFamily: "'JetBrains Mono', monospace" }}>Resource</div>
            <code style={{ fontSize: 12, color: "#a0b0c0", background: "#0a1420", padding: "4px 8px", borderRadius: 4 }}>{f.resource}</code>
          </div>
          <div>
            <div style={{ fontSize: 11, color: "#4a9eff", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 4, fontFamily: "'JetBrains Mono', monospace" }}>Description</div>
            <p style={{ margin: 0, fontSize: 13, color: "#8899aa", lineHeight: 1.6 }}>{f.description}</p>
          </div>
          <div>
            <div style={{ fontSize: 11, color: "#06d6a0", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 4, fontFamily: "'JetBrains Mono', monospace" }}>Recommendation</div>
            <p style={{ margin: 0, fontSize: 13, color: "#b8c8d8", lineHeight: 1.6, borderLeft: "3px solid #06d6a044", paddingLeft: 10 }}>{f.recommendation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────
export default function App() {
  const [report, setReport] = useState(DEMO_REPORT);
  const [isDemoMode, setIsDemoMode] = useState(true);
  const [filterSev, setFilterSev] = useState("ALL");
  const [filterSvc, setFilterSvc] = useState("ALL");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState(null);
  const [dragOver, setDragOver] = useState(false);

  const loadFile = useCallback((file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(e.target.result);
        if (parsed.findings && parsed.meta) {
          setReport(parsed);
          setIsDemoMode(false);
          setFilterSev("ALL");
          setFilterSvc("ALL");
          setSearch("");
          setExpandedId(null);
        } else {
          alert("Invalid report format. Please load a JSON file generated by aws_security_auditor.py");
        }
      } catch {
        alert("Could not parse JSON file.");
      }
    };
    reader.readAsText(file);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    loadFile(file);
  }, [loadFile]);

  const handleFileInput = useCallback((e) => {
    loadFile(e.target.files[0]);
  }, [loadFile]);

  const services = useMemo(() => {
    const s = new Set(report.findings.map(f => f.service));
    return ["ALL", ...Array.from(s).sort()];
  }, [report]);

  const filtered = useMemo(() => {
    return report.findings.filter(f => {
      if (filterSev !== "ALL" && f.severity !== filterSev) return false;
      if (filterSvc !== "ALL" && f.service !== filterSvc) return false;
      if (search) {
        const q = search.toLowerCase();
        return f.title.toLowerCase().includes(q) || f.resource.toLowerCase().includes(q) || f.description.toLowerCase().includes(q);
      }
      return true;
    });
  }, [report, filterSev, filterSvc, search]);

  const total = report.meta.total_findings;
  const scanDate = new Date(report.meta.scan_time).toLocaleString();

  // Risk score 0-100
  const riskScore = Math.min(100, Math.round(
    (report.summary.CRITICAL || 0) * 25 +
    (report.summary.HIGH || 0) * 10 +
    (report.summary.MEDIUM || 0) * 4 +
    (report.summary.LOW || 0) * 1
  ));
  const riskColor = riskScore >= 70 ? "#ff3b5c" : riskScore >= 40 ? "#ff8c42" : "#06d6a0";
  const riskLabel = riskScore >= 70 ? "HIGH RISK" : riskScore >= 40 ? "MODERATE" : "LOW RISK";

  return (
    <div style={{
      minHeight: "100vh",
      background: "#060d18",
      color: "#c8d8e8",
      fontFamily: "'Segoe UI', system-ui, sans-serif",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@700;800&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0a1420; }
        ::-webkit-scrollbar-thumb { background: #1e2a3a; border-radius: 3px; }
        input::placeholder { color: #2a3a4a; }
        select option { background: #0d1926; }
      `}</style>

      {/* Header */}
      <div style={{
        background: "linear-gradient(180deg, #0a1420 0%, #060d18 100%)",
        borderBottom: "1px solid #1a2535",
        padding: "20px 32px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 20,
      }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 8,
              background: "linear-gradient(135deg, #ff3b5c, #ff8c42)",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18,
            }}>🛡️</div>
            <div>
              <h1 style={{ margin: 0, fontFamily: "'Syne', sans-serif", fontSize: 20, fontWeight: 800, letterSpacing: "-0.02em", color: "#e8f0f8" }}>
                AWS Security Auditor
              </h1>
              <p style={{ margin: 0, fontSize: 11, color: "#4a5568", fontFamily: "'JetBrains Mono', monospace" }}>
                {isDemoMode ? "DEMO MODE — load your report JSON to see real results" : `Account: ${report.meta.account_id} · ${report.meta.region} · ${scanDate}`}
              </p>
            </div>
          </div>
        </div>

        {/* Load file button */}
        <label style={{
          display: "flex", alignItems: "center", gap: 8,
          padding: "8px 16px",
          background: "#0d1926",
          border: "1px solid #1e3a5a",
          borderRadius: 6,
          cursor: "pointer",
          fontSize: 12,
          color: "#4a9eff",
          fontFamily: "'JetBrains Mono', monospace",
          transition: "border-color 0.15s",
        }}
          onMouseEnter={e => e.currentTarget.style.borderColor = "#4a9eff"}
          onMouseLeave={e => e.currentTarget.style.borderColor = "#1e3a5a"}
        >
          📂 Load Report JSON
          <input type="file" accept=".json" style={{ display: "none" }} onChange={handleFileInput} />
        </label>
      </div>

      {/* Drop zone (shown when no real report loaded) */}
      {isDemoMode && (
        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          style={{
            margin: "20px 32px 0",
            border: `2px dashed ${dragOver ? "#4a9eff" : "#1e3a5a"}`,
            borderRadius: 10,
            padding: "20px",
            textAlign: "center",
            background: dragOver ? "#0a1e30" : "#070e1a",
            transition: "all 0.15s",
            cursor: "default",
          }}
        >
          <p style={{ margin: 0, color: "#2a4a6a", fontSize: 13, fontFamily: "'JetBrains Mono', monospace" }}>
            ↑ Drop your <code style={{ color: "#4a9eff" }}>aws_audit_report.json</code> here, or click "Load Report JSON" above
          </p>
        </div>
      )}

      {/* Summary row */}
      <div style={{ padding: "24px 32px 0", display: "flex", gap: 16, flexWrap: "wrap", alignItems: "stretch" }}>
        {/* Risk Score */}
        <div style={{
          background: "#0d1926",
          border: `1px solid ${riskColor}33`,
          borderTop: `3px solid ${riskColor}`,
          borderRadius: 8,
          padding: "18px 24px",
          minWidth: 140,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}>
          <div style={{ fontSize: 42, fontWeight: 800, color: riskColor, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>{riskScore}</div>
          <div style={{ fontSize: 11, color: riskColor, marginTop: 4, letterSpacing: "0.15em", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>{riskLabel}</div>
          <div style={{ fontSize: 10, color: "#4a5568", marginTop: 2 }}>Risk Score</div>
        </div>

        {/* Severity counts */}
        {Object.entries(SEV_CONFIG).map(([sev, cfg]) => (
          <StatCard
            key={sev}
            label={cfg.label}
            value={report.summary[sev] || 0}
            color={cfg.color}
            bg={cfg.bg}
          />
        ))}

        {/* Total */}
        <StatCard label="Total" value={total} color="#4a9eff" bg="#4a9eff18" />
      </div>

      {/* Service breakdown */}
      <div style={{ padding: "16px 32px 0" }}>
        <div style={{
          background: "#0d1926",
          border: "1px solid #1a2535",
          borderRadius: 8,
          padding: "16px 20px",
          display: "flex",
          gap: 24,
          flexWrap: "wrap",
        }}>
          {services.filter(s => s !== "ALL").map(svc => {
            const count = report.findings.filter(f => f.service === svc).length;
            return (
              <div key={svc} style={{ minWidth: 80, flex: "1 1 0" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                  <span style={{ fontSize: 12, color: "#8899aa" }}>{SERVICE_ICONS[svc] || "⚡"} {svc}</span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 700, color: "#c8d8e8" }}>{count}</span>
                </div>
                <MiniBar count={count} total={total} color="#4a9eff" />
              </div>
            );
          })}
        </div>
      </div>

      {/* Filters */}
      <div style={{ padding: "16px 32px 0", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search findings..."
          style={{
            flex: "1 1 200px", padding: "8px 14px",
            background: "#0d1926", border: "1px solid #1e2a3a", borderRadius: 6,
            color: "#c8d8e8", fontSize: 13, outline: "none",
            fontFamily: "'JetBrains Mono', monospace",
          }}
        />
        <select value={filterSev} onChange={e => setFilterSev(e.target.value)} style={{
          padding: "8px 12px", background: "#0d1926", border: "1px solid #1e2a3a",
          borderRadius: 6, color: "#c8d8e8", fontSize: 12, outline: "none",
          fontFamily: "'JetBrains Mono', monospace", cursor: "pointer",
        }}>
          <option value="ALL">All Severities</option>
          {Object.keys(SEV_CONFIG).map(s => <option key={s} value={s}>{SEV_CONFIG[s].label}</option>)}
        </select>
        <select value={filterSvc} onChange={e => setFilterSvc(e.target.value)} style={{
          padding: "8px 12px", background: "#0d1926", border: "1px solid #1e2a3a",
          borderRadius: 6, color: "#c8d8e8", fontSize: 12, outline: "none",
          fontFamily: "'JetBrains Mono', monospace", cursor: "pointer",
        }}>
          {services.map(s => <option key={s} value={s}>{s === "ALL" ? "All Services" : `${SERVICE_ICONS[s] || ""} ${s}`}</option>)}
        </select>
        <span style={{ fontSize: 12, color: "#4a5568", fontFamily: "'JetBrains Mono', monospace" }}>
          {filtered.length} / {total} findings
        </span>
      </div>

      {/* Findings table */}
      <div style={{ margin: "16px 32px 32px", background: "#0d1926", border: "1px solid #1a2535", borderRadius: 10, overflow: "hidden" }}>
        {/* Column headers */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "40px 100px 80px 1fr 110px",
          gap: 12,
          padding: "10px 20px",
          background: "#080f1a",
          borderBottom: "1px solid #1a2535",
        }}>
          {["", "Severity", "Service", "Finding", "ID"].map((h, i) => (
            <span key={i} style={{ fontSize: 10, color: "#2a4a6a", textTransform: "uppercase", letterSpacing: "0.12em", fontFamily: "'JetBrains Mono', monospace", textAlign: i === 4 ? "right" : "left" }}>{h}</span>
          ))}
        </div>

        {filtered.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#2a4a6a", fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>
            No findings match your filters.
          </div>
        ) : (
          filtered.map(f => (
            <FindingRow
              key={f.id}
              f={f}
              expanded={expandedId === f.id}
              onToggle={() => setExpandedId(expandedId === f.id ? null : f.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}
