import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowUpRight, BarChart3, Bell,
  CheckCircle2, ChevronRight, Clock3, FileText, Globe,
  LayoutDashboard, LoaderCircle, Mail, Menu, Search,
  Shield, ShieldAlert, ShieldCheck, Trash2, X
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis
} from 'recharts'
import './App.css'

const STORAGE_KEY = 'phishing-analyzer-history'

const readHistory = () => {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]')
  } catch {
    return []
  }
}

const riskColor = (label = '') => {
  const value = label.toLowerCase()
  if (value === 'phishing') return 'danger'
  if (value === 'suspicious') return 'warning'
  return 'safe'
}

const explainFlag = (flag) => {
  const value = flag.toLowerCase()

  if (value.includes('urgency/pressure')) {
    return {
      title: 'Urgency and pressure language',
      explanation: 'The message contains words that create urgency or pressure, such as immediately, verify, suspend or password.',
      risk: 'Attackers often use urgent language to make recipients act without verifying the request.',
      action: 'Verify the request through the organization’s official website or app. Do not follow unexpected links.'
    }
  }

  if (value.includes('does not use https')) {
    return {
      title: 'HTTPS protection not detected',
      explanation: 'The submitted URL uses HTTP instead of HTTPS.',
      risk: 'Data exchanged with an HTTP website is not protected by HTTPS encryption during transmission.',
      action: 'Avoid entering credentials or personal information. Navigate to the official HTTPS website instead.'
    }
  }

  if (value.includes('many hyphens')) {
    return {
      title: 'Unusual number of hyphens',
      explanation: 'The URL contains multiple hyphens in its address.',
      risk: 'Attackers sometimes create misleading domain names that imitate trusted brands or login pages.',
      action: 'Inspect the actual registered domain carefully before opening the website.'
    }
  }

  if (value.includes('suspicious keyword')) {
    return {
      title: 'Suspicious URL keywords',
      explanation: 'The URL contains words commonly associated with account access or verification, such as login, secure, verify or account.',
      risk: 'These terms can be used to make a fraudulent website appear like a genuine account or banking service.',
      action: 'Do not enter credentials until you independently verify the website address.'
    }
  }

  if (value.includes('ip address')) {
    return {
      title: 'IP address used instead of a domain',
      explanation: 'The website address appears to use a direct IP address.',
      risk: 'Some malicious websites use direct IP addresses to avoid recognizable domain names.',
      action: 'Verify the destination independently before visiting it.'
    }
  }

  if (value.includes('subdomain')) {
    return {
      title: 'Unusual subdomain structure',
      explanation: 'The URL contains several subdomains.',
      risk: 'Complex subdomain structures can make an unrelated domain look like a trusted organization.',
      action: 'Read the registered domain from right to left and verify its ownership.'
    }
  }

  if (value.includes('at sign') || value.includes('@')) {
    return {
      title: 'Unusual @ symbol in URL',
      explanation: 'The URL contains an @ symbol, which can make its destination confusing.',
      risk: 'In URLs, text before @ may be interpreted as user information rather than the destination host.',
      action: 'Do not open the link until you have verified its actual destination.'
    }
  }

  if (value.includes('long url')) {
    return {
      title: 'Unusually long URL',
      explanation: 'The URL exceeds the configured length threshold.',
      risk: 'Long URLs can hide confusing paths or misleading parameters.',
      action: 'Inspect the domain and avoid shortened or unexpected links.'
    }
  }

  return {
    title: 'Additional detection indicator',
    explanation: flag,
    risk: 'This indicator was returned by the configured detection system.',
    action: 'Review the submitted content carefully before interacting with it.'
  }
}




function App() {
  const [page, setPage] = useState('Overview')
  const [scanType, setScanType] = useState('email')
  const [emailText, setEmailText] = useState('')
  const [urlText, setUrlText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState(readHistory)
  const [mobileMenu, setMobileMenu] = useState(false)

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history))
  }, [history])

  const totals = useMemo(() => {
    const counts = { phishing: 0, suspicious: 0, legitimate: 0 }
    history.forEach(item => {
      Object.values(item.result || {}).forEach(scan => {
        const label = (scan.label || '').toLowerCase()
        if (counts[label] !== undefined) counts[label] += 1
      })
    })
    return {
      scans: history.length,
      phishing: counts.phishing,
      suspicious: counts.suspicious,
      legitimate: counts.legitimate
    }
  }, [history])

  const chartData = useMemo(() => {
    const days = []
    for (let i = 6; i >= 0; i--) {
      const date = new Date()
      date.setDate(date.getDate() - i)
      const key = date.toLocaleDateString()
      const dayItems = history.filter(item =>
        new Date(item.timestamp).toLocaleDateString() === key
      )
      let threats = 0
      dayItems.forEach(item => {
        Object.values(item.result || {}).forEach(scan => {
          if (['phishing', 'suspicious'].includes((scan.label || '').toLowerCase())) {
            threats += 1
          }
        })
      })
      days.push({
        day: date.toLocaleDateString('en', { weekday: 'short' }),
        scans: dayItems.length,
        threats
      })
    }
    return days
  }, [history])

  const runScan = async (event) => {
    event.preventDefault()
    setError('')
    setResult(null)

    const payload = {}
    if (scanType === 'email' || scanType === 'both') {
      if (!emailText.trim()) {
        setError('Please enter email content before scanning.')
        return
      }
      payload.text = emailText.trim()
    }
    if (scanType === 'url' || scanType === 'both') {
      if (!urlText.trim()) {
        setError('Please enter a URL before scanning.')
        return
      }
      payload.url = urlText.trim()
    }

    setLoading(true)
    try {
      const response = await fetch('/api/scan/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'The scan request could not be completed.')
      }

      const record = {
        id: `${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: scanType,
        result: data,
        emailPreview: payload.text || '',
        urlPreview: payload.url || ''
      }
      setResult(record)
      setHistory(previous => [record, ...previous].slice(0, 100))
      setPage('Scanner')
    } catch (err) {
      setError(`${err.message}. Check that the Django server is running on port 8000.`)
    } finally {
      setLoading(false)
    }
  }

  const clearHistory = () => {
    if (window.confirm('Delete all saved scan history from this browser?')) {
      setHistory([])
      setResult(null)
    }
  }

  const navItems = [
    { name: 'Overview', icon: LayoutDashboard },
    { name: 'Scanner', icon: Search },
    { name: 'Scan History', icon: Clock3 },
    { name: 'Reports', icon: FileText },
    { name: 'About Project', icon: Shield }
  ]

  const goTo = (name) => {
    setPage(name)
    setMobileMenu(false)
    setError('')
  }

  const formatDate = (value) => new Date(value).toLocaleString()

  const renderFinding = (scan, title) => (
    <div className="finding-card" key={title}>
      <div className="finding-heading">
        <div>
          <span className="eyebrow">{title} ANALYSIS</span>
          <h3>{title === 'Email' ? 'Email threat assessment' : 'URL threat assessment'}</h3>
        </div>
        <span className={`status-pill ${riskColor(scan.label)}`}>
          {scan.label || 'Unknown'}
        </span>
      </div>
      <div className="risk-row">
        <div>
          <span className="muted">Risk score</span>
          <div className="risk-number">{Number(scan.risk_score ?? 0).toFixed(1)}<small>/100</small></div>
        </div>
        <div className="risk-meter">
          <div
            className={`risk-meter-fill ${riskColor(scan.label)}`}
            style={{ width: `${Math.max(0, Math.min(100, Number(scan.risk_score) || 0))}%` }}
          />
        </div>
      </div>




       <div className="explanation-block">
  <h4>
    <AlertTriangle size={16} />
    Explainable Threat Analysis
  </h4>

  {scan.red_flags?.length ? (
    <div className="explanation-list">
      {scan.red_flags.map((flag, index) => {
        const detail = explainFlag(flag)

        return (
          <div className="explanation-item" key={index}>
            <div className="explanation-title">
              <span className="indicator-number">{index + 1}</span>
              <strong>{detail.title}</strong>
              <span className="indicator-status">Detected</span>
            </div>

            <p>{detail.explanation}</p>

            <div className="explanation-detail">
              <strong>Why is this risky?</strong>
              <p>{detail.risk}</p>
            </div>

            <div className="recommendation-detail">
              <strong>Recommended action</strong>
              <p>{detail.action}</p>
            </div>
          </div>
        )
      })}
    </div>
  ) : (
    <p className="muted">No red flags returned. This does not guarantee safety.</p>
  )}
</div>

<div className="risk-interpretation">
  <h4>Risk Score Interpretation</h4>

  <p>
    {Number(scan.risk_score) >= 70
      ? 'The model classifies this result as phishing. Treat it as potentially malicious.'
      : Number(scan.risk_score) >= 40
      ? 'The model classifies this result as suspicious. Additional verification is recommended.'
      : 'The model classifies this result as legitimate. This does not guarantee safety.'}
  </p>

  <div className="threshold-list">
    <span>0–39: Legitimate</span>
    <span>40–69: Suspicious</span>
    <span>70–100: Phishing</span>
  </div>
</div>

        
       
      <p className="disclaimer">
        This result is an automated model assessment, not a guarantee that the content is safe or malicious.
      </p>
    </div>



  )

  const renderResult = (record) => {
    if (!record) return null
    return (
      <section className="results-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">SCAN OUTPUT</span>
            <h2>Threat analysis report</h2>
            <p className="muted">{formatDate(record.timestamp)}</p>
          </div>
          <button className="button secondary" onClick={() => window.print()}>
            <FileText size={16} /> Print report
          </button>
        </div>
        {record.emailPreview && (
          <div className="input-preview">
            <strong><Mail size={15} /> Scanned email content</strong>
            <p>{record.emailPreview}</p>
          </div>
        )}
        {record.urlPreview && (
          <div className="input-preview">
            <strong><Globe size={15} /> Scanned URL</strong>
            <p className="url-preview">{record.urlPreview}</p>
          </div>
        )}
        <div className="finding-grid">
          {record.result.email && renderFinding(record.result.email, 'Email')}
          {record.result.url && renderFinding(record.result.url, 'URL')}
        </div>
      </section>
    )
  }

  const renderOverview = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">SECURITY OPERATIONS</span>
          <h1>Threat overview</h1>
          <p className="muted">Monitor scans and review detected phishing indicators.</p>
        </div>
        <button className="button primary" onClick={() => goTo('Scanner')}>
          <Search size={17} /> New scan
        </button>
      </div>

      <div className="stats-grid">
        <StatCard icon={Activity} title="Total scan records" value={totals.scans} note="Saved in this browser" tone="blue" />
        <StatCard icon={ShieldAlert} title="Phishing detections" value={totals.phishing} note="Model label: phishing" tone="red" />
        <StatCard icon={AlertTriangle} title="Suspicious detections" value={totals.suspicious} note="Requires manual review" tone="amber" />
        <StatCard icon={ShieldCheck} title="Legitimate detections" value={totals.legitimate} note="Model label: legitimate" tone="green" />
      </div>

      <div className="overview-grid">
        <div className="panel chart-panel">
          <div className="panel-heading">
            <div>
              <h3>Scan activity</h3>
              <p className="muted">Last 7 days, based on saved scan records</p>
            </div>
            <span className="subtle-tag">7 DAYS</span>
          </div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#263448" />
                <XAxis dataKey="day" stroke="#8190a5" tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} stroke="#8190a5" tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: '#111d2d', border: '1px solid #293b53', borderRadius: 10 }} />
                <Area type="monotone" dataKey="scans" stroke="#60a5fa" fill="url(#scanGradient)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          {!history.length && <p className="chart-empty">Your scan activity will appear here after your first scan.</p>}
        </div>

        <div className="panel distribution-panel">
          <div className="panel-heading">
            <div>
              <h3>Detection summary</h3>
              <p className="muted">Based on saved scan results</p>
            </div>
            <BarChart3 size={19} className="muted-icon" />
          </div>
          {[
            ['Phishing', totals.phishing, 'danger'],
            ['Suspicious', totals.suspicious, 'warning'],
            ['Legitimate', totals.legitimate, 'safe']
          ].map(([label, value, tone]) => (
            <div className="distribution-item" key={label}>
              <div className="distribution-label"><span>{label}</span><strong>{value}</strong></div>
              <div className="distribution-track">
                <div className={`distribution-fill ${tone}`} style={{
                  width: `${totals.phishing + totals.suspicious + totals.legitimate
                    ? value / (totals.phishing + totals.suspicious + totals.legitimate) * 100 : 0}%`
                }} />
              </div>
            </div>
          ))}
          <p className="small-note">Counts are derived from this browser's saved scan history, not from a central server.</p>
        </div>
      </div>

      <div className="panel recent-panel">
        <div className="panel-heading">
          <div>
            <h3>Recent scans</h3>
            <p className="muted">Latest scan records saved on this device</p>
          </div>
          <button className="text-button" onClick={() => goTo('Scan History')}>View history <ChevronRight size={15} /></button>
        </div>
        {history.length ? (
          <HistoryTable items={history.slice(0, 5)} onSelect={setResult} onOpen={() => goTo('Scanner')} />
        ) : (
          <EmptyState icon={Search} title="No scans yet" text="Run your first email or URL scan to populate this dashboard." />
        )}
      </div>
    </>
  )

  const renderScanner = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">THREAT DETECTION</span>
          <h1>Security scanner</h1>
          <p className="muted">Submit email content, a URL, or both for analysis by your Django ML API.</p>
        </div>
        <span className="connection-status"><span /> API route: /api/scan/</span>
      </div>

      <div className="panel scanner-panel">
        <div className="scanner-tabs">
          <button className={scanType === 'email' ? 'active' : ''} onClick={() => { setScanType('email'); setResult(null) }}><Mail size={16} /> Email scan</button>
          <button className={scanType === 'url' ? 'active' : ''} onClick={() => { setScanType('url'); setResult(null) }}><Globe size={16} /> URL scan</button>
          <button className={scanType === 'both' ? 'active' : ''} onClick={() => { setScanType('both'); setResult(null) }}><Activity size={16} /> Combined scan</button>
        </div>
        <form onSubmit={runScan} className="scan-form">
          {(scanType === 'email' || scanType === 'both') && (
            <label className="form-field">
              <span>Email content</span>
              <textarea value={emailText} onChange={e => setEmailText(e.target.value)} placeholder="Paste the email message here. Include sender claims, links and message body where available..." rows={7} />
              <small>Paste the message text. Avoid entering passwords or other sensitive information.</small>
            </label>
          )}
          {(scanType === 'url' || scanType === 'both') && (
            <label className="form-field">
              <span>Website URL</span>
              <input value={urlText} onChange={e => setUrlText(e.target.value)} placeholder="https://example.com/login" />
              <small>Enter the full URL you want to assess.</small>
            </label>
          )}
          {error && <div className="error-message"><AlertTriangle size={16} /> {error}</div>}
          <div className="form-footer">
            <p className="muted"><Shield size={15} /> Analysis is performed by your configured backend model.</p>
            <button className="button primary" type="submit" disabled={loading}>
              {loading ? <><LoaderCircle className="spin" size={17} /> Analyzing...</> : <><Search size={17} /> Analyze threat</>}
            </button>
          </div>
        </form>
      </div>

      {result ? renderResult(result) : (
        <div className="panel scanner-guidance">
          <div className="guidance-icon"><ShieldCheck size={24} /></div>
          <div>
            <h3>Understand the result</h3>
            <p className="muted">The API returns a risk score, a classification label and red-flag indicators. Review the explanation and verify suspicious content through trusted channels before taking action.</p>
          </div>
        </div>
      )}
    </>
  )

  const renderHistory = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">ACTIVITY LOG</span>
          <h1>Scan history</h1>
          <p className="muted">Review scan records saved locally in this browser.</p>
        </div>
        <button className="button danger-outline" onClick={clearHistory} disabled={!history.length}><Trash2 size={16} /> Clear history</button>
      </div>
      <div className="panel recent-panel">
        {history.length ? (
          <HistoryTable items={history} onSelect={record => { setResult(record); setPage('Scanner') }} onOpen={() => setPage('Scanner')} />
        ) : (
          <EmptyState icon={Clock3} title="History is empty" text="Your completed scans will be listed here." />
        )}
      </div>
    </>
  )

  const renderReports = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">DOCUMENTATION</span>
          <h1>Scan reports</h1>
          <p className="muted">Open a saved analysis and print it or save it as PDF.</p>
        </div>
      </div>
      <div className="panel recent-panel">
        {history.length ? (
          <div className="report-list">
            {history.map(item => {
              const labels = Object.values(item.result || {}).map(x => x.label).filter(Boolean)
              const worst = labels.includes('phishing') ? 'phishing' : labels.includes('suspicious') ? 'suspicious' : 'legitimate'
              return (
                <div className="report-row" key={item.id}>
                  <div className="report-icon"><FileText size={19} /></div>
                  <div className="report-info">
                    <strong>Threat analysis report</strong>
                    <span>{formatDate(item.timestamp)} · {item.type} scan</span>
                  </div>
                  <span className={`status-pill ${riskColor(worst)}`}>{worst}</span>
                  <button className="button secondary small-button" onClick={() => { setResult(item); setPage('Scanner') }}>Open report <ArrowUpRight size={15} /></button>
                </div>
              )
            })}
          </div>
        ) : (
          <EmptyState icon={FileText} title="No reports available" text="Reports are generated after you complete a scan." />
        )}
      </div>
      <div className="notice-panel">
        <AlertTriangle size={18} />
        <p><strong>Report limitations:</strong> Reports contain the results returned by the current backend API. They do not include forensic evidence, sender authentication checks or external reputation lookups unless those capabilities are added to the backend.</p>
      </div>
    </>
  )

  const renderAbout = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">PROJECT INFORMATION</span>
          <h1>About the analyzer</h1>
          <p className="muted">Project scope, architecture and current analysis capabilities.</p>
        </div>
      </div>
      <div className="about-hero panel">
        <div className="about-mark"><Shield size={32} /></div>
        <div>
          <span className="eyebrow">MACHINE LEARNING · CYBERSECURITY</span>
          <h2>Phishing Detection &amp; Explainable Threat Analyzer</h2>
          <p className="muted">A web-based application that analyzes submitted email text and URLs using trained machine learning models and returns risk assessments with detection indicators.</p>
        </div>
      </div>
      <div className="about-grid">
        <InfoCard icon={Mail} title="Email analysis" text="Uses text cleaning, TF-IDF vectorization and a trained classification model to assess submitted email content." />
        <InfoCard icon={Globe} title="URL analysis" text="Uses URL characteristics such as length, dots, hyphens, subdomains, IP presence, HTTPS and suspicious terms." />
        <InfoCard icon={Activity} title="Explainable output" text="Displays the model risk score, classification label and heuristic red flags returned by the backend." />
        <InfoCard icon={ShieldCheck} title="Backend architecture" text="React frontend communicates with a Django REST API through the Vite development proxy." />
      </div>
      <div className="panel methodology-panel">
        <h3>Current system workflow</h3>
        <ol>
          <li>User submits email content, URL or both through the scanner.</li>
          <li>React sends a POST request to <code>/api/scan/</code>.</li>
          <li>Django passes the input to the corresponding trained ML model.</li>
          <li>The backend returns a risk score, label and red-flag indicators.</li>
          <li>The dashboard displays the result and saves a local scan record.</li>
        </ol>
        <p className="small-note">Model accuracy, precision, recall and F1-score are not displayed here because verified evaluation metrics have not yet been connected to this dashboard.</p>
      </div>
    </>
  )

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileMenu ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-icon"><Shield size={22} /></div>
          <div><strong>ThreatLens</strong><span>SECURITY ANALYZER</span></div>
          <button className="mobile-close" onClick={() => setMobileMenu(false)}><X size={19} /></button>
        </div>
        <div className="sidebar-label">WORKSPACE</div>
        <nav className="side-nav">
          {navItems.map(item => {
            const Icon = item.icon
            return (
              <button key={item.name} className={page === item.name ? 'selected' : ''} onClick={() => goTo(item.name)}>
                <Icon size={18} /><span>{item.name}</span>
                {page === item.name && <ChevronRight size={15} className="nav-chevron" />}
              </button>
            )
          })}
        </nav>
        <div className="sidebar-bottom">
          <div className="system-card">
            <span className="system-dot" />
            <div><strong>Local analyzer</strong><small>Development environment</small></div>
          </div>
          <div className="profile-row">
            <div className="avatar">PS</div>
            <div><strong>Project workspace</strong><small>Phishing Analyzer</small></div>
          </div>
        </div>
      </aside>

      {mobileMenu && <button className="mobile-overlay" onClick={() => setMobileMenu(false)} aria-label="Close navigation" />}

      <main className="main-area">
        <header className="topbar">
          <button className="mobile-menu-button" onClick={() => setMobileMenu(true)}><Menu size={20} /></button>
          <div className="breadcrumb">Workspace <ChevronRight size={14} /> <strong>{page}</strong></div>
          <div className="topbar-right">
            <span className="top-status"><span /> System ready</span>
            <div className="top-icon"><Bell size={18} /></div>
          </div>
        </header>

        <div className="page-content">
          {page === 'Overview' && renderOverview()}
          {page === 'Scanner' && renderScanner()}
          {page === 'Scan History' && renderHistory()}
          {page === 'Reports' && renderReports()}
          {page === 'About Project' && renderAbout()}
          <footer className="app-footer">
            <span>ThreatLens · Phishing Detection &amp; Explainable Threat Analyzer</span>
            <span>For educational and defensive security use</span>
          </footer>
        </div>
      </main>
    </div>
  )
}

function StatCard({ icon: Icon, title, value, note, tone }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${tone}`}><Icon size={19} /></div>
      <span className="stat-title">{title}</span>
      <strong className="stat-value">{value}</strong>
      <span className="stat-note">{note}</span>
    </div>
  )
}

function HistoryTable({ items, onSelect }) {
  return (
    <div className="table-scroll">
      <table className="history-table">
        <thead>
          <tr><th>SCAN TYPE</th><th>DATE &amp; TIME</th><th>DETECTION</th><th>RESULT</th><th /></tr>
        </thead>
        <tbody>
          {items.map(item => {
            const scans = Object.entries(item.result || {})
            const labels = scans.map(([, scan]) => scan.label || 'unknown')
            const worst = labels.includes('phishing') ? 'phishing' : labels.includes('suspicious') ? 'suspicious' : labels[0] || 'unknown'
            return (
              <tr key={item.id}>
                <td><span className="type-cell">{item.type === 'email' ? <Mail size={15} /> : item.type === 'url' ? <Globe size={15} /> : <Activity size={15} />}{item.type}</span></td>
                <td>{new Date(item.timestamp).toLocaleString()}</td>
                <td>{scans.map(([type]) => type).join(' + ')}</td>
                <td><span className={`status-pill ${riskColor(worst)}`}>{worst}</span></td>
                <td><button className="icon-button" onClick={() => onSelect(item)} aria-label="View scan result"><ArrowUpRight size={17} /></button></td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function EmptyState({ icon: Icon, title, text }) {
  return (
    <div className="empty-state">
      <div><Icon size={22} /></div>
      <strong>{title}</strong>
      <p>{text}</p>
    </div>
  )
}

function InfoCard({ icon: Icon, title, text }) {
  return (
    <div className="panel info-card">
      <div className="info-icon"><Icon size={19} /></div>
      <h3>{title}</h3>
      <p className="muted">{text}</p>
    </div>
  )
}

export default App
