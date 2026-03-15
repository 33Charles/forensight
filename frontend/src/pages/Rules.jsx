import { useState } from 'react'
import { RefreshCw, CheckCircle, AlertTriangle, Settings } from 'lucide-react'
import api from '../utils/api'
import { PageHeader } from '../components/ui'

const RULES = [
  { key: 'brute_force',           label: 'SSH Brute Force',        technique: 'T1110', tactic: 'Credential Access',     severity: 'medium/high/critical' },
  { key: 'root_login',            label: 'Root Login Attempt',     technique: 'T1078', tactic: 'Initial Access',         severity: 'high'     },
  { key: 'sudo_brute_force',      label: 'Sudo Brute Force',       technique: 'T1548.003', tactic: 'Privilege Escalation', severity: 'high'  },
  { key: 'unauthorized_sudo',     label: 'Unauthorized Sudo',      technique: 'T1548.003', tactic: 'Privilege Escalation', severity: 'medium'},
  { key: 'privilege_escalation',  label: 'Privilege Escalation',   technique: 'T1548', tactic: 'Privilege Escalation',   severity: 'high/critical' },
  { key: 'sensitive_file_access', label: 'Sensitive File Access',  technique: 'T1003', tactic: 'Credential Access',      severity: 'high'    },
  { key: 'unauthorized_file_access','label':'Unauthorized File Access','technique':'T1083','tactic':'Discovery',         severity: 'medium'  },
  { key: 'port_scan',             label: 'Port Scan',              technique: 'T1046', tactic: 'Discovery',              severity: 'high'    },
  { key: 'reverse_shell',         label: 'Reverse Shell',          technique: 'T1059', tactic: 'Execution',              severity: 'critical'},
  { key: 'c2_detection',          label: 'C2 Beaconing',           technique: 'T1071', tactic: 'Command & Control',      severity: 'critical'},
]

const TACTIC_COLORS = {
  'Credential Access':   'text-critical bg-critical/10 border-critical/20',
  'Initial Access':      'text-high bg-high/10 border-high/20',
  'Privilege Escalation':'text-medium bg-medium/10 border-medium/20',
  'Discovery':           'text-info bg-info/10 border-info/20',
  'Execution':           'text-critical bg-critical/10 border-critical/20',
  'Command & Control':   'text-accent bg-accent/10 border-accent/20',
}

export default function Rules() {
  const [status,  setStatus]  = useState(null)  // 'success' | 'error'
  const [loading, setLoading] = useState(false)

  const handleReload = async () => {
    setLoading(true)
    setStatus(null)
    try {
      await api.post('/rules/reload')
      setStatus('success')
    } catch {
      setStatus('error')
    } finally {
      setLoading(false)
      setTimeout(() => setStatus(null), 3000)
    }
  }

  return (
    <div className="animate-fade-in">
      <PageHeader
        title="Detection Rules"
        subtitle="Active MITRE ATT&CK-mapped detection rules"
      >
        <button
          onClick={handleReload}
          disabled={loading}
          className="btn-primary flex items-center gap-1.5"
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          Reload Rules
        </button>
      </PageHeader>

      {/* Status */}
      {status === 'success' && (
        <div className="flex items-center gap-2 text-sm text-low bg-low/10
                        border border-low/20 rounded-lg px-4 py-3 mb-5 animate-slide-in">
          <CheckCircle size={14} />
          Detection rules reloaded successfully from detection_rules.yaml
        </div>
      )}
      {status === 'error' && (
        <div className="flex items-center gap-2 text-sm text-critical bg-critical/10
                        border border-critical/20 rounded-lg px-4 py-3 mb-5 animate-slide-in">
          <AlertTriangle size={14} />
          Failed to reload rules — check server logs
        </div>
      )}

      {/* Info banner */}
      <div className="flex items-start gap-3 text-sm text-dim bg-accent/5
                      border border-accent/15 rounded-xl px-4 py-3.5 mb-5">
        <Settings size={14} className="text-accent mt-0.5 shrink-0" />
        <p>
          Rules are loaded from <span className="font-mono text-accent">backend/detection_rules.yaml</span>.
          Edit thresholds, severities, and whitelists there, then click{' '}
          <span className="text-text font-medium">Reload Rules</span> to apply changes without restarting the app.
        </p>
      </div>

      {/* Rules table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-surface/60">
              {['Rule','MITRE Technique','Tactic','Severity'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs font-mono
                                       text-subtle uppercase tracking-widest font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {RULES.map(r => (
              <tr key={r.key}
                  className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                <td className="px-4 py-3">
                  <p className="text-sm text-text font-medium">{r.label}</p>
                  <p className="text-xs text-subtle font-mono mt-0.5">{r.key}</p>
                </td>
                <td className="px-4 py-3">
                  <span className="badge bg-surface border border-border text-dim font-mono">
                    {r.technique}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`badge border ${TACTIC_COLORS[r.tactic] ?? 'text-dim bg-muted border-border'}`}>
                    {r.tactic}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs font-mono text-dim">{r.severity}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
