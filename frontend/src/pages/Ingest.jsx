import { useState, useRef, useCallback } from 'react'
import { Upload, FileText, CheckCircle, AlertTriangle, X, Loader } from 'lucide-react'
import api from '../utils/api'
import { PageHeader } from '../components/ui'

function DropZone({ onFile, disabled }) {
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef(null)

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) onFile(file)
  }, [onFile])

  const handleDrag = (e) => {
    e.preventDefault()
    setDragging(e.type === 'dragover')
  }

  return (
    <div
      onDrop={handleDrop}
      onDragOver={handleDrag}
      onDragLeave={handleDrag}
      onClick={() => !disabled && inputRef.current?.click()}
      className={`relative border-2 border-dashed rounded-2xl p-12 text-center
                  transition-all duration-200 cursor-pointer
                  ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
                  ${dragging
                    ? 'border-accent bg-accent/10 scale-[1.01]'
                    : 'border-border hover:border-accent/50 hover:bg-accent/5'
                  }`}
    >
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        accept=".log,.txt,text/plain"
        onChange={e => e.target.files[0] && onFile(e.target.files[0])}
        disabled={disabled}
      />
      <div className="flex flex-col items-center gap-3">
        <div className={`w-14 h-14 rounded-2xl flex items-center justify-center
                         transition-colors
                         ${dragging ? 'bg-accent/20' : 'bg-muted/60'}`}>
          <Upload size={24} className={dragging ? 'text-accent' : 'text-subtle'} />
        </div>
        <div>
          <p className="text-text font-medium">
            {dragging ? 'Drop to upload' : 'Drop a log file here'}
          </p>
          <p className="text-sm text-dim mt-1">
            or <span className="text-accent">click to browse</span>
          </p>
          <p className="text-xs text-subtle font-mono mt-2">
            Supports: auth.log, syslog, /var/log/auth.log exports
          </p>
        </div>
      </div>
    </div>
  )
}

function ResultCard({ result }) {
  const items = [
    { label: 'Lines processed', value: result.processed, color: 'text-text' },
    { label: 'Entries saved',   value: result.saved,     color: 'text-low'  },
    { label: 'Alerts generated',value: result.alerts,    color: result.alerts > 0 ? 'text-high' : 'text-dim' },
    { label: 'Errors',          value: result.errors,    color: result.errors > 0 ? 'text-critical' : 'text-dim' },
  ]

  return (
    <div className="card border-low/20 bg-low/5 animate-slide-in">
      <div className="flex items-center gap-2 mb-4">
        <CheckCircle size={16} className="text-low" />
        <p className="font-display font-semibold text-text">Ingestion Complete</p>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {items.map(({ label, value, color }) => (
          <div key={label} className="text-center p-3 bg-surface rounded-xl">
            <p className={`text-2xl font-display font-bold ${color}`}>{value}</p>
            <p className="text-xs text-dim font-mono mt-1">{label}</p>
          </div>
        ))}
      </div>
      {result.alerts > 0 && (
        <p className="text-xs text-high bg-high/10 border border-high/20 rounded-lg
                      px-3 py-2 mt-4 font-mono">
          ⚠ {result.alerts} suspicious events detected — check the Events page
        </p>
      )}
    </div>
  )
}

export default function Ingest() {
  const [file,     setFile]     = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [result,   setResult]   = useState(null)
  const [error,    setError]    = useState('')
  const [progress, setProgress] = useState(0)

  const handleFile = (f) => {
    setFile(f)
    setResult(null)
    setError('')
    setProgress(0)
  }

  const handleRemove = () => {
    setFile(null)
    setResult(null)
    setError('')
    setProgress(0)
  }

  const handleUpload = async () => {
    if (!file) return
    setLoading(true)
    setError('')
    setProgress(0)

    // Simulate progress while waiting
    const interval = setInterval(() => {
      setProgress(prev => prev < 85 ? prev + Math.random() * 15 : prev)
    }, 300)

    try {
      const form = new FormData()
      form.append('file', file)
      const { data } = await api.post('/ingest', form, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      setProgress(100)
      setResult(data)
      setFile(null)
    } catch (err) {
      setError(err.response?.data?.error ?? 'Upload failed')
    } finally {
      clearInterval(interval)
      setLoading(false)
    }
  }

  return (
    <div className="animate-fade-in max-w-2xl">
      <PageHeader
        title="Ingest Logs"
        subtitle="Upload historical log files for analysis"
      />

      {/* Info banner */}
      <div className="flex items-start gap-3 text-sm text-dim bg-accent/5
                      border border-accent/15 rounded-xl px-4 py-3.5 mb-6">
        <FileText size={14} className="text-accent mt-0.5 shrink-0" />
        <p>
          Upload log files exported from <span className="font-mono text-accent">/var/log/auth.log</span> or
          similar. Logs are saved as <span className="font-mono text-accent">historical</span> source
          and processed through all detection rules.
        </p>
      </div>

      {/* Drop zone */}
      {!file && !loading && (
        <DropZone onFile={handleFile} disabled={loading} />
      )}

      {/* Selected file */}
      {file && !loading && (
        <div className="card flex items-center gap-3 animate-slide-in">
          <div className="w-10 h-10 rounded-xl bg-accent/10 border border-accent/20
                          flex items-center justify-center shrink-0">
            <FileText size={18} className="text-accent" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-text truncate">{file.name}</p>
            <p className="text-xs text-dim font-mono mt-0.5">
              {(file.size / 1024).toFixed(1)} KB
            </p>
          </div>
          <button onClick={handleRemove} className="text-subtle hover:text-dim p-1">
            <X size={15} />
          </button>
        </div>
      )}

      {/* Upload progress */}
      {loading && (
        <div className="card animate-slide-in">
          <div className="flex items-center gap-3 mb-3">
            <Loader size={15} className="text-accent animate-spin" />
            <p className="text-sm text-text font-medium">Processing {file?.name}...</p>
          </div>
          <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full bg-accent rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="text-xs text-dim font-mono mt-2">{Math.round(progress)}% complete</p>
        </div>
      )}

      {/* Upload button */}
      {file && !loading && (
        <button
          onClick={handleUpload}
          className="btn-primary w-full mt-4 flex items-center justify-center gap-2"
        >
          <Upload size={14} />
          Analyse Log File
        </button>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 text-sm text-critical bg-critical/10
                        border border-critical/20 rounded-lg px-4 py-3 mt-4 animate-slide-in">
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* Result */}
      {result && <div className="mt-4"><ResultCard result={result} /></div>}
    </div>
  )
}
