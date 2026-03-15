export function exportToCSV(data, filename) {
  if (!data?.length) return

  const headers = Object.keys(data[0])
  const rows    = data.map(row =>
    headers.map(h => {
      const val = row[h] ?? ''
      // Wrap in quotes if contains comma, newline or quote
      const str = String(val).replace(/"/g, '""')
      return /[,\n"]/.test(str) ? `"${str}"` : str
    }).join(',')
  )

  const csv  = [headers.join(','), ...rows].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
