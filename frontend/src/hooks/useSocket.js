import { useEffect, useRef } from 'react'
import { io } from 'socket.io-client'

let _socket = null

export function useSocket(onSuspiciousEvent, onLogEntry) {
  const cbRef = useRef({ onSuspiciousEvent, onLogEntry })
  cbRef.current = { onSuspiciousEvent, onLogEntry }

  useEffect(() => {
    if (!_socket) {
      _socket = io('/', { transports: ['websocket'] })
    }

    const handleEvent = (data) => cbRef.current.onSuspiciousEvent?.(data)
    const handleLog   = (data) => cbRef.current.onLogEntry?.(data)

    _socket.on('suspicious_event', handleEvent)
    _socket.on('log_entry', handleLog)

    return () => {
      _socket.off('suspicious_event', handleEvent)
      _socket.off('log_entry', handleLog)
    }
  }, [])
}
