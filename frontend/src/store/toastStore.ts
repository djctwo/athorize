import { create } from 'zustand'

export type ToastType = 'success' | 'error' | 'info'

export interface ToastAction {
  label: string
  onAction: () => void
}

interface Toast {
  id: number
  type: ToastType
  message: string
  action?: ToastAction
}

interface ToastStore {
  toasts: Toast[]
  add: (type: ToastType, message: string, options?: { durationMs?: number; action?: ToastAction }) => number
  dismiss: (id: number) => void
}

let nextId = 0
const timers = new Map<number, ReturnType<typeof setTimeout>>()

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  add: (type, message, options) => {
    const id = ++nextId
    const duration = options?.durationMs ?? 4000
    set((s) => {
      const next = [...s.toasts, { id, type, message, action: options?.action }]
      if (next.length > 5) {
        const evicted = next.shift()!
        const t = timers.get(evicted.id)
        if (t) { clearTimeout(t); timers.delete(evicted.id) }
      }
      return { toasts: next }
    })
    const timer = setTimeout(() => {
      timers.delete(id)
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }))
    }, duration)
    timers.set(id, timer)
    return id
  },
  dismiss: (id) => {
    const timer = timers.get(id)
    if (timer) { clearTimeout(timer); timers.delete(id) }
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }))
  },
}))

export const toast = {
  success: (msg: string) => useToastStore.getState().add('success', msg),
  error: (msg: string) => useToastStore.getState().add('error', msg),
  info: (msg: string) => useToastStore.getState().add('info', msg),
  undo: (msg: string, onUndo: () => void, durationMs = 8000) =>
    useToastStore.getState().add('info', msg, {
      durationMs,
      action: { label: 'Undo', onAction: onUndo },
    }),
}
