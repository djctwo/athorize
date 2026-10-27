import { create } from 'zustand'

interface ControlPanelStore {
  openControlId: string | null
  frameworkId: string | null
  open: (controlId: string, frameworkId?: string) => void
  close: () => void
}

export const useControlPanelStore = create<ControlPanelStore>((set) => ({
  openControlId: null,
  frameworkId: null,
  open: (controlId, frameworkId) => set({ openControlId: controlId, frameworkId: frameworkId ?? null }),
  close: () => set({ openControlId: null, frameworkId: null }),
}))
