import { create } from 'zustand'
import type { System } from '../types'

interface SystemStore {
  systems: System[]
  selectedSystemId: number | null
  setSystems: (systems: System[]) => void
  selectSystem: (id: number | null) => void
}

export const useSystemStore = create<SystemStore>((set) => ({
  systems: [],
  selectedSystemId: null,
  setSystems: (systems) =>
    set((state) => ({
      systems,
      selectedSystemId:
        state.selectedSystemId != null &&
        systems.some((s) => s.id === state.selectedSystemId)
          ? state.selectedSystemId
          : systems[0]?.id ?? null,
    })),
  selectSystem: (id) => set({ selectedSystemId: id }),
}))

export const useSelectedSystem = (): System | null =>
  useSystemStore(
    (s) => s.systems.find((sys) => sys.id === s.selectedSystemId) ?? null
  )
