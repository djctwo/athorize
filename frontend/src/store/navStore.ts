import { create } from 'zustand'

// Tracks which sidebar groups are collapsed. In-memory only (no localStorage
// per project rules) — groups default to expanded each session.
interface NavStore {
  collapsed: Record<string, boolean>
  toggleGroup: (title: string) => void
}

export const useNavStore = create<NavStore>((set) => ({
  collapsed: {},
  toggleGroup: (title) =>
    set((s) => ({ collapsed: { ...s.collapsed, [title]: !s.collapsed[title] } })),
}))
