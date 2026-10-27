import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useLayoutEffect, useRef, useState } from 'react'
import { MessageSquare, Trash2, User as UserIcon } from 'lucide-react'
import { api } from '../lib/api'
import { formatRelative } from '../lib/datetime'
import { useUserStore } from '../store/userStore'
import { useCan } from '../hooks/useRole'
import { toast } from '../store/toastStore'
import { SkeletonBar } from './Skeleton'

export interface CommentItem {
  id: number
  entity_type: string
  entity_id: number
  author_id: number | null
  author_name: string
  body: string
  mentions: number[]
  created_at: string | null
}

interface Assignable {
  id: number
  display_name: string
  username: string
}

interface Props {
  entityType: 'finding' | 'control_implementation'
  entityId: number
}

const MENTION_TOKEN = /(@[A-Za-z0-9][A-Za-z0-9._-]*)/g
const ACTIVE_MENTION = /(?:^|\s)@([A-Za-z0-9._-]*)$/

/** Render a comment body with @mention tokens highlighted. */
function CommentBody({ body }: { body: string }) {
  const parts = body.split(MENTION_TOKEN)
  return (
    <p className="text-sm text-[var(--text-primary)] whitespace-pre-wrap break-words">
      {parts.map((part, i) =>
        part.startsWith('@') ? (
          <span key={i} className="text-[var(--accent)] font-medium">{part}</span>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </p>
  )
}

/** Flat comment thread + composer with a simple @username autocomplete
 * (fed by /users/assignable, so any role can mention teammates). */
export default function CommentsSection({ entityType, entityId }: Props) {
  const qc = useQueryClient()
  const currentUser = useUserStore(s => s.user)
  const [body, setBody] = useState('')
  const [mentionQuery, setMentionQuery] = useState<string | null>(null)
  const [highlighted, setHighlighted] = useState(0)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const queryKey = ['comments', entityType, String(entityId)]
  const { data: comments = [], isLoading } = useQuery<CommentItem[]>({
    queryKey,
    queryFn: () => api.get(`/comments?entity_type=${entityType}&entity_id=${entityId}`),
  })
  const { data: assignable = [] } = useQuery<Assignable[]>({
    queryKey: ['assignable-users'],
    queryFn: () => api.get('/users/assignable'),
  })

  const postMut = useMutation({
    mutationFn: (text: string) =>
      api.post<CommentItem>('/comments', { entity_type: entityType, entity_id: entityId, body: text }),
    onSuccess: () => {
      setBody('')
      setMentionQuery(null)
      qc.invalidateQueries({ queryKey })
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : 'Comment failed'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => api.delete(`/comments/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey }),
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : 'Delete failed'),
  })

  const suggestions = mentionQuery === null
    ? []
    : assignable
        .filter(u =>
          u.username.toLowerCase().startsWith(mentionQuery.toLowerCase()) ||
          (u.display_name || '').toLowerCase().includes(mentionQuery.toLowerCase()))
        .slice(0, 5)

  const syncMentionState = (text: string, caret: number) => {
    const match = ACTIVE_MENTION.exec(text.slice(0, caret))
    setMentionQuery(match ? match[1] : null)
    setHighlighted(0)
  }

  const pendingCaret = useRef<number | null>(null)

  const insertMention = (username: string) => {
    const el = textareaRef.current
    const caret = el ? el.selectionStart : body.length
    const before = body.slice(0, caret).replace(ACTIVE_MENTION, m =>
      m.startsWith('@') ? `@${username} ` : `${m[0]}@${username} `)
    const next = before + body.slice(caret)
    // Put the caret after the inserted mention in the SAME commit that renders
    // the new text (layout effect below). A requestAnimationFrame here ran one
    // frame late, so a keystroke typed right after picking a mention landed at
    // the end of the text and the caret then jumped back ("…@analyst efore Friday.b").
    pendingCaret.current = before.length
    setBody(next)
    setMentionQuery(null)
  }

  useLayoutEffect(() => {
    const el = textareaRef.current
    if (pendingCaret.current == null || !el) return
    el.focus()
    el.setSelectionRange(pendingCaret.current, pendingCaret.current)
    pendingCaret.current = null
  }, [body])

  const submit = () => {
    const text = body.trim()
    if (!text || postMut.isPending) return
    postMut.mutate(text)
  }

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (suggestions.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setHighlighted(h => (h + 1) % suggestions.length)
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setHighlighted(h => (h - 1 + suggestions.length) % suggestions.length)
        return
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault()
        insertMention(suggestions[highlighted]?.username ?? suggestions[0].username)
        return
      }
      if (e.key === 'Escape') {
        setMentionQuery(null)
        return
      }
    }
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault()
      submit()
    }
  }

  const canPost = useCan('post:comment')

  const canDelete = (c: CommentItem) =>
    !!currentUser && (currentUser.role === 'admin' || c.author_id === currentUser.id)

  return (
    <section className="border-t border-[var(--border)] pt-4">
      <div className="flex items-center gap-2 mb-3">
        <MessageSquare size={14} className="text-[var(--text-secondary)]" />
        <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
          Comments
        </div>
        {comments.length > 0 && (
          <div className="text-[11px] text-[var(--text-secondary)]">· {comments.length}</div>
        )}
      </div>

      {isLoading ? (
        <div className="space-y-2">
          <SkeletonBar className="h-3 w-full" />
          <SkeletonBar className="h-3 w-2/3" />
        </div>
      ) : comments.length === 0 ? (
        <p className="text-[11px] text-[var(--text-secondary)]">
          {canPost ? 'No comments yet — start the discussion. Use @username to notify a teammate.' : 'No comments yet.'}
        </p>
      ) : (
        <ol className="space-y-3">
          {comments.map(c => (
            <li key={c.id} className="text-sm">
              <div className="flex items-baseline gap-2">
                <span className="flex items-center gap-1 text-[11px] font-medium text-[var(--text-primary)]">
                  <UserIcon size={10} className="text-[var(--text-secondary)]" />
                  {c.author_name}
                </span>
                <span className="text-[11px] text-[var(--text-secondary)]">
                  {formatRelative(c.created_at)}
                </span>
                {canDelete(c) && (
                  <button
                    onClick={() => deleteMut.mutate(c.id)}
                    disabled={deleteMut.isPending}
                    className="ml-auto text-[var(--text-secondary)] hover:text-[var(--danger)]"
                    title="Delete comment"
                    aria-label={`Delete comment by ${c.author_name}`}
                  >
                    <Trash2 size={12} />
                  </button>
                )}
              </div>
              <div className="mt-0.5 pl-3 border-l-2 border-[var(--border)]">
                <CommentBody body={c.body} />
              </div>
            </li>
          ))}
        </ol>
      )}

      {canPost && <div className="relative mt-3">
        <textarea
          ref={textareaRef}
          value={body}
          rows={2}
          maxLength={5000}
          placeholder="Add a comment… use @username to mention a teammate"
          onChange={e => {
            setBody(e.target.value)
            syncMentionState(e.target.value, e.target.selectionStart)
          }}
          onKeyDown={onKeyDown}
          onBlur={() => setTimeout(() => setMentionQuery(null), 150)}
          className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 text-[var(--text-primary)] placeholder:text-[var(--text-secondary)]"
        />
        {suggestions.length > 0 && (
          <ul
            className="absolute left-0 bottom-full mb-1 w-64 max-w-full border border-[var(--border)] bg-[var(--bg-secondary)] shadow-lg z-20"
            role="listbox"
            aria-label="Mention a teammate"
          >
            {suggestions.map((u, i) => (
              <li key={u.id} role="option" aria-selected={i === highlighted}>
                <button
                  type="button"
                  onMouseDown={e => { e.preventDefault(); insertMention(u.username) }}
                  onMouseEnter={() => setHighlighted(i)}
                  className={`w-full text-left px-2 py-1.5 text-xs flex items-baseline gap-2 ${
                    i === highlighted ? 'bg-[var(--bg-tertiary)]' : ''
                  }`}
                >
                  <span className="text-[var(--accent)] font-mono">@{u.username}</span>
                  <span className="text-[var(--text-secondary)] truncate">{u.display_name}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        <div className="flex justify-end mt-1.5">
          <button
            onClick={submit}
            disabled={!body.trim() || postMut.isPending}
            className="px-3 py-1.5 text-xs bg-[var(--accent)] text-white disabled:opacity-50"
          >
            {postMut.isPending ? 'Posting…' : 'Comment'}
          </button>
        </div>
      </div>}
    </section>
  )
}
