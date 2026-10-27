import { useEffect, useRef } from 'react'

interface Props {
  checked: boolean
  indeterminate?: boolean
  onChange: (checked: boolean) => void
  ariaLabel: string
  onClick?: (e: React.MouseEvent<HTMLInputElement>) => void
}

export function BulkSelectCheckbox({
  checked,
  indeterminate = false,
  onChange,
  ariaLabel,
  onClick,
}: Props) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate
  }, [indeterminate])
  return (
    <input
      ref={ref}
      type="checkbox"
      aria-label={ariaLabel}
      checked={checked}
      onChange={(e) => onChange(e.target.checked)}
      onClick={onClick ?? ((e) => e.stopPropagation())}
      className="accent-[var(--accent)] cursor-pointer"
    />
  )
}
