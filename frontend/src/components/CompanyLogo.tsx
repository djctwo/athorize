import { useEffect, useState } from 'react'

/**
 * The active company's logo, rendered from the server-validated PNG/JPEG data
 * URI carried on /auth/me (Organization.settings.branding). Renders nothing
 * when the company has no logo — or if the image fails to load — so callers
 * keep a clean text-only fallback.
 */
export default function CompanyLogo({
  src,
  name,
  className = '',
}: {
  src: string | null | undefined
  name?: string | null
  className?: string
}) {
  const [broken, setBroken] = useState(false)
  useEffect(() => setBroken(false), [src])

  if (!src || broken) return null
  return (
    <img
      src={src}
      alt={name ? `${name} logo` : 'Company logo'}
      className={`object-contain ${className}`}
      onError={() => setBroken(true)}
    />
  )
}
