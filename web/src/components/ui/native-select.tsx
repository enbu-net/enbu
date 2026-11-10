import { type ComponentProps } from 'react'
import { css } from 'styled-system/css'

const selectClass = css({
  appearance: 'none',
  h: '8',
  borderWidth: '1px',
  borderColor: 'border.strong',
  borderRadius: 'md',
  px: '3',
  fontSize: 'sm',
  bg: 'bg.surface',
  color: 'fg.default',
  outline: 'none',
  cursor: 'pointer',
  _focus: { borderColor: 'colorPalette.8', outlineWidth: '1px', outlineColor: 'colorPalette.8' },
  _hover: { borderColor: 'fg.muted' },
})

export type NativeSelectProps = ComponentProps<'select'>

export const NativeSelect = ({ className, ...props }: NativeSelectProps) => (
  <select className={`${selectClass}${className ? ` ${className}` : ''}`} {...props} />
)
