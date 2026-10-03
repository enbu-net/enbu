'use client'
import { ark } from '@ark-ui/react/factory'
import { Popover } from '@ark-ui/react/popover'
import type { ComponentProps } from 'react'
import { createSlotRecipeContext, styled } from 'styled-system/jsx'
import { popover } from 'styled-system/recipes'
import type { PopoverSlot } from 'styled-system/recipes'

const { withRootProvider, withContext } = createSlotRecipeContext(popover)

export type RootProps = ComponentProps<typeof Root>
export const Root = withRootProvider(Popover.Root, {
  defaultProps: { unmountOnExit: true, lazyMount: true },
})
export const RootProvider = withRootProvider(Popover.Root, {
  defaultProps: { unmountOnExit: true, lazyMount: true },
})
export const Anchor = withContext(Popover.Anchor, 'anchor')
export const ArrowTip = withContext(Popover.ArrowTip, 'arrowTip')
export const Arrow = withContext(Popover.Arrow, 'arrow', {
  defaultProps: { children: <ArrowTip /> },
})
export const CloseTrigger = withContext(Popover.CloseTrigger, 'closeTrigger')
export const Content = withContext(Popover.Content, 'content')
export const Description = withContext(Popover.Description, 'description')
export const Indicator = withContext(Popover.Indicator, 'indicator' as PopoverSlot)
export const Positioner = withContext(Popover.Positioner, 'positioner')
export const Title = withContext(Popover.Title, 'title')
export const Trigger = withContext(Popover.Trigger, 'trigger')

export const Body = styled(ark.div, { base: { p: '4' } })
export const Header = styled(ark.div, { base: { pb: '2', fontWeight: 'semibold' } })
export const Footer = styled(ark.div, { base: { pt: '2' } })

export { PopoverContext as Context } from '@ark-ui/react/popover'
