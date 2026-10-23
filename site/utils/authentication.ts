import type { ClientID, DistributionView, TargetAuthentication } from '../types/registry.ts'

export interface AuthenticationIndicator {
  state: TargetAuthentication
  label: string
  detail: string
}

/** Read the resolved release's target policy; product-wide legacy hints are not authority here. */
export function authenticationIndicator(
  distribution: Pick<DistributionView, 'id' | 'release_sequence' | 'targets'> | undefined,
  selectedClients: readonly ClientID[],
  autoDetect: boolean,
): AuthenticationIndicator {
  if (autoDetect) return {
    state: 'unknown',
    label: 'Authentication requirements unknown',
    detail: 'Installed agents are detected when you run the command. Select agents in Install to see the requirements for their resolved distribution and release.',
  }
  if (!distribution || !selectedClients.length) return {
    state: 'unknown',
    label: 'Authentication requirements unknown',
    detail: 'No install candidate is resolved for these agents. Select a supported agent to check its requirements.',
  }
  const values = selectedClients.map(client => ({ client, authentication: distribution.targets.find(target => target.client === client)?.authentication ?? 'unknown' }))
  const states = new Set(values.map(value => value.authentication))
  const state = states.size === 1 ? values[0]!.authentication : 'unknown'
  const label = states.size > 1 ? 'Authentication varies by agent'
    : state === 'required' ? 'Authentication required'
      : state === 'not_required' ? 'No authentication required' : 'Authentication requirements unknown'
  const description = (value: TargetAuthentication) => value === 'required' ? 'authentication required'
    : value === 'not_required' ? 'no authentication required' : 'requirements unknown'
  return {
    state,
    label,
    detail: `${distribution.id}${distribution.release_sequence === undefined ? '' : ` · release ${distribution.release_sequence}`}. ${values.map(value => `${value.client}: ${description(value.authentication)}`).join('; ')}. ${state === 'required' ? 'The package may require an account, token, or sign-in; this does not specify OAuth or confirm that you are signed in.' : state === 'not_required' ? 'No authentication is declared for these agents. Service limits and other setup requirements may still apply.' : 'Check the package requirements before connecting.'}`,
  }
}
