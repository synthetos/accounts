/** Shared authorization vocabulary returned to relying parties with every session check. */
export const ROLES = ['member', 'tester', 'moderator', 'admin'] as const;
export type Role = typeof ROLES[number];
export type Capability = 'run.connect';
const CAPABILITIES: Record<Role, readonly Capability[]> = {
  member: [], tester: ['run.connect'], moderator: ['run.connect'], admin: ['run.connect'],
};
export function isRole(value: string): value is Role { return ROLES.some(role => role === value); }
export function capabilities(role: Role): Capability[] { return [...CAPABILITIES[role]]; }
