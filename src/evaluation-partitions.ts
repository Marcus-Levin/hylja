/** Public planning family IDs only. Blind payloads, labels, answers and seeds never belong in Git. */
export const DEVELOPMENT_FAMILY_IDS = [
  'D01', 'D02', 'D03', 'D04', 'D05', 'D06', 'D07', 'D08', 'D09', 'D10', 'D11', 'D12',
] as const;
export const HELD_OUT_FAMILY_IDS = ['H01', 'H02', 'H03', 'H04'] as const;
