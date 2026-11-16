import { scoreGroups } from './check-score.mjs';

export function summarize(report) {
  const groups = scoreGroups(report);
  const below = Object.values(groups).some(result => result.detected * 100 < result.total * 90);
  const survivors = [];
  for (const [file, entry] of Object.entries(report.files)) {
    for (const mutant of entry.mutants) {
      if (['Survived', 'NoCoverage'].includes(mutant.status)) survivors.push({ file, ...mutant });
    }
  }
  return { below, groups, survivors };
}
export function issueBody(summary, runUrl) {
  const lines = ['Mutation score below 90', '', `Run and complete JSON/HTML reports: ${runUrl}`, '',
    ...Object.entries(summary.groups).map(([name, result]) => `${name}: ${result.detected}/${result.total} detected (${result.score.toFixed(2)}%).`), '', 'Surviving / uncovered mutants:', ''];
  let body = lines.join('\n');
  for (const mutant of summary.survivors) {
    const row = '\n    ' + JSON.stringify({ file: mutant.file, location: mutant.location, status: mutant.status, mutator: mutant.mutatorName, replacement: mutant.replacement });
    if (body.length + row.length > 58000) return body + '\n\nList truncated for GitHub’s issue limit; the linked run artifact contains every mutant.\n';
    body += row;
  }
  return body + '\n';
}
