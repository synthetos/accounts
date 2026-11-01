import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/** Keep a strong package from hiding a regression in another identity boundary. */
export function checkScores(report) {
  const groups=Object.fromEntries(['auth-core','idp','Worker'].map(name=>[name,{detected:0,total:0}]));
  for(const [file,entry] of Object.entries(report.files)) {
    const name=file.startsWith('packages/auth-core/src/')?'auth-core':file.startsWith('packages/idp/src/')?'idp':file.startsWith('workers/accounts/src/')?'Worker':undefined;
    if(!name)throw new Error('Unexpected mutation source: '+file);
    for(const mutant of entry.mutants) {
      if(!['Killed','Timeout','Survived','NoCoverage'].includes(mutant.status))throw new Error('Unresolved mutation status: '+mutant.status);
      groups[name].total++;
      if(mutant.status==='Killed'||mutant.status==='Timeout')groups[name].detected++;
    }
  }
  for(const [name,result] of Object.entries(groups)) {
    if(result.total===0||result.detected*100<result.total*90)throw new Error(name+' mutation score is below 90% or has no mutants');
  }
  return Object.fromEntries(Object.entries(groups).map(([name,result])=>[name,{...result,score:100*result.detected/result.total}]));
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  console.log(JSON.stringify(checkScores(JSON.parse(readFileSync('reports/release-mutation.json','utf8'))),null,2));
}
