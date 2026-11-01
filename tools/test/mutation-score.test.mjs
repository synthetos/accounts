import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkScores } from '../mutation/check-score.mjs';

function report(workerStatuses) {
  return {files:{
    'packages/auth-core/src/example.ts':{mutants:[{status:'Killed'}]},
    'packages/idp/src/example.ts':{mutants:[{status:'Timeout'}]},
    'workers/accounts/src/example.ts':{mutants:workerStatuses.map(status=>({status}))},
  }};
}
test('each identity package must independently meet 90%, without rounding or hiding uncovered mutants',()=>{
  assert.equal(checkScores(report([...Array(9).fill('Killed'),'Survived'])).Worker.score,90);
  assert.throws(()=>checkScores(report([...Array(8).fill('Killed'),'Survived','NoCoverage'])),/Worker/);
  assert.throws(()=>checkScores(report([...Array(899).fill('Killed'),...Array(101).fill('Survived')])),/Worker/);
  assert.throws(()=>checkScores(report([])),/Worker/);
  const missing=report(['Killed']);delete missing.files['packages/idp/src/example.ts'];
  assert.throws(()=>checkScores(missing),/idp/);
  for(const status of ['CompileError','RuntimeError','Ignored','Pending','unrecognized'])assert.throws(()=>checkScores(report([status])),/Unresolved/);
  const unexpected=report(['Killed']);unexpected.files['tools/helper.ts']={mutants:[{status:'Killed'}]};
  assert.throws(()=>checkScores(unexpected),/Unexpected/);
});
