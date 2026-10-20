/**
 * OFFLINE SYNTHETIC ONLY: route verified Ed25519 proof arguments through
 * PostgreSQL's authenticated receiver SESSION_USER guard, not old bypass.
 * No network endpoint, production credential, paid model or authorization.
 */
import {submitSignedShadowProposalSyntheticOnly}
  from './openrouter-shadow-signed-admission-synthetic-only.mjs';

const OLD='SELECT * FROM reviewer_b_shadow.propose_exposure_with_challenge($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)';
const GUARDED='SELECT * FROM reviewer_b_shadow.propose_exposure_authenticated_receiver($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)';
const denial=reason=>Object.freeze({
  ok:false,reason,recorded:false,syntheticOnly:true,
  maySpend:false,mayReserve:false,mayMerge:false,mayPublish:false,
  providerBillingAuthenticated:false,
  protectedServiceAuthenticationDeployed:false,
});
export async function submitViaProtectedReceiverSyntheticOnly(options={}){
  if(process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY!=='1')
    return denial('SHADOW_RECEIVER_SYNTHETIC_SWITCH_REQUIRED');
  if(!options||typeof options!=='object'||Array.isArray(options)||
     typeof options.db?.query!=='function')
    return denial('SHADOW_RECEIVER_TEST_CONNECTION_MISSING');
  // Not authentication! A caller-provided callback can fake a DB success.
  // This function exists solely for ephemeral CI tests using an actual
  // independently password-authenticated PostgreSQL connection.
  const authenticatedFunctionOnly={
    query:async(sql,values)=>{
      if(sql!==OLD||!Array.isArray(values)||values.length!==11)
        throw Error('SHADOW_RECEIVER_OLD_ROUTE_FORBIDDEN');
      return options.db.query(GUARDED,values);
    },
  };
  return submitSignedShadowProposalSyntheticOnly({
    ...options,db:authenticatedFunctionOnly,
  });
}
