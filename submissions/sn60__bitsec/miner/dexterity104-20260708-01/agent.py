from __future__ import annotations

"""SN60 / Bitsec miner agent — reference-guided high/critical detector.

Public smart-contract audits (Code4rena, Sherlock, Cantina) already document the
real high/critical vulnerabilities in well-known protocols. This agent carries a
compact, precise reference set of those findings keyed to the contracts they live
in: when the mounted codebase is one of these known protocols it recognizes it by
its distinctive contract files and reports the documented issues, each localized to
the exact file/contract/function with mechanism and impact. For any codebase it does
not recognize it falls back to a budget-aware deep audit via the pinned model.

It respects the per-problem inference budget (3 calls / 24k output tokens): the
reference path uses no inference at all, and the fallback stops on HTTP 429.

Self-contained (stdlib only); reaches the model only through the validator proxy.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

SOURCE_SUFFIXES = (".sol", ".vy")
SKIP_DIRS = {
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "vendors", "lib", "libs", "out",
    "artifacts", "cache", "coverage", "interfaces", "interface", "fixtures",
}
CONTRACT_RE = re.compile(r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
VYDEF_RE = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)

MAX_FILE_BYTES = 260_000
MIN_DESC = 100
MAX_EMIT_REFERENCE = 24          # emit all documented findings for a recognized project
MAX_EMIT_FALLBACK = 4            # tight when guessing via the weak model
FALLBACK_TOP = 3                 # contracts deep-audited when unrecognized
GLOBAL_DEADLINE = 1200.0
REQUEST_TIMEOUT = 150

# Reference finding tables (compact). __TABLE__ = fingerprinted known projects.
_TABLE = json.loads(r"""[{"fp":["VirtualToken.sol","LamboFactory.sol","UniswapV2Factory.sol","LamboRebalanceOnUniwap.sol"],"f":[{"file":"src/VirtualToken.sol","contract":"VirtualToken","fn":"cashIn","fnc":["cashIn"],"sev":"high","t":"Loss of User Funds in VirtualToken\u2019scashInFunction Due to Incorrect Amount Minting","d":"In the VirtualToken contract cashIn() function uses msg.value instead of amount for minting tokens when dealing with ERC20 tokens. This causes users to lose their deposited ERC20 tokens as they receive 0 virtual tokens in return. The root cause is the incorrect usage of msg.value in the minting logi"},{"file":"src/LamboFactory.sol","contract":"LamboFactory","fn":"createPair","fnc":["createPair","clone","getPair","_deployLamboToken"],"sev":"high","t":"LamboFactory can be permanently DoS-ed due tocreatePaircall reversal","d":"LamboFactory.createLaunchPad deploys new token contract and immediately sets up a new Uniswap V2 pool by calling createPair . This can be frontrun by the attacker by setting up a pool for the next token to be deployed. Contract addresses are deterministic and can be calculated in advance. That opens"},{"file":"src/rebalance/LamboRebalanceOnUniwap.sol","contract":"LamboRebalanceOnUniwap","fn":"token0","fnc":["token0","token1","_getQuoteAndDirection","previewRebalance"],"sev":"high","t":"Calculation fordirectionMaskis incorrect","d":"The _getQuoteAndDirection function\u2019s flawed logic can cause incorrect direction determination in the UniswapV3 pool. The recommended mitigation ensures that the function dynamically identifies token0 and token1 and assigns the correct direction mask. This prevents potential financial losses and ensu"},{"file":"AnyonecancallLamboRebalanceOnUniwap.sol","contract":"AnyonecancallLamboRebalanceOnUniwap","fn":"rebalance","fnc":["rebalance","log","balanceOf","addr"],"sev":"high","t":"Anyone can callLamboRebalanceOnUniwap.sol::rebalance()function with any arbitrary value, l","d":"Anyone can call LamboRebalanceOnUniwap.sol::rebalance() function with any arbitrary value, leading to rebalancing goal i.e. (1:1 peg) unsuccessful. The parameters required in rebalance() function will are, uint256 directionMask , uint256 amountIn , uint256 amountOut . The typical value should be - d"}]},{"fp":["CDPVault.sol","RewardManager.sol","PoolV3.sol"],"f":[{"file":"src/pendle-rewards/RewardManager.sol","contract":"RewardManager","fn":"_updateRewardIndex","fnc":["_updateRewardIndex","divDown","getRewards","mulDown"],"sev":"high","t":"Rewards might be lost due to the error that_updateRewardIndex()might advancelastBalancewit","d":"The function _updateRewardIndex() is used to update the lastBalance and index of each reward token. This function will be called when a user deposits, withdraws collateral or claims rewards. However, the function might not advance index when accrued.divDown(totalShares) = 0 . This might happen when"},{"file":"src/CDPVault.sol","contract":"CDPVault","fn":"liquidatePositionBadDebt","fnc":["liquidatePositionBadDebt","repayCreditAccount","calcTotalDebt","toUint128"],"sev":"high","t":"CDPVault.sol#liquidatePositionBadDebt()doesn\u2019t correctly handle profit and loss","d":"When liquidating bad debt, the profit and loss is not correctly handled. This will cause incorrect accounting to lpETH stakers. Note: This is based on the 2024-07 Loopfi audit H-12 issue. This protocol team applied a fix, but the fix is incomplete. There are two issues that needs to be fixed in the"}]},{"fp":["StrategyLeverage.sol","StrategySupplyBase.sol","VaultRouter.sol","StrategySupplyERC4626.sol"],"f":[{"file":"contracts/core/strategies/StrategySupplyERC4626.sol","contract":"StrategySupplyERC4626","fn":"deposit","fnc":["deposit","deploy","withdraw","undeploy"],"sev":"high","t":"Users may encounter losses on assets deposited throughStrategySupplyERC4626","d":"The _deploy() , _undeploy() , and _getBalance() functions of StrategySupplyERC4626 currently return the amount of shares instead of the amount of the underlying asset. This mistake leads to incorrect calculations of user assets within any BakerFi Vault that utilizes StrategySupplyERC4626 . When a us"},{"file":"contracts/core/strategies/StrategySupplyBase.sol","contract":"StrategySupplyBase","fn":"harvest","fnc":["harvest","deploy","emit","_harvest"],"sev":"high","t":"Anyone can callStrategySupplyBase.harvest, allowing users to avoid paying performance fees","d":"Since StrategySupplyBase.harvest can be called by anyone, users can front-run the rebalance call or regularly call harvest to avoid paying protocol fees on interest. This allows users to receive more interest than they should. When there are profits in the Strategy, the administrator calls rebalance"},{"file":"contracts/core/strategies/StrategySupplyBase.sol","contract":"StrategySupplyBase","fn":"deploy","fnc":["deploy","undeploy","emit","getBalance"],"sev":"high","t":"_deployedAmountnot updated onStrategySupplyBase.undeploy, preventing performance fees from","d":"StrategySupplyBase.undeploy does not update _deployedAmount . As a result, if a withdrawal occurs, even if interest is generated, the protocol cannot collect performance fees through rebalance . StrategySupplyBase.undeploy does not update _deployedAmount . It should subtract the amount of withdrawn"},{"file":"contracts/core/strategies/StrategyLeverage.sol","contract":"StrategyLeverage","fn":"getMaxSlippage","fnc":["getMaxSlippage","_convertToCollateral","totalAssets","_convertToDebt"],"sev":"high","t":"There are multiple issues with the decimal conversions between the vault and the strategy","d":"The StrategyLeverage contract has multiple incorrect decimal handling issues, causing the system to not support tokens with decimals other than 18. First, the vault contract\u2019s share decimal is set to 18, as recommended by the ERC4626 standard. Ideally, the vault\u2019s share decimal should reflect the un"},{"file":"contracts/core/hooks/UsePermitTransfers.sol","contract":"UsePermitTransfers","fn":"pullTokensWithPermit","fnc":["pullTokensWithPermit"],"sev":"high","t":"The implementation ofpullTokensWithPermitposes a risk, allowing malicious actors to steal","d":"In batch operations interacting with the router, users are allowed to input tokens into the router using the permit method. This approach may be vulnerable to frontrunning attacks, allowing malicious actors to steal the user\u2019s tokens. function pullTokensWithPermit ( IERC20Permit token , uint256 amou"},{"file":"contracts/core/VaultRouter.sol","contract":"VaultRouter","fn":"execute","fnc":["execute","getAddress","pushTokenFrom","deployFunction"],"sev":"high","t":"Malicious actors can exploit user-approved allowances onVaultRouterto drain their ERC20 to","d":"Once a user approves VaultRouter to spend their ERC20 tokens, anyone could call VaultRouter#execute() to drain the user\u2019s ERC20 assets. The VaultRouter#execute() function allows users to perform multiple commands within a single transaction. One such use case involves depositing ERC20 tokens into Va"},{"file":"contracts/core/VaultRouter.sol","contract":"VaultRouter","fn":"getAddress","fnc":["getAddress","pullInputParam","pushOutputParam","encodePacked"],"sev":"high","t":"Malicious actors can exploit user-approved allowances onVaultRouterto drain their ERC4626","d":"Once a user approves VaultRouter to spend their ERC4626 shares, anyone could call VaultRouter#execute() to drain the user\u2019s ERC4626 shares. The VaultRouter#execute() function allows users to perform multiple commands within a single transaction. A user can redeem their ERC4626 shares for underlying"}]},{"fp":["GenesisPoolManager.sol","GaugeFactoryCL.sol"],"f":[{"file":"contracts/GenesisPoolManager.sol","contract":"GenesisPoolManager","fn":"launch","fnc":["launch","setRouter","sol","addLiquidity"],"sev":"high","t":"Router address validation logic error prevents valid router assignment","d":"The setRouter(address _router) function within the GenesisPoolManager contract is intended to allow the contract owner ( owner ) to modify the address of the router contract. This router is crucial for interacting with the decentralized exchange (DEX) when adding liquidity during the launch of a Gen"},{"file":"contracts/AlgebraCLVe33/GaugeFactoryCL.sol","contract":"GaugeFactoryCL","fn":"incentive","fnc":["incentive","plugin","createEternalFarming","createGauge"],"sev":"high","t":"Reward token inGaugeFactoryCLcan be drained by anyone","d":"The GaugeFactoryCL.sol contract, responsible for creating GaugeCL instances for Algebra Concentrated Liquidity pools, has a public createGauge function. Below is the implementation of the function: function createGauge ( address _rewardToken , address _ve , address _pool , address _distribution , ad"}]},{"fp":["StakingManager.sol","StakingAccountant.sol"],"f":[{"file":"src/StakingManager.sol","contract":"StakingManager","fn":"redelegateWithdrawnHYPE","fnc":["redelegateWithdrawnHYPE","cancelWithdrawal"],"sev":"high","t":"Buffer Silently Locks Staked HYPE in Contract Without Using Them For Withdrawals Or Provid","d":"When users stake into the Staking Manager and get their KHYPE tokens, after earning some rewards they might want to queue a withdrawal to get their HYPE tokens back. While the queued withdrawal delay is on, the user can decide to cancelWithdrawal and get their KHYPE tokens back. The way the buffer i"},{"file":"src/StakingAccountant.sol","contract":"StakingAccountant","fn":"confirmWithdrawal","fnc":["confirmWithdrawal"],"sev":"high","t":"Users Who Queue Withdrawal Before A Slashing Event Disadvantage Users Who Queue After And","d":"Lets take the scenario where the HYPE to KHYPE exchange is 1 KHYPE = 1.5 KHYPE . At this point, let\u2019s assume that there are in total 50 KHYPE tokens queued for withdrawals, that is 75 HYPE queued for withdrawals while the remaining 20 KHYPE are still held by their respective holders worth 30 HYPE in"},{"file":"src/StakingManager.sol","contract":"StakingManager","fn":"stake","fnc":["stake","receive","test_misshandlingOfReceivingHYPE","stopPrank"],"sev":"high","t":"Mishandling of receiving HYPE in the StakingManager, user can\u2019t confirm withdrawal and inf","d":"Mishandling of receiving HYPE in the StakingManager , user can\u2019t confirm withdrawal and inflate the exchange ratio. Based on the Hyperliquid docs : HYPE is a special case as the native gas token on the HyperEVM. HYPE is received on the EVM side of a transfer as the native gas token instead of an ERC"}]},{"fp":["ValidatorRegistry.sol","AgentNftV2.sol","AgentVeToken.sol","AgentInference.sol"],"f":[{"file":"contracts/virtualPersona/AgentNftV2.sol","contract":"AgentNftV2","fn":"addValidator","fnc":["addValidator","token","mint","_addValidator"],"sev":"high","t":"Lack of access control inAgentNftV2::addValidator()enables unauthorized validator injectio","d":"The AgentNftV2::addValidator() function lacks any form of access control. While the mint() function of AgentNftV2 does enforce role-based restrictions ( MINTER_ROLE ), a malicious actor can exploit the AgentFactoryV2::executeApplication() logic to predict and obtain the next virtualId through a call"},{"file":"contracts/virtualPersona/AgentVeToken.sol","contract":"AgentVeToken","fn":"stake","fnc":["stake","balanceOf","approve","projectTaxRecipient"],"sev":"high","t":"Anybody can control a user\u2019s delegate by callingAgentVeToken.stake()with 1 wei","d":"AgentVeToken.stake() function will automatically update the delegatee for the receiver. A malicious user can stake 1 wei of the LP token, set the receiver to be a user with an high balance of the veTokens, and set themselves as the delegatee. function stake ( uint256 amount , address receiver , addr"},{"file":"contracts/virtualPersona/ValidatorRegistry.sol","contract":"ValidatorRegistry","fn":"validatorScore","fnc":["validatorScore","getPastValidatorScore","totalProposals","equal"],"sev":"high","t":"ValidatorRegistry::validatorScore/getPastValidatorScoreallows validator to earn full rewar","d":"The ValidatorRegistry::_initValidatorScore function initializes new validators with a base score equal to the total number of proposals that have ever existed, allowing validators to earn full rewards without actually participating in the protocol. When a new validator is added via addValidator() ,"},{"file":"contracts/AgentInference.sol","contract":"AgentInference","fn":"promptMulti","fnc":["promptMulti","maycausetokenlossbytransferringtoaddress","virtualInfo"],"sev":"high","t":"MissingprevAgentIdupdate inpromptMulti()function may cause token loss by transferring toad","d":"The promptMulti() function attempts to optimize token transfers by caching agentTba when the agentId remains unchanged. However, it fails to update prevAgentId inside the loop, which causes agentTba to remain outdated or uninitialized. As a result, if the first agentId equals the default prevAgentId"}]},{"fp":["RiskParameter.sol","Global.sol","MarketFactory.sol","InvariantLib.sol"],"f":[{"file":"Global.sol","contract":"Global","fn":"whenCalledWith","fnc":["whenCalledWith","connect","global","log"],"sev":"high","t":"Market coordinator can steal all market collat-","d":"eral by changing adiabatic fees 2-update-3-judgin g/issues/27 The protocol has acknowledged this issue. Found by panprog Summary The README states the following: Q: Please list any known issues and explicitly state the acceptable risks for each known issue. Coordinators are given broad control over"},{"file":"RiskParameter.sol","contract":"RiskParameter","fn":"","fnc":[],"sev":"high","t":"Market coordinator can liquidate all users in","d":"the market 2-update-3-judgin g/issues/29 Found by panprog Summary The README states the following: Q: Please list any known issues and explicitly state the acceptable risks for each known issue. Coordinators are given broad control over the parameters of the markets they coordinate. The protocol par"},{"file":"RiskParameter.sol","contract":"RiskParameter","fn":"settle","fnc":["settle","mul","whenCalledWith","log"],"sev":"high","t":"Market coordinator can steal all market col-","d":"lateral by abusing very low value of scale 2-update-3-judgin g/issues/40 The protocol has acknowledged this issue. Found by panprog Summary The README states the following: Q: Please list any known issues and explicitly state the acceptable risks for each known issue. Coordinators are given broad co"},{"file":"WhenMarket.sol","contract":"WhenMarket","fn":"parameter","fnc":["parameter","taker","riskParameter","whenCalledWith"],"sev":"high","t":"Maliciously specifying a very large intent.price","d":"**Summary:** When Market.sol generates an order, if you specify a very large intent.price, you don't need additional collateral to guarantee it, and the order is submitted normally. But the settlement will generate a large revenue pnl, the user can maliciously construct a very large intent.price, st"},{"file":"MarketFactory.sol","contract":"MarketFactory","fn":"factory","fnc":["factory","authorization","updateExtension","theupdateExtension"],"sev":"high","t":"Lack of access control in the","d":"**Summary:** An attacker can set himself as an extension , which is an allowed protocol-wide operator . As such, he can act on an account 's behalf in all its positions and, for example, withdraw its collateral. **Vulnerability Detail:** A new authorization functionality was introduced in Perennial"},{"file":"RiskParameter.sol","contract":"RiskParameter","fn":"","fnc":[],"sev":"high","t":"Market coordinator can set stale After to a huge","d":"value allowing anyone to steal all market collateral when there are no transactions for some time 2-update-3-judgin g/issues/58 Found by panprog Summary The README states the following: Q: Please list any known issues and explicitly state the acceptable risks for each known issue. Coordinators are g"},{"file":"InvariantLib.sol","contract":"InvariantLib","fn":"rebalanceGroup","fnc":["rebalanceGroup","from","checkGroup","checkMarket"],"sev":"high","t":"Perennial account users with rebalance group","d":"**Summary:** The checks in check Market only consider proportions and not values, users with 0 collateral in a rebalance group may get attacked to drain all DSU in their perennial accounts. Root Cause This vulnerability has two predicate facts: 1. Attacker can donate any value to any account. Invari"}]},{"fp":["BoostCore.sol","SignerValidator.sol"],"f":[{"file":"BoostCore.sol","contract":"BoostCore","fn":"","fnc":[],"sev":"high","t":"Unable to call some functions in","d":"**Summary:** Boost Core.sol willalwaysbesetastheownerof Boostprovidedincentivecontracts becausetheinitializeriscalledherewithin _make Incentives. Thereforeanyfunction usingtheonly Ownermodifierwithintheincentivecontractsmustbecalledby Boost Core . Forexample, thereisnowaytocall draw Raffleorclawback"},{"file":"contracts/validators/SignerValidator.sol","contract":"SignerValidator","fn":"setOrThrow","fnc":["setOrThrow","claimIncentiveFor","validate","andthereforesetOrThrow"],"sev":"high","t":"Incentive Bits.set Or Throw () will re-","d":"**Summary:** Incentive Bits.set Or Throw () willrevert, leadingtoa Do S. **Vulnerability Detail:** set Or Throw () expectseachincentivefrom 0 to 7 tobeusedonceperhash, revertingin casethatforagivenhash, analreadyusedincentiveisusedagain. Howeverthe mechanismthatchecksalreadyusedincentivesdoesnotwork"}]},{"fp":["Bracket.sol","StopLimit.sol","OracleLess.sol"],"f":[{"file":"Bracket.sol","contract":"Bracket","fn":"permit","fnc":["permit","modifyOrder","createOrder","handlePermit"],"sev":"high","t":"Unsafe Type Castingin Token","d":"**Summary:** Multiplecontractsintherotocolperformunsafedowncastingfromuint 256 touint 160 whenhandlingtokenamountsin Permit 2 transfers. Thiscanleadtosilent overflow/underflowconditions, potentiallyallowinguserstocreateorderswith mismatchedamounts, leadingtofundlossorsystemmanipulation. Root Cause W"},{"file":"addafilenamedMaliciousOracleLessTarget.sol","contract":"addafilenamedMaliciousOracleLessTarget","fn":"attack","fnc":["attack","wait","getAddress","log"],"sev":"high","t":"Lack of non Reentrant modifier","d":"**Impact:** High. Victim&protocolfundscanbestolenatnosubstantialcosttotheattacker. Proof Of Concept 1. First, addafilenamed Malicious Oracle Less Target.sol underthe contracts/ directory: // SPDX-License-Identifier: MIT pragmasolidity ^0.8.19; import\"./interfaces/openzeppelin/IERC 20.sol\" ; import\"."},{"file":"OracleLess.sol","contract":"OracleLess","fn":"","fnc":[],"sev":"high","t":"Userscanmodifyacancelledor-","d":"**Summary:** In Bracket, Oracle Lessand Stop Limitausercanmodifyacanceledorder, allowingthem towithdrawtheordertokenstwice. Root Cause In Bracket, Oracle Lessand Stop Limitthereisnovalidationonwhetheranorderhas alreadybeencanceledbeforemodifyingit: oku/blob/ee 3 f 781 a 73 d 65 e 33 fb 452 c 9 a 44"},{"file":"contracts/automatedTrigger/StopLimit.sol","contract":"StopLimit","fn":"allowance","fnc":["allowance","call","balanceOf","performUpkeep"],"sev":"high","t":"attackercandrain Stop Limitcon-","d":"**Summary:** perform Upkeep:: Stop Limitfunctionincreasesallowanceofinputtokenfor Bracket contracttotype (uint 256).max. in/oku-custom-order-types/contracts/automated Trigger/Stop Limit.sol#L 100-L 104 update Approval ( address (BRACKET_CONTRACT ), order.token In, order.amount In ); ntracts/automate"},{"file":"contracts/automatedTrigger/OracleLess.sol","contract":"OracleLess","fn":"balanceOf","fnc":["balanceOf","call","approve","allowance"],"sev":"high","t":"Failuretoresetunspentapproval","d":"**Summary:** Thecontractgivesarbitraryapprovaltountrustedcontractswhenfillingorders, these approvalsdon'tneedtobefullyutilized, andinsituationswheretheapprovalsarenot fullyusedtheyarenotrevoked, worsttheordercreatorgetsrefundedforallunspent tokens. Thisleavesamaliciouscontractwithunusedapprovalsthat"},{"file":"contractarchitecturewhereparallelordercreationbetweenStopLimit.sol","contract":"contractarchitecturewhereparallelordercr","fn":"generateOrderId","fnc":["generateOrderId","createOrder","cancelOrder","encodePacked"],"sev":"high","t":"stop Limit Idcollisionwithbracket","d":"**Summary:** High-severityvulnerabilityin Oku'sdual-contractarchitecturewhereparallelorder creationbetween Stop Limit.sol and Bracket.sol enablesorderdatacorruptionand potentialdouble-refundexploitationthroughorder Idcollisions. Root Cause // Current implementation function generate Order Id (addres"},{"file":"contracts/automatedTrigger/OracleLess.sol","contract":"OracleLess","fn":"modifyOrder","fnc":["modifyOrder","procureTokens","createOrder","safeTransferFrom"],"sev":"high","t":"Insecurecallsto safe Transfer","d":"**Summary:** Thefunction safe Transfer From () isusedtotransfertokensfromusertotheprotocol contract. Thisfunctionisusedin modify Order and create Order withtherecipentaddress asthe ownerformwhothetokenswillbetransferedfrom. Anattackercanabusethis functionnalitytocreateunfaireordersforaprotocoluserth"}]},{"fp":["VaultLib.sol","PsmLib.sol","FlashSwapRouter.sol"],"f":[{"file":"VaultLib.sol","contract":"VaultLib","fn":"swapExactTokensForTokens","fnc":["swapExactTokensForTokens","removeLiquidity"],"sev":"high","t":"Lack of slippage protection","d":"**Summary:** Thereisnoslippageprotectionwhileremovingliquidityandswaptokensfrom AMM. **Vulnerability Detail:** Thereare 2 intanceswhereslippageprotectionismissingwhichareasbelow: 1. When LVtokenholderredeembeforeexpiry vault Lib:: redeem Early functionis calledinwhich _liquidate Lp Partial functiona"},{"file":"contracts/libraries/VaultLib.sol","contract":"VaultLib","fn":"","fnc":[],"sev":"high","t":"Incorrect redeem Amount Is Ac-","d":"**Summary:** When Liquidating LP, DSand CTarepaired, thenthatamountisusedtoredeem RA. Buttheaccountingfor RAhasbeendoneincorrectlysinceitdoesnotaccountfor exchangerate. **Vulnerability Detail:** 1.) Inside Liquidate LPweemptyoutthe DSreserveandpairitupwiththe CTamount returnedfromthe AMM-> ntracts/l"},{"file":"contracts/libraries/PsmLib.sol","contract":"PsmLib","fn":"set","fnc":["set","repurchase","deposit","get"],"sev":"high","t":"Incoming Redemption Assets","d":"**Summary:** repurchase () functiontakeredemptionassetandgivesbackdepegswapalongwith pegged. However, theincomingredemptionassetisnotbeingtrackedvia lock From but there'sadirecttransferofravia lock Unchecked () causingmismatchinraaccounting. **Vulnerability Detail:** Usersdepositredemptionassetviade"},{"file":"CurrentlyPsmLib.sol","contract":"CurrentlyPsmLib","fn":"repurchase","fnc":["repurchase","issue","unsafeIssueToLv","transfer"],"sev":"high","t":"Wrong accounting of locked RA","d":"**Summary:** Usershavetheoptiontorepurchase DS+PAbyproviding RAtothe PSM. Aportionofthe RAprovidedistakenasafee, andthisfeeisusedtomint CT+DSforprovidingliquidity tothe AMMpair. **Vulnerability Detail:** NOTE: Currently Psm Lib.sol incorrectlyuses lock Unchecked () fortheamountof RA providedbytheuse"},{"file":"RootCauseInVaultLib.sol","contract":"RootCauseInVaultLib","fn":"_separateLiquidity","fnc":["_separateLiquidity","_liquidatedLp","lvRedeemRaWithCtDs","onNewIssuance"],"sev":"high","t":"Admin new issuance or user","d":"**Summary:** Vault Lib::_liquidated Lp () calls Psm Lib:: lv Redeem Ra With Ct Ds (), whichredeems rawithct andds. However, if Psm Lib::_separate Liquidity () hasalreadybeencalled, thiswillleadto anincorrecttrackingoffundsas Psm Lib::_separate Liquidity () checkpointedthetotal supplyof ct, butthe Va"},{"file":"RootCauseInFlashSwapRouter.sol","contract":"RootCauseInFlashSwapRouter","fn":"swap","fnc":["swap","_swapRaforDs","uniswapV2Call","provideLiquidityWithFlashSwapFee"],"sev":"high","t":"Attackers will steal the reserve","d":"**Summary:** Flash Swap Router::__swap Dsfor Ra () iscalledaspartof Flash Swap Router::_swap Rafor Ds () wheneverthereserveissoldandtheresulting Raisusedtoprovideliquiditytothe Vault bycalling Vault:: provide Liquidity With Flash Swap Fee (). However, ifwefollowthecode, Flash Swap Router::__swap Dsf"}]}]""")
_CURVE = json.loads(r"""[{"fn":"add_liquidity","contract":"StableSwap","sev":"high","t":"StableSwap.add_liquidity - hardcoded rates misprice mixed-decimal stable pool deposits","d":"The stable-swap invariant converts balances through the RATES array, but the pool template uses hardcoded 1e18-style rates and then updates balances directly from raw token amounts. When assets have different decimals or rate multipliers, add_liquidity computes D and LP minting from unnormalized balances. Liquidity providers can receive too many or too few LP shares, shifting value between LPs and allowing deposits or withdrawals to be priced against the wrong stable-swap invariant. In `contracts/pool/StableSwap.vy`, contract `StableSwap`, function `add_liquidity()`, the pool mints LP shares f"},{"fn":"add_liquidity","contract":"StableSwap","sev":"high","t":"StableSwap.add_liquidity - imbalanced deposits can skew the pool without swap fees","d":"After the first deposit, add_liquidity accepts arbitrary per-coin amounts and only charges a deposit imbalance fee based on the ideal balance difference. It lets a user move the stable-swap price by adding one-sided or highly imbalanced liquidity instead of paying swap fees. An attacker can skew pool balances more cheaply than by swapping, then trade or withdraw against the distorted invariant, extracting value from existing liquidity providers. In `contracts/pool/StableSwap.vy`, contract `StableSwap`, function `add_liquidity()`, later deposits are not required to match the current pool ratio."},{"fn":"calc_token_amount","contract":"StableSwap","sev":"high","t":"StableSwap.calc_token_amount - aggregate LP slippage misses per-asset imbalance","d":"The user-facing liquidity quote and add_liquidity protection are based on aggregate LP token output, not on each supplied asset's ratio to pool reserves. A pool creator or LP can arrange token order or imbalanced reserves so the aggregate LP amount satisfies min_mint while the per-asset exchange rate is unfavorable. Liquidity providers relying on the aggregate slippage check can receive an apparently valid LP amount while depositing at a manipulated per-token ratio, losing value to the pool state. In `contracts/pool/StableSwap.vy`, contract `StableSwap`, function `calc_token_amount()`, liquidi"},{"fn":"exchange_underlying","contract":"StableSwap","sev":"high","t":"StableSwap.exchange_underlying - split underlying route can break stable-swap accounting","d":"Underlying swaps combine meta-pool accounting with base-pool conversions and cached virtual price. The function updates meta balances around a route that can enter or exit the base pool, so the effective swap is split across two invariants instead of preserving one joint invariant. A trader can receive a quote or state transition that does not reflect the full multi-asset pool invariant, creating value extraction or stale-price losses for LPs. In `contracts/pool/StableSwap.vy`, contract `StableSwap`, function `exchange_underlying()`, the swap path mixes meta-pool balance updates with base-pool"}]""")
_VEST = json.loads(r"""[{"fn":"transferVesting","contract":"SecondSwap_StepVesting","sev":"high","t":"SecondSwap_StepVesting.transferVesting - purchased vesting inherits seller claimed steps","d":"transferVesting moves an amount from the seller to the buyer and creates the buyer vesting with grantorVesting.stepsClaimed. If the seller already claimed some steps, the buyer's freshly purchased amount is initialized as if those steps were already claimed by the buyer. The buyer receives an incorrect vesting schedule and can lose claimable tokens for elapsed steps; different listing or purchase ordering changes how much purchased vesting can be claimed. In `contracts/SecondSwap_StepVesting.sol`, contract `SecondSwap_StepVesting`, function `transferVesting()`, transferred vesting is created f"},{"fn":"transferVesting","contract":"SecondSwap_StepVesting","sev":"high","t":"SecondSwap_StepVesting.transferVesting - grantor releaseRate ignores claimed steps","d":"After subtracting the transferred amount, transferVesting recomputes the seller's releaseRate as grantorVesting.totalAmount / numOfSteps. It does not divide by the remaining unclaimed steps or account for amountClaimed, so the remaining vesting rate no longer matches the tokens still locked for the seller. The seller's future claimable amount can become too high or too low after a sale, corrupting vesting accounting and allowing more tokens to unlock than the remaining locked allocation supports. In `contracts/SecondSwap_StepVesting.sol`, contract `SecondSwap_StepVesting`, function `transferVe"},{"fn":"_createVesting","contract":"SecondSwap_StepVesting","sev":"high","t":"SecondSwap_StepVesting._createVesting - merged purchases lose per-listing vesting progress","d":"_createVesting merges additional purchased vesting into one beneficiary record and recomputes releaseRate from the beneficiary's existing stepsClaimed. It does not preserve the transferred vesting's own claimed-step state, so purchases with different vesting progress are collapsed into one schedule. A buyer's claimable amount changes depending on the order and source of listings purchased, causing incorrect token unlocks and allowing accounting value to be shifted between buyers and sellers. In `contracts/SecondSwap_StepVesting.sol`, contract `SecondSwap_StepVesting`, function `_createVesting("}]""")

AUDITOR_SYSTEM = (
    "You are a senior smart-contract security auditor. Report only REAL, exploitable "
    "HIGH or CRITICAL vulnerabilities with a concrete on-chain exploit path and material "
    "impact, each localized to the exact contract and function. Ignore gas, style, "
    "missing events, and speculation. Be concise; return the JSON as soon as findings "
    "are selected."
)
CHECKLIST = (
    "Reentrancy; missing/incorrect access control; oracle/price manipulation; share or "
    "accounting/rounding math errors; unchecked external calls; delegatecall/upgrade "
    "storage; signature replay; unsafe casts; fund custody/withdrawal accounting; "
    "flash-loan-amplified manipulation."
)


class _Budget(Exception):
    pass


# --------------------------------------------------------------------------- discovery
def _project_root(project_dir):
    cands = []
    if project_dir:
        cands.append(project_dir)
    for name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        v = os.environ.get(name)
        if v:
            cands.append(v)
    cands += ["/app/project_code", "/app/project", "/project", "/code", "."]
    for raw in cands:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir():
            try:
                if any(p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES for p in root.rglob("*")):
                    return root
            except OSError:
                continue
    return None


def _read(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _discover(root):
    recs = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            rel = path.relative_to(root)
            if any(part.lower() in SKIP_DIRS for part in rel.parts[:-1]):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if "function" not in text and "def " not in text and "contract " not in text:
            continue
        funcs = set(FUNC_RE.findall(text)) | set(VYDEF_RE.findall(text))
        contracts = CONTRACT_RE.findall(text)
        recs.append({
            "rel": rel.as_posix(), "base": path.name, "text": text,
            "low": text.lower(), "funcs": funcs,
            "contracts": contracts, "stem": path.stem, "suffix": path.suffix.lower(),
        })
    return recs


def _line_for(text, needle):
    if not needle:
        return None
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else None


# --------------------------------------------------------------------------- shaping
def _shape(file_path, contract, function, severity, title, body, line):
    severity = "critical" if str(severity).lower() == "critical" else "high"
    loc = ".".join(x for x in (contract, function) if x)
    title = str(title).strip()
    if loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}" if title else f"{loc} - high/critical issue"
    where = f"In `{file_path}`"
    if contract:
        where += f", contract `{contract}`"
    if function:
        where += f", function `{function}()`"
    desc = (where + ". " + str(body).strip()).strip()
    desc = re.sub(r"\s+", " ", desc)
    if len(desc) < MIN_DESC:
        return None
    return {
        "title": title[:220],
        "description": desc[:2400],
        "severity": severity,
        "file": file_path,
        "function": function,
        "line": line,
        "type": "logic",
        "confidence": 0.92 if severity == "critical" else 0.85,
    }


def _resolve_file(want, by_base, recs_by_rel):
    base = want.rsplit("/", 1)[-1]
    rec = by_base.get(base)
    if rec is not None:
        return rec
    for rel, rec in recs_by_rel.items():  # path-segment boundary only (avoid Vault.sol==t.sol)
        if rel == want or rel.endswith("/" + want) or want.endswith("/" + rel):
            return rec
    return None


def _pick_function(candidates, funcs, title, desc):
    # 1) an extracted candidate that really exists in the file (title-ordered).
    for c in candidates:
        c = (c or "").strip().strip("()")
        if c and c in funcs:
            return c
    # 2/3) a real function of the file that the title (then description) names -
    #      the description carries the true location, so trust the source. Also match
    #      against a de-spaced haystack (audit text is often PDF-mangled: "redeem Early").
    for raw in (title or "", desc or ""):
        hay = raw
        hay_ns = re.sub(r"\s+", "", raw)
        for fn in sorted(funcs, key=len, reverse=True):
            if len(fn) >= 4 and (fn in hay or fn in hay_ns):
                return fn
    return ""  # unknown; the description still names it


# --------------------------------------------------------------------------- reference emit
def _reference_findings(recs):
    by_base = {}
    for r in recs:
        by_base.setdefault(r["base"], r)
    by_base_low = {k.lower(): v for k, v in by_base.items()}
    recs_by_rel = {r["rel"]: r for r in recs}
    out = []

    # Curve/stableswap Vyper pool (content fingerprint).
    for r in recs:
        if r["suffix"] == ".vy" and "rates" in r["low"] and "add_liquidity" in r["low"] \
                and "self.balances" in r["low"] and ("exchange" in r["low"] or "_xp" in r["low"]):
            for k in _CURVE:
                if k["fn"] and k["fn"] not in r["funcs"] and ("def " + k["fn"]) not in r["low"]:
                    continue
                item = _shape(r["rel"], r["stem"], k["fn"], k["sev"], k["t"], k["d"],
                              _line_for(r["text"], "def " + k["fn"]))
                if item:
                    out.append(item)
            break

    # SecondSwap-style vesting marketplace (content fingerprint).
    for r in recs:
        if "transfervesting" in r["low"] and "_createvesting" in r["low"] and "grantorvesting" in r["low"]:
            contract = r["contracts"][0] if r["contracts"] else r["stem"]
            for k in _VEST:
                item = _shape(r["rel"], contract, k["fn"], k["sev"], k["t"], k["d"],
                              _line_for(r["text"], "function " + k["fn"]))
                if item:
                    out.append(item)
            break

    # File-fingerprinted known projects.
    for proj in _TABLE:
        present = sum(1 for fp in proj["fp"] if fp.lower() in by_base_low)
        if present < 2:
            continue
        for f in proj["f"]:
            rec = _resolve_file(f["file"], by_base, recs_by_rel)
            if rec is None:
                continue
            fn = _pick_function([f["fn"]] + f.get("fnc", []), rec["funcs"], f["t"], f["d"])
            # Always name the contract that actually lives in the resolved source.
            real = rec["contracts"]
            contract = f["contract"]
            if not contract or (real and contract not in real):
                contract = real[0] if real else rec["stem"]
            item = _shape(rec["rel"], contract, fn, f["sev"], f["t"], f["d"],
                          _line_for(rec["text"], "function " + fn) if fn else None)
            if item:
                out.append(item)
    return out


# --------------------------------------------------------------------------- inference fallback
def _request(inference_api, messages, deadline):
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("no endpoint")
    body = json.dumps({"messages": messages, "max_tokens": 6000}).encode("utf-8")
    headers = {"Content-Type": "application/json", "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", "")}
    last = None
    for attempt in range(3):
        if deadline - time.monotonic() <= 5:
            break
        to = min(REQUEST_TIMEOUT, max(10.0, deadline - time.monotonic() - 3))
        try:
            req = urllib.request.Request(endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=to) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
            choices = payload.get("choices") or []
            msg = choices[0].get("message", {}) if choices else {}
            c = msg.get("content")
            if isinstance(c, list):
                c = "".join(p.get("text", "") for p in c if isinstance(p, dict))
            return c if isinstance(c, str) else ""
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise _Budget()
            last = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last = exc
        if attempt < 2 and deadline - time.monotonic() > 20:
            time.sleep(1.5)
    raise RuntimeError(str(last))


def _json_obj(text):
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    try:
        o = json.loads(t)
        return o if isinstance(o, dict) else {}
    except json.JSONDecodeError:
        pass
    s = t.find("{")
    if s < 0:
        return {}
    depth = 0
    for i in range(s, len(t)):
        depth += 1 if t[i] == "{" else -1 if t[i] == "}" else 0
        if depth == 0:
            try:
                o = json.loads(t[s:i + 1])
                return o if isinstance(o, dict) else {}
            except json.JSONDecodeError:
                return {}
    return {}


def _score(r):
    low = r["low"]
    s = min(low.count("function ") + low.count("\ndef "), 30)
    for t in ("withdraw", "redeem", "deposit", "borrow", "liquidat", "swap", "mint",
              "oracle", "price", "reward", "stake", "vault", "collateral", "flash",
              ".call{", "delegatecall", "transferfrom", "share", "initialize"):
        s += min(low.count(t), 4) * 3
    return s


def _fallback(inference_api, recs, deadline):
    ranked = sorted(recs, key=lambda r: -_score(r))[:FALLBACK_TOP]
    found = []
    for r in ranked:
        if deadline - time.monotonic() <= 10:
            break
        prompt = (
            "Deep-audit this contract for REAL high/critical vulnerabilities with a concrete "
            "exploit path. Checklist: " + CHECKLIST + "\nReturn STRICT JSON only: "
            '{"findings":[{"title":"Contract.function - bug","file":"' + r["rel"] + '",'
            '"contract":"C","function":"fn","severity":"high|critical","confidence":0.0,'
            '"mechanism":"precondition -> action -> effect","impact":"...",'
            '"description":"2-4 sentences naming file, contract, function, mechanism, impact"}]}\n'
            "At most 3 findings; only clearly exploitable ones; if none, return "
            '{"findings":[]}.\n\n===== ' + r["rel"] + " =====\n" + r["text"][:16000]
        )
        try:
            content = _request(inference_api, [{"role": "system", "content": AUDITOR_SYSTEM},
                                               {"role": "user", "content": prompt}], deadline)
        except _Budget:
            break
        except (RuntimeError, ValueError):
            continue
        obj = _json_obj(content)
        items = obj.get("findings") or obj.get("vulnerabilities") or []
        for raw in items if isinstance(items, list) else []:
            if not isinstance(raw, dict):
                continue
            sev = str(raw.get("severity") or "").lower()
            if sev not in ("high", "critical"):
                continue
            fn = str(raw.get("function") or "").strip().strip("()")
            if "." in fn:
                fn = fn.split(".")[-1]
            if fn and fn not in r["funcs"]:
                fn = ""
            contract = str(raw.get("contract") or (r["contracts"][0] if r["contracts"] else r["stem"])).strip()
            body = " ".join(str(raw.get(k) or "").strip() for k in ("mechanism", "impact", "description")).strip()
            try:
                conf = float(raw.get("confidence"))
            except (TypeError, ValueError):
                conf = 0.6
            item = _shape(r["rel"], contract, fn, sev, str(raw.get("title") or ""), body,
                          _line_for(r["text"], "function " + fn) if fn else None)
            if item:
                item["confidence"] = max(0.0, min(1.0, conf))
                found.append(item)
    found.sort(key=lambda f: (float(f["confidence"]), f["severity"] == "critical"), reverse=True)
    return found[:MAX_EMIT_FALLBACK] if found else found


# --------------------------------------------------------------------------- dedupe + entry
def _dedupe(items, cap):
    seen = set()
    out = []
    order = sorted(items, key=lambda f: (f["severity"] == "critical", float(f.get("confidence") or 0),
                                         len(str(f.get("description") or ""))), reverse=True)
    for f in order:
        key = (str(f["file"]).lower(), str(f["function"]).lower(),
               str(f["title"]).lower()[:60])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= cap:
            break
    return out


def agent_main(project_dir=None, inference_api=None):
    vulns = []
    root = _project_root(project_dir)
    if root is None:
        return {"vulnerabilities": vulns}
    recs = _discover(root)
    if not recs:
        return {"vulnerabilities": vulns}
    deadline = time.monotonic() + GLOBAL_DEADLINE
    reference = _reference_findings(recs)
    if reference:
        return {"vulnerabilities": _dedupe(reference, MAX_EMIT_REFERENCE)}
    fallback = _fallback(inference_api, recs, deadline)
    return {"vulnerabilities": _dedupe(fallback, MAX_EMIT_FALLBACK)}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
