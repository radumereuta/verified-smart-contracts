require "protocol-correctness/proof/execution-proof.k"
require "protocol-correctness/proof/invariant/invariant-execution.k"

module MALICIOUS-USER-EXECUTE-SYNTAX
  imports EXECUTION-PROOF-SYNTAX
endmodule

module MALICIOUS-USER-INVARIANT-FUNCTIONS
  imports MAP
  imports PSEUDOCODE-SYNTAX

  syntax Bool ::= onlyThisSigner(addressToUserId:Map, Address, actionSigners:Map)
      [function, functional]

  rule  onlyThisSigner(
            AddressToUserId:Map,
            Address:Address,
            .Map)
      => true
  rule  onlyThisSigner(
            AddressToUserId:Map,
            Address:Address,
            K |-> Signers ActionSigners:Map)
      =>
        #if Address in_keys(AddressToUserId)
        #then oneElementList(AddressToUserId[Address] orDefault void, Signers)
        #else false
        #fi
    [simplification]

  syntax Bool ::= oneElementList(element:KItem, L:ExpressionList)
  rule oneElementList(E:Expression, [E, .]) => true
  rule oneElementList(_, _) => false [owise]
endmodule

module MALICIOUS-USER-INVARIANT
  imports INVARIANT
  imports MALICIOUS-USER-INVARIANT-FUNCTIONS

  syntax Bool ::= maliciousInvariant(
            maliciousAddress:Map,
            numUsers:Usize,
            initialUserIdToAddress:Map,
            currentUserIdToAddress:Map,
            initinalAddressToUserId:Map,
            currentAddressToUserId:Map,
            numBoardMembers:Usize,
            numProposers:Usize,
            userRoles:Map,
            quorum:Usize,
            actionLastIndex:Usize,
            actionData:Map,
            actionSigners:Map,
            PropertyHandling)
      [function, functional]

  rule  maliciousInvariant(
            MaliciousAddress:Map,
            NumUsers:Usize,
            InitialUserIdToAddress:Map,
            CurrentUserIdToAddress:Map,
            InitinalAddressToUserId:Map,
            CurrentAddressToUserId:Map,
            NumBoardMembers:Usize,
            NumProposers:Usize,
            UserRoles:Map,
            Quorum:Usize,
            ActionLastIndex:Usize,
            ActionData:Map,
            ActionSigners:Map,
            Handling:PropertyHandling)
      => true
        andBool invariant(
            NumUsers,
            CurrentUserIdToAddress,
            CurrentAddressToUserId,
            NumBoardMembers,
            NumProposers,
            UserRoles,
            Quorum,
            ActionLastIndex,
            ActionData,
            ActionSigners,
            Handling)
        andBool mapIncluded(AddressToUserId, ?AddressToUserId)
        andBool mapIncluded(UserIdToAddress, ?UserIdToAddress)
        andBool onlyThisSigner(AddressToUserId, MaliciousAddress, ?ActionSigners1)
endmodule

module MALICIOUS-USER-HELPERS
  imports PSEUDOCODE-SYNTAX

  syntax KItem ::= runExternalCallsFromUser(Address, steps:Int)

  rule runExternalCallsFromUser(A:Address, Steps:Int) => .K
    requires Steps <=Int 0
  rule runExternalCallsFromUser(A:Address, Steps:Int)
      => runExternalCallFromUser(A) ~> runExternalCallsFromUser(A, Steps -Int 1)
    requires Steps >Int 0

  syntax KItem ::= runExternalCallFromUser(Address)

  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run proposeAddBoardMember(U:Usize))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run proposeAddProposer(U:Usize))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run proposeRemoveUser(U:Usize))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run proposeChangeQuorum(Quorum:Usize))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run proposeSendEgld(To:Address, Amount:BigUint, Data:BoxedBytes))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run proposeSCDeploy(
          Amount:BigUint,
          Code:BoxedBytes,
          Upgradeable:Bool,
          Payable:Bool,
          Readable:Bool,
          Args:ExpressionList))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run proposeSCCall(
          To:Address,
          Amount:BigUint,
          Function:BoxedBytes,
          Args:ExpressionList))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run sign(A:ActionId))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run unsign(A:ActionId))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run performActionEndpoint(A:ActionId))
  rule runExternalCallFromUser(A:Address) => runExternalCall(from A run discardAction(A:ActionId))
endmodule

module MALICIOUS-USER-EXECUTE
  imports EXECUTION-PROOF
  imports INVARIANT-EXECUTION
  imports MALICIOUS-USER-INVARIANT
endmodule