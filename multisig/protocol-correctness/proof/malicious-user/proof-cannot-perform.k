module PROOF-CANNOT-PERFORM
  imports MALICIOUS-USER-EXECUTE
  imports PSEUDOCODE

  claim <T><TT>
          <k> runExternalCallsFromUser(MaliciousAddress:Address, _Count:Int) ~> K:K </k>
          invariantState(
              NumUsers:Usize,
              UserIdToAddress:Map,
              AddressToUserId:Map,
              NumBoardMembers:Usize,
              NumProposers:Usize,
              UserRoles:Map,
              Quorum:Usize,
              ActionLastIndex:Usize,
              ActionData:Map,
              ActionSigners:Map,
              PerformedActions:List)
        </TT></T>
      =>
        <T><TT>
          <k> runExternalCalls(EC) </k>
          invariantState(
              NumUsers,
              ?UserIdToAddress:Map,
              ?AddressToUserId:Map,
              NumBoardMembers,
              NumProposers,
              UserRoles,
              Quorum,
              ?ActionLastIndex1:Usize,
              ?ActionData1:Map,
              ?ActionSigners1:Map,
              PerformedActions:List):StateCell
        </TT></T>
    requires true
        andBool maliciousInvariant(
            MaliciousAddress:Map,
            NumUsers:Usize,
            UserIdToAddress:Map,
            UserIdToAddress:Map,
            AddressToUserId:Map,
            AddressToUserId:Map,
            NumBoardMembers:Usize,
            NumProposers:Usize,
            UserRoles:Map,
            Quorum:Usize,
            ActionLastIndex:Usize,
            ActionData:Map,
            ActionSigners:Map,
            expand(expanded))
        andBool atMostThisSigner(AddressToUserId, MaliciousAddress, ?ActionSigners1)

        andBool Quorum >= 2
    ensures true
        andBool mapIncluded(AddressToUserId, ?AddressToUserId)
        andBool mapIncluded(UserIdToAddress, ?UserIdToAddress)
        andBool atMostThisSigner(AddressToUserId, MaliciousAddress, ?ActionSigners1)
endmodule
