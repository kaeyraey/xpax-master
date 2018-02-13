
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef MASTERNODEMAN_H
#define MASTERNODEMAN_H

#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "key.h"
#include "core.h"
#include "util.h"
#include "script.h"
#include "base58.h"
#include "main.h"
#include "masternode.h"

#define MASTERNODES_DUMP_SECONDS               (15*60)
#define MASTERNODES_DSEG_SECONDS               (3*60*60)

using namespace std;

class CMasternodeMan;

extern CMasternodeMan mnodeman;

extern void Misbehaving(NodeId nodeid, int howmuch);

void DumpMasternodes();

/** Access to the MN database (mncache.dat) */
class CMasternodeDB
{
private:
    boost::filesystem::path pathMN;
    std::string strMagicMessage;
public:
    enum ReadResult {
        Ok,
       FileError,
        HashReadError,
        IncorrectHash,
        IncorrectMagicMessage,
        IncorrectMagicNumber,
        IncorrectFormat
    };

    CMasternodeDB();
    bool Write(const CMasternodeMan &mnodemanToSave);
    ReadResult Read(CMasternodeMan& mnodemanToLoad);
};

class CMasternodeMan
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // map to hold all MNs
    std::vector<CMasternode> vMasternodes;
    // who's asked for the masternode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForMasternodeList;
    // who we asked for the masternode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForMasternodeList;
    // which masternodes we've asked for
    std::map<COutPoint, int64_t> mWeAskedForMasternodeListEntry;

public:
    // keep track of dsq count to prevent masternodes from gaming darksend queue
    int64_t nDsqCount;

    IMPLEMENT_SERIALIZE
    (
        // serialized format:
        // * version byte (currently 0)
        // * masternodes vector
        {
                LOCK(cs);
                unsigned char nVersion = 0;
                READWRITE(nVersion);
                READWRITE(vMasternodes);
                READWRITE(mAskedUsForMasternodeList);
                READWRITE(mWeAskedForMasternodeList);
                READWRITE(mWeAskedForMasternodeListEntry);
                READWRITE(nDsqCount);
        }
    )

    CMasternodeMan();
    CMasternodeMan(CMasternodeMan& other);

    // Add an entry
    bool Add(CMasternode &mn);

    // Check all masternodes
    void Check();

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, CTxIn &vin);

    // Check all masternodes and remove inactive
    void CheckAndRemove();

    // Clear masternode vector
    void Clear();

    unsigned int CountEnabled(int protocolVersion = -1);

    int CountMasternodesAboveProtocol(int protocolVersion);

    void DsegUpdate(CNode* pnode);

    // Find an entry
    CMasternode* Find(const CTxIn& vin);
    CMasternode* Find(const CPubKey& pubKeyMasternode);

    //Find an entry thta do not match every entry provided vector
    CMasternode* FindOldestNotInVec(const std::vector<CTxIn> &vVins, int nMinimumAge);

    // Find a random entry
    CMasternode* FindRandom();

    /// Find a random entry
    CMasternode* FindRandomNotInVec(std::vector<CTxIn> &vecToExclude, int protocolVersion = -1);

    // Get the current winner for this block
    CMasternode* GetCurrentMasterNode(int mod=1, int64_t nBlockHeight=0, int minProtocol=0);

    std::vector<CMasternode> GetFullMasternodeVector() { Check(); return vMasternodes; }

    std::vector<pair<int, CMasternode> > GetMasternodeRanks(int64_t nBlockHeight, int minProtocol=0);
    int GetMasternodeRank(const CTxIn &vin, int64_t nBlockHeight, int minProtocol=0, bool fOnlyActive=true);
    CMasternode* GetMasternodeByRank(int nRank, int64_t nBlockHeight, int minProtocol=0, bool fOnlyActive=true);

    void ProcessMasternodeConnections();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    // Return the number of (unique) masternodes
    int size() { return vMasternodes.size(); }

    std::string ToString() const;

    //
    // Relay Masternode Messages
    //

    void RelayOldMasternodeEntry(const CTxIn vin, const CService addr, const std::vector<unsigned char> vchSig, const int64_t nNow, const CPubKey pubkey, const CPubKey pubkey2, const int count, const int current, const int64_t lastUpdated, const int protocolVersion);
    void RelayMasternodeEntry(const CTxIn vin, const CService addr, const std::vector<unsigned char> vchSig, const int64_t nNow, const CPubKey pubkey, const CPubKey pubkey2, const int count, const int current, const int64_t lastUpdated, const int protocolVersion, CScript rewardAddress, int rewardPercentage);
    void RelayMasternodeEntryPing(const CTxIn vin, const std::vector<unsigned char> vchSig, const int64_t nNow, const bool stop);

    void Remove(CTxIn vin);

};

#endif

/** FOR REFFERENCE:
 *
#ifndef MASTERNODEMAN_H
#define MASTERNODEMAN_H

#include "masternode.h"
#include "sync.h"

using namespace std;

class CMasternodeMan;
class CConnman;

extern CMasternodeMan mnodeman;

class CMasternodeMan
{
public:
    typedef std::pair<arith_uint256, CMasternode*> score_pair_t;
    typedef std::vector<score_pair_t> score_pair_vec_t;
    typedef std::pair<int, CMasternode> rank_pair_t;
    typedef std::vector<rank_pair_t> rank_pair_vec_t;

private:
    static const std::string SERIALIZATION_VERSION_STRING;

    static const int DSEG_UPDATE_SECONDS        = 3 * 60 * 60;

    static const int LAST_PAID_SCAN_BLOCKS      = 100;

    static const int MIN_POSE_PROTO_VERSION     = 70203;
    static const int MAX_POSE_CONNECTIONS       = 10;
    static const int MAX_POSE_RANK              = 10;
    static const int MAX_POSE_BLOCKS            = 10;

    static const int MNB_RECOVERY_QUORUM_TOTAL      = 10;
    static const int MNB_RECOVERY_QUORUM_REQUIRED   = 6;
    static const int MNB_RECOVERY_MAX_ASK_ENTRIES   = 10;
    static const int MNB_RECOVERY_WAIT_SECONDS      = 60;
    static const int MNB_RECOVERY_RETRY_SECONDS     = 3 * 60 * 60;


    mutable CCriticalSection cs;

    int nCachedBlockHeight;

    std::map<COutPoint, CMasternode> mapMasternodes;
    std::map<CNetAddr, int64_t> mAskedUsForMasternodeList;
    std::map<CNetAddr, int64_t> mWeAskedForMasternodeList;
    std::map<COutPoint, std::map<CNetAddr, int64_t> > mWeAskedForMasternodeListEntry;
    std::map<CNetAddr, CMasternodeVerification> mWeAskedForVerification;

    std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > > mMnbRecoveryRequests;
    std::map<uint256, std::vector<CMasternodeBroadcast> > mMnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256> > listScheduledMnbRequestConnections;

    bool fMasternodesAdded;

    bool fMasternodesRemoved;

    std::vector<uint256> vecDirtyGovernanceObjectHashes;

    int64_t nLastWatchdogVoteTime;

    friend class CMasternodeSync;
    CMasternode* Find(const COutPoint& outpoint);

    bool GetMasternodeScores(const uint256& nBlockHash, score_pair_vec_t& vecMasternodeScoresRet, int nMinProtocol = 0);

public:
    std::map<uint256, std::pair<int64_t, CMasternodeBroadcast> > mapSeenMasternodeBroadcast;
    std::map<uint256, CMasternodePing> mapSeenMasternodePing;
    std::map<uint256, CMasternodeVerification> mapSeenMasternodeVerification;
    int64_t nDsqCount;


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        LOCK(cs);
        std::string strVersion;
        if(ser_action.ForRead()) {
            READWRITE(strVersion);
        }
        else {
            strVersion = SERIALIZATION_VERSION_STRING;
            READWRITE(strVersion);
        }

        READWRITE(mapMasternodes);
        READWRITE(mAskedUsForMasternodeList);
        READWRITE(mWeAskedForMasternodeList);
        READWRITE(mWeAskedForMasternodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastWatchdogVoteTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenMasternodeBroadcast);
        READWRITE(mapSeenMasternodePing);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CMasternodeMan();

    bool Add(CMasternode &mn);

    void AskForMN(CNode *pnode, const COutPoint& outpoint, CConnman& connman);
    void AskForMnb(CNode *pnode, const uint256 &hash);

    bool PoSeBan(const COutPoint &outpoint);
    bool AllowMixing(const COutPoint &outpoint);
    bool DisallowMixing(const COutPoint &outpoint);

    void Check();

    void CheckAndRemove(CConnman& connman);
    void CheckAndRemove() {}

    void Clear();

    int CountMasternodes(int nProtocolVersion = -1);
    int CountEnabled(int nProtocolVersion = -1);


    void DsegUpdate(CNode* pnode, CConnman& connman);

    bool Get(const COutPoint& outpoint, CMasternode& masternodeRet);
    bool Has(const COutPoint& outpoint);

    bool GetMasternodeInfo(const COutPoint& outpoint, masternode_info_t& mnInfoRet);
    bool GetMasternodeInfo(const CPubKey& pubKeyMasternode, masternode_info_t& mnInfoRet);
    bool GetMasternodeInfo(const CScript& payee, masternode_info_t& mnInfoRet);

    bool GetNextMasternodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCountRet, masternode_info_t& mnInfoRet);
    bool GetNextMasternodeInQueueForPayment(bool fFilterSigTime, int& nCountRet, masternode_info_t& mnInfoRet);

    masternode_info_t FindRandomNotInVec(const std::vector<COutPoint> &vecToExclude, int nProtocolVersion = -1);

    std::map<COutPoint, CMasternode> GetFullMasternodeMap() { return mapMasternodes; }

    bool GetMasternodeRanks(rank_pair_vec_t& vecMasternodeRanksRet, int nBlockHeight = -1, int nMinProtocol = 0);
    bool GetMasternodeRank(const COutPoint &outpoint, int& nRankRet, int nBlockHeight = -1, int nMinProtocol = 0);

    void ProcessMasternodeConnections(CConnman& connman);
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv, CConnman& connman);

    void DoFullVerificationStep(CConnman& connman);
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<CMasternode*>& vSortedByAddr, CConnman& connman);
    void SendVerifyReply(CNode* pnode, CMasternodeVerification& mnv, CConnman& connman);
    void ProcessVerifyReply(CNode* pnode, CMasternodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CMasternodeVerification& mnv);

    int size() { return mapMasternodes.size(); }

    std::string ToString() const;

    void UpdateMasternodeList(CMasternodeBroadcast mnb, CConnman& connman);
    bool CheckMnbAndUpdateMasternodeList(CNode* pfrom, CMasternodeBroadcast mnb, int& nDos, CConnman& connman);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    void UpdateLastPaid(const CBlockIndex* pindex);

    void AddDirtyGovernanceObjectHash(const uint256& nHash)
    {
        LOCK(cs);
        vecDirtyGovernanceObjectHashes.push_back(nHash);
    }

    std::vector<uint256> GetAndClearDirtyGovernanceObjectHashes()
    {
        LOCK(cs);
        std::vector<uint256> vecTmp = vecDirtyGovernanceObjectHashes;
        vecDirtyGovernanceObjectHashes.clear();
        return vecTmp;;
    }

    bool IsWatchdogActive();
    void UpdateWatchdogVoteTime(const COutPoint& outpoint, uint64_t nVoteTime = 0);
    bool AddGovernanceVote(const COutPoint& outpoint, uint256 nGovernanceObjectHash);
    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void CheckMasternode(const CPubKey& pubKeyMasternode, bool fForce);

    bool IsMasternodePingedWithin(const COutPoint& outpoint, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetMasternodeLastPing(const COutPoint& outpoint, const CMasternodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    void NotifyMasternodeUpdates(CConnman& connman);

};

#endif

*
*/
