/**
Copyright (c) 2010 Satoshi Nakamoto
Copyright (c) 2009-2012 The Bitcoin developers
Copyright (c) 2018 Xpax developers
Distributed under the MIT/X11 software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php.
*/
#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds array into usable address objects.
static void convertSeeds(std::vector<CAddress> &vSeedsOut, const unsigned int *data, unsigned int count, int port)
{
     // It'll only connect to one or two seed nodes because once it connects,
     // it'll get a pile of addresses with newer timestamps.
     // Seed nodes are given a random 'last seen time' of between one and two
     // weeks ago.
     const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int k = 0; k < count; ++k)
    {
        struct in_addr ip;
        unsigned int i = data[k], t;

        // -- convert to big endian
        t =   (i & 0x000000ff) << 24u
            | (i & 0x0000ff00) << 8u
            | (i & 0x00ff0000) >> 8u
            | (i & 0xff000000) >> 24u;

        memcpy(&ip, &t, sizeof(ip));

        CAddress addr(CService(ip, port));
        addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

/*******************/
/* Main network    */
/*******************/
class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xec;
        pchMessageStart[1] = 0x3a;
        pchMessageStart[2] = 0xaf;
        pchMessageStart[3] = 0x85;
        vAlertPubKey = ParseHex("041c01169dd8d55d0c04dad302b3a1aa6d27f227c82650d2b12819ace08ecf1d555d243e267de1e1be563013df5edf7698ec1c86e52086a63f2b06ca87fca3f5c7");
        nDefaultPort = 15876;
        nRPCPort = 15877;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);

        /** Genesis block info:
        CBlock(hash=0000088e39f7f205701afd80597d455da6c775463bf8d72d6a45bab2160ea929, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=aa9413a7d0545af6b3d5ced324ff0529c30c656cd7fb7192db0818781fbfb440, nTime=1518161400, nBits=1e0fffff, nNonce=2938116, vtx=1, vchBlockSig=)
          Coinbase(hash=aa9413a7d0545af6b3d5ced324ff0529c30c656cd7fb7192db0818781fbfb440, nTime=1518161400, ver=1, vin.size=1, vout.size=1, nLockTime=0)
            CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a4032303138204665627275617279203820537061636558204c61756e636865642074686520576f726c642073204d6f737420506f77657266756c20526f636b6574)
            CTxOut(empty)

          vMerkleTree:  aa9413a7d0545af6b3d5ced324ff0529c30c656cd7fb7192db0818781fbfb440

        mainnet.genesis.GetHash():      0000088e39f7f205701afd80597d455da6c775463bf8d72d6a45bab2160ea929
        mainnet.genesis.hashMerkleRoot: aa9413a7d0545af6b3d5ced324ff0529c30c656cd7fb7192db0818781fbfb440
        mainnet.genesis.nTime:          1518161400
        mainnet.genesis.nNonce:         2938116
        */
        const char* pszTimestamp = "2018 February 8 SpaceX Launched the World s Most Powerful Rocket";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1518161400, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1518161400;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 2938116;

        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x0000088e39f7f205701afd80597d455da6c775463bf8d72d6a45bab2160ea929"));
        assert(genesis.hashMerkleRoot == uint256("0xaa9413a7d0545af6b3d5ced324ff0529c30c656cd7fb7192db0818781fbfb440"));

        base58Prefixes[PUBKEY_ADDRESS]  = std::vector<unsigned char>(1,15);
        base58Prefixes[SCRIPT_ADDRESS]  = std::vector<unsigned char>(1,45);
        base58Prefixes[SECRET_KEY]      = std::vector<unsigned char>(1,175);
        base58Prefixes[STEALTH_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[EXT_PUBLIC_KEY]  = list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY]  = list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vSeeds.push_back(CDNSSeedData("0",  "45.77.3.217"));
        vSeeds.push_back(CDNSSeedData("1",  "209.250.229.72"));
        convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);

        nPoolMaxTransactions = 3;
        strDarksendPoolDummyAddress = "KqCw84AwFKfF4HcxcMMAJwsvd8dRQ7LtMx";
        nLastPOWBlock = 10368000;
        nPOSStartBlock = 2;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


/*******************/
/* TestNet network */
/*******************/
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xeb;
        pchMessageStart[1] = 0x3b;
        pchMessageStart[2] = 0xaf;
        pchMessageStart[3] = 0x85;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);
        vAlertPubKey = ParseHex("04e16101e3a2bc4d57755e6cb02e87099481b3293acbff76d6396767412c1c5e813df209f746757cfc8ba9847bfd4491624d9bfb197939b843ec3a2578fb0a24f8");
        nDefaultPort = 14876;
        nRPCPort = 14877;
        strDataDir = "testnet";

        /**
        CBlock(hash=00000facbb1d343df60c249084393ad2039b717fc455f9dc58dd1c2ff2a67654, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=84cd53c84f276442d1fb98eb847216d1c88013af9e3b82b7567090aaac3c6aab, nTime=1518161400, nBits=1e0fffff, nNonce=277487, vtx=2, vchBlockSig=)
          Coinbase(hash=aa9413a7d0545af6b3d5ced324ff0529c30c656cd7fb7192db0818781fbfb440, nTime=1518161400, ver=1, vin.size=1, vout.size=1, nLockTime=0)
            CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a4032303138204665627275617279203820537061636558204c61756e636865642074686520576f726c642073204d6f737420506f77657266756c20526f636b6574)
            CTxOut(empty)

          Coinbase(hash=d524a6425f55721eff9fd2000a412b1a1c95cead2d20c4de3a04e0b0174cd1d6, nTime=1518161400, ver=1, vin.size=1, vout.size=1, nLockTime=0)
            CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a1e32303138204558555320636f696e2074657374206e65742062697274682e)
            CTxOut(empty)

          vMerkleTree:  aa9413a7d0545af6b3d5ced324ff0529c30c656cd7fb7192db0818781fbfb440 d524a6425f55721eff9fd2000a412b1a1c95cead2d20c4de3a04e0b0174cd1d6 84cd53c84f276442d1fb98eb847216d1c88013af9e3b82b7567090aaac3c6aab

        testnet.genesis.GetHash():      00000facbb1d343df60c249084393ad2039b717fc455f9dc58dd1c2ff2a67654
        testnet.genesis.hashMerkleRoot: 84cd53c84f276442d1fb98eb847216d1c88013af9e3b82b7567090aaac3c6aab
        testnet.genesis.nTime:          1518161400
        testnet.genesis.nNonce:         277487
        */
        const char* pszTimestamp = "2018 XPAX coin test net birth.";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1518161400, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1518161400;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 277487;

        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x00000facbb1d343df60c249084393ad2039b717fc455f9dc58dd1c2ff2a67654"));
        assert(genesis.hashMerkleRoot == uint256("0x84cd53c84f276442d1fb98eb847216d1c88013af9e3b82b7567090aaac3c6aab"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,136);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,219);
        base58Prefixes[STEALTH_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        convertSeeds(vFixedSeeds, pnTestnetSeed, ARRAYLEN(pnTestnetSeed), nDefaultPort);

        nLastPOWBlock = 10368000;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {

    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
