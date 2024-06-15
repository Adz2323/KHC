#include "KeyHunt.h"
#include "GmpUtil.h"
#include "Base58.h"
#include "hash/sha256.h"
#include "hash/keccak160.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <cassert>
#ifndef WIN64
#include <pthread.h>
#endif

//using namespace std;

Point Gn[CPU_GRP_SIZE / 2];
Point _2Gn;

// ----------------------------------------------------------------------------

KeyHunt::KeyHunt(const std::string& inputFile, int compMode, int searchMode, int coinType, bool useGpu,
    const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
    const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
    this->compMode = compMode;
    this->useGpu = useGpu;
    this->outputFile = outputFile;
    this->useSSE = useSSE;
    this->nbGPUThread = 0;
    this->inputFile = inputFile;
    this->maxFound = maxFound;
    this->rKey = rKey;
    this->searchMode = searchMode;
    this->coinType = coinType;
    this->rangeStart.SetBase16(rangeStart.c_str());
    this->rangeEnd.SetBase16(rangeEnd.c_str());
    this->rangeDiff2.Set(&this->rangeEnd);
    this->rangeDiff2.Sub(&this->rangeStart);
    this->lastrKey = 0;

    secp = new Secp256K1();
    secp->Init();

    // load file
    FILE* wfd;
    uint64_t N = 0;

    wfd = fopen(this->inputFile.c_str(), "rb");
    if (!wfd) {
        printf("%s can not open\n", this->inputFile.c_str());
        exit(1);
    }

#ifdef WIN64
    _fseeki64(wfd, 0, SEEK_END);
    N = _ftelli64(wfd);
#else
    fseek(wfd, 0, SEEK_END);
    N = ftell(wfd);
#endif

    int K_LENGTH = 20;
    if (this->searchMode == (int)SEARCH_MODE_MX)
        K_LENGTH = 32;

    N = N / K_LENGTH;
    rewind(wfd);

    DATA = (uint8_t*)malloc(N * K_LENGTH);
    memset(DATA, 0, N * K_LENGTH);

    uint8_t* buf = (uint8_t*)malloc(K_LENGTH);;

    bloom = new Bloom(2 * N, 0.000001);

    uint64_t percent = (N - 1) / 100;
    uint64_t i = 0;
    printf("\n");
    while (i < N && !should_exit) {
        memset(buf, 0, K_LENGTH);
        memset(DATA + (i * K_LENGTH), 0, K_LENGTH);
        if (fread(buf, 1, K_LENGTH, wfd) == K_LENGTH) {
            bloom->add(buf, K_LENGTH);
            memcpy(DATA + (i * K_LENGTH), buf, K_LENGTH);
            if ((percent != 0) && i % percent == 0) {
                printf("\rLoading      : %lu %%", (i / percent));
                fflush(stdout);
            }
        }
        i++;
    }
    fclose(wfd);
    free(buf);

    if (should_exit) {
        delete secp;
        delete bloom;
        if (DATA)
            free(DATA);
        exit(0);
    }

    BLOOM_N = bloom->get_bytes();
    TOTAL_COUNT = N;
    targetCounter = i;
    if (coinType == COIN_BTC) {
        if (searchMode == (int)SEARCH_MODE_MA)
            printf("Loaded       : %s Bitcoin addresses\n", formatThousands(i).c_str());
        else if (searchMode == (int)SEARCH_MODE_MX)
            printf("Loaded       : %s Bitcoin xpoints\n", formatThousands(i).c_str());
    }
    else {
        printf("Loaded       : %s Ethereum addresses\n", formatThousands(i).c_str());
    }

    printf("\n");

    bloom->print();
    printf("\n");

    InitGenratorTable();

}

// ----------------------------------------------------------------------------

KeyHunt::KeyHunt(const std::vector<unsigned char>& hashORxpoint, int compMode, int searchMode, int coinType,
    bool useGpu, const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
    const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
    this->compMode = compMode;
    this->useGpu = useGpu;
    this->outputFile = outputFile;
    this->useSSE = useSSE;
    this->nbGPUThread = 0;
    this->maxFound = maxFound;
    this->rKey = rKey;
    this->searchMode = searchMode;
    this->coinType = coinType;
    this->rangeStart.SetBase16(rangeStart.c_str());
    this->rangeEnd.SetBase16(rangeEnd.c_str());
    this->rangeDiff2.Set(&this->rangeEnd);
    this->rangeDiff2.Sub(&this->rangeStart);
    this->targetCounter = 1;

    secp = new Secp256K1();
    secp->Init();

    if (this->searchMode == (int)SEARCH_MODE_SA) {
        assert(hashORxpoint.size() == 20);
        for (size_t i = 0; i < hashORxpoint.size(); i++) {
            ((uint8_t*)hash160Keccak)[i] = hashORxpoint.at(i);
        }
    }
    else if (this->searchMode == (int)SEARCH_MODE_SX) {
        assert(hashORxpoint.size() == 32);
        for (size_t i = 0; i < hashORxpoint.size(); i++) {
            ((uint8_t*)xpoint)[i] = hashORxpoint.at(i);
        }
    }
    printf("\n");

    InitGenratorTable();
}

// ----------------------------------------------------------------------------

void KeyHunt::InitGenratorTable()
{
    // Compute Generator table G[n] = (n+1)*G
    Point g = secp->G;
    Gn[0] = g;
    g = secp->DoubleDirect(g);
    Gn[1] = g;
    for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
        g = secp->AddDirect(g, secp->G);
        Gn[i] = g;
    }
    // _2Gn = CPU_GRP_SIZE*G
    _2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

    char* ctimeBuff;
    time_t now = time(NULL);
    ctimeBuff = ctime(&now);
    printf("Start Time   : %s", ctimeBuff);

    if (rKey > 0) {
        printf("Base Key     : Randomly changes on every %lu Mkeys\n", rKey);
    }
    printf("Global start : %s (%d bit)\n", this->rangeStart.GetBase16().c_str(), this->rangeStart.GetBitLength());
    printf("Global end   : %s (%d bit)\n", this->rangeEnd.GetBase16().c_str(), this->rangeEnd.GetBitLength());
    printf("Global range : %s (%d bit)\n", this->rangeDiff2.GetBase16().c_str(), this->rangeDiff2.GetBitLength());

}

// ----------------------------------------------------------------------------

KeyHunt::~KeyHunt()
{
    delete secp;
    if (searchMode == (int)SEARCH_MODE_MA || searchMode == (int)SEARCH_MODE_MX)
        delete bloom;
    if (DATA)
        free(DATA);
}

// ----------------------------------------------------------------------------

double log1(double x)
{
    // Use taylor series to approximate log(1-x)
    return -x - (x * x) / 2.0 - (x * x * x) / 3.0 - (x * x * x * x) / 4.0;
}

void KeyHunt::output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey)
{

#ifdef WIN64
    WaitForSingleObject(ghMutex, INFINITE);
#else
    pthread_mutex_lock(&ghMutex);
#endif

    FILE* f = stdout;
    bool needToClose = false;

    if (outputFile.length() > 0) {
        f = fopen(outputFile.c_str(), "a");
        if (f == NULL) {
            printf("Cannot open %s for writing\n", outputFile.c_str());
            f = stdout;
        }
        else {
            needToClose = true;
        }
    }

    if (!needToClose)
        printf("\n");

    fprintf(f, "PubAddress: %s\n", addr.c_str());
    fprintf(stdout, "\n=================================================================================\n");
    fprintf(stdout, "PubAddress: %s\n", addr.c_str());

    if (coinType == COIN_BTC) {
        fprintf(f, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
        fprintf(stdout, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
    }

    fprintf(f, "Priv (HEX): %s\n", pAddrHex.c_str());
    fprintf(stdout, "Priv (HEX): %s\n", pAddrHex.c_str());

    fprintf(f, "PubK (HEX): %s\n", pubKey.c_str());
    fprintf(stdout, "PubK (HEX): %s\n", pubKey.c_str());

    fprintf(f, "=================================================================================\n");
    fprintf(stdout, "=================================================================================\n");

    if (needToClose)
        fclose(f);

#ifdef WIN64
    ReleaseMutex(ghMutex);
#else
    pthread_mutex_unlock(&ghMutex);
#endif

}

// ----------------------------------------------------------------------------

bool KeyHunt::checkPrivKey(std::string addr, Int& key, int32_t incr, bool mode)
{
    Int k(&key), k2(&key);
    k.Add((uint64_t)incr);
    k2.Add((uint64_t)incr);
    // Check addresses
    Point p = secp->ComputePublicKey(&k);
    std::string px = p.x.GetBase16();
    std::string chkAddr = secp->GetAddress(mode, p);
    if (chkAddr != addr) {
        //Key may be the opposite one (negative zero or compressed key)
        k.Neg();
        k.Add(&secp->order);
        p = secp->ComputePublicKey(&k);
        std::string chkAddr = secp->GetAddress(mode, p);
        if (chkAddr != addr) {
            printf("\n=================================================================================\n");
            printf("Warning, wrong private key generated !\n");
            printf("  PivK :%s\n", k2.GetBase16().c_str());
            printf("  Addr :%s\n", addr.c_str());
            printf("  PubX :%s\n", px.c_str());
            printf("  PivK :%s\n", k.GetBase16().c_str());
            printf("  Check:%s\n", chkAddr.c_str());
            printf("  PubX :%s\n", p.x.GetBase16().c_str());
            printf("=================================================================================\n");
            return false;
        }
    }
    output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
    return true;
}

bool KeyHunt::checkPrivKeyETH(std::string addr, Int& key, int32_t incr)
{
    Int k(&key), k2(&key);
    k.Add((uint64_t)incr);
    k2.Add((uint64_t)incr);
    // Check addresses
    Point p = secp->ComputePublicKey(&k);
    std::string px = p.x.GetBase16();
    std::string chkAddr = secp->GetAddressETH(p);
    if (chkAddr != addr) {
        //Key may be the opposite one (negative zero or compressed key)
        k.Neg();
        k.Add(&secp->order);
        p = secp->ComputePublicKey(&k);
        std::string chkAddr = secp->GetAddressETH(p);
        if (chkAddr != addr) {
            printf("\n=================================================================================\n");
            printf("Warning, wrong private key generated !\n");
            printf("  PivK :%s\n", k2.GetBase16().c_str());
            printf("  Addr :%s\n", addr.c_str());
            printf("  PubX :%s\n", px.c_str());
            printf("  PivK :%s\n", k.GetBase16().c_str());
            printf("  Check:%s\n", chkAddr.c_str());
            printf("  PubX :%s\n", p.x.GetBase16().c_str());
            printf("=================================================================================\n");
            return false;
        }
    }
    output(addr, k.GetBase16()/*secp->GetPrivAddressETH(k)*/, k.GetBase16(), secp->GetPublicKeyHexETH(p));
    return true;
}

bool KeyHunt::checkPrivKeyX(Int& key, int32_t incr, bool mode)
{
    Int k(&key);
    k.Add((uint64_t)incr);
    Point p = secp->ComputePublicKey(&k);
    std::string addr = secp->GetAddress(mode, p);
    output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
    return true;
}

// ----------------------------------------------------------------------------

#ifdef WIN64
DWORD WINAPI _FindKeyCPU(LPVOID lpParam)
{
#else
void* _FindKeyCPU(void* lpParam)
{
#endif
    TH_PARAM* p = (TH_PARAM*)lpParam;
    p->obj->FindKeyCPU(p);
    return 0;
}

#ifdef WIN64
DWORD WINAPI _FindKeyGPU(LPVOID lpParam)
{
#else
void* _FindKeyGPU(void* lpParam)
{
#endif
    TH_PARAM* p = (TH_PARAM*)lpParam;
    p->obj->FindKeyGPU(p);
    return 0;
}

// ----------------------------------------------------------------------------

void KeyHunt::checkMultiAddresses(bool compressed, Int key, int i, Point p1)
{
    unsigned char h0[20];

    // Point
    secp->GetHash160(compressed, p1, h0);
    if (CheckBloomBinary(h0, 20) > 0) {
        std::string addr = secp->GetAddress(compressed, h0);
        if (checkPrivKey(addr, key, i, compressed)) {
            nbFoundKey++;
        }
    }
}

// ----------------------------------------------------------------------------

void KeyHunt::checkMultiAddressesETH(Int key, int i, Point p1)
{
    unsigned char h0[20];

    // Point
    secp->GetHash160(compressed, p1, h0);
    if (CheckBloomBinary(h0, 20) > 0) {
        std::string addr = secp->GetAddress(compressed, h0);
        if (checkPrivKeyETH(addr, key, i)) {
            nbFoundKey++;
        }
    }
}

// ----------------------------------------------------------------------------

void KeyHunt::FindKeyCPU(TH_PARAM* param)
{
    if (searchMode == SEARCH_MODE_SA) {
        secp->SetThreadIndex(param->threadIndex);
        if (coinType == COIN_BTC)
            checkPrivKey(param->targetAddr, param->key, 0, (compMode == SEARCH_COMPRESSED || compMode == SEARCH_BOTH));
        else
            checkPrivKeyETH(param->targetAddr, param->key, 0);
        return;
    }

    // Search space
    Int range(param->rangeEnd);
    range.Sub(&param->rangeStart);

    Int range2(param->rangeEnd);
    range2.Sub(&param->rangeStart);
    range2.RShift(1);

    if (searchMode == SEARCH_MODE_MX || searchMode == SEARCH_MODE_SX) {
        Int key(&param->rangeStart);

        Point p = secp->ComputePublicKey(&key);
        if (searchMode == SEARCH_MODE_SX)
            checkPrivKeyX(param->key, 0, (compMode == SEARCH_COMPRESSED || compMode == SEARCH_BOTH));
        else if (searchMode == SEARCH_MODE_MX) {
            checkMultiAddresses(false, param->key, 0, p);
            checkMultiAddresses(true, param->key, 0, p);
        }
    }

    bool useBloom = (searchMode == SEARCH_MODE_MA);
    while (param->key.Less(&param->rangeEnd)) {
        Int baseKey(param->key);

        for (int i = 0; i < CPU_GRP_SIZE; i++) {
            if (should_exit)
                return;
            Point p = secp->AddDirect(baseKey, Gn[i]);
            checkMultiAddresses(false, param->key, i, p);
            checkMultiAddresses(true, param->key, i, p);
        }

        param->key.Add(&range2);
    }
}

// ----------------------------------------------------------------------------

void KeyHunt::FindKeyGPU(TH_PARAM* param)
{
    if (searchMode == SEARCH_MODE_SA) {
        secp->SetThreadIndex(param->threadIndex);
        if (coinType == COIN_BTC)
            checkPrivKey(param->targetAddr, param->key, 0, (compMode == SEARCH_COMPRESSED || compMode == SEARCH_BOTH));
        else
            checkPrivKeyETH(param->targetAddr, param->key, 0);
        return;
    }

    int gridSizeX = param->gridSizeX;
    int gridSizeY = param->gridSizeY;

    GPUEngine* gpu = new GPUEngine(secp, gridSizeX, gridSizeY, param->gpuId, param->maxFound, searchMode, compMode, coinType,
        BLOOM_N, bloom->get_bits(), bloom->get_hashes(), const_cast<uint8_t*>(bloom->get_bf()), DATA, TOTAL_COUNT, (rKey != 0));

    switch (searchMode) {
    case SEARCH_MODE_MA:
        gpu->LaunchSEARCH_MODE_MA(param->found, true);
        break;
    case SEARCH_MODE_MX:
        gpu->LaunchSEARCH_MODE_MX(param->found, true);
        break;
    case SEARCH_MODE_SA:
        gpu->LaunchSEARCH_MODE_SA(param->found, true);
        break;
    case SEARCH_MODE_SX:
        gpu->LaunchSEARCH_MODE_SX(param->found, true);
        break;
    default:
        break;
    }
    delete gpu;
}

// ----------------------------------------------------------------------------

bool KeyHunt::CheckBloomBinary(unsigned char* hash, int size)
{
    return bloom->check(hash, size);
}

// ----------------------------------------------------------------------------

void KeyHunt::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{
    // CPU threads
    pthread_t* thread = new pthread_t[nbThread];
    pthread_t* threadGpu = new pthread_t[gpuId.size()];
    TH_PARAM* param = new TH_PARAM[nbThread];
    TH_PARAM* paramGpu = new TH_PARAM[gpuId.size()];

#ifdef WIN64
    // Create CPU threads
    for (int i = 0; i < nbThread; i++) {
        param[i].obj = this;
        param[i].threadIndex = i;
        param[i].maxFound = maxFound;
        param[i].found = 0;
        param[i].rangeStart.Set(&rangeStart);
        param[i].rangeEnd.Set(&rangeEnd);
        param[i].rangeStart.RShift(i);
        param[i].rangeEnd.RShift(i);
        param[i].rangeStart.Add(param[i].rangeStart);
        param[i].rangeEnd.Add(param[i].rangeEnd);

        thread[i] = CreateThread(NULL, 0, _FindKeyCPU, (void*)&param[i], 0, NULL);
    }

    // Create GPU threads
    for (int i = 0; i < gpuId.size(); i++) {
        paramGpu[i].obj = this;
        paramGpu[i].gpuId = gpuId[i];
        paramGpu[i].gridSizeX = gridSize[2 * i];
        paramGpu[i].gridSizeY = gridSize[2 * i + 1];
        paramGpu[i].maxFound = maxFound;
        paramGpu[i].found = 0;

        paramGpu[i].rangeStart.Set(&rangeStart);
        paramGpu[i].rangeEnd.Set(&rangeEnd);
        paramGpu[i].rangeStart.RShift(i);
        paramGpu[i].rangeEnd.RShift(i);
        paramGpu[i].rangeStart.Add(paramGpu[i].rangeStart);
        paramGpu[i].rangeEnd.Add(paramGpu[i].rangeEnd);

        threadGpu[i] = CreateThread(NULL, 0, _FindKeyGPU, (void*)&paramGpu[i], 0, NULL);
    }

    // Wait CPU threads
    for (int i = 0; i < nbThread; i++) {
        WaitForSingleObject(thread[i], INFINITE);
    }

    // Wait GPU threads
    for (int i = 0; i < gpuId.size(); i++) {
        WaitForSingleObject(threadGpu[i], INFINITE);
    }
#else
    // Create CPU threads
    for (int i = 0; i < nbThread; i++) {
        param[i].obj = this;
        param[i].threadIndex = i;
        param[i].maxFound = maxFound;
        param[i].found = 0;

        pthread_create(&thread[i], NULL, _FindKeyCPU, (void*)&param[i]);
    }

    // Create GPU threads
    for (int i = 0; i < gpuId.size(); i++) {
        paramGpu[i].obj = this;
        paramGpu[i].gpuId = gpuId[i];
        paramGpu[i].gridSizeX = gridSize[2 * i];
        paramGpu[i].gridSizeY = gridSize[2 * i + 1];
        paramGpu[i].maxFound = maxFound;
        paramGpu[i].found = 0;

        pthread_create(&threadGpu[i], NULL, _FindKeyGPU, (void*)&paramGpu[i]);
    }

    // Wait CPU threads
    for (int i = 0; i < nbThread; i++) {
        pthread_join(thread[i], NULL);
    }

    // Wait GPU threads
    for (int i = 0; i < gpuId.size(); i++) {
        pthread_join(threadGpu[i], NULL);
    }
#endif

    delete[] thread;
    delete[] threadGpu;
    delete[] param;
    delete[] paramGpu;
}

// ----------------------------------------------------------------------------

std::string KeyHunt::formatThousands(uint64_t x)
{
    char buf[32];
    sprintf(buf, "%lu", x);
    std::string s = buf;
    int n = s.length() - 3;
    while (n > 0) {
        s.insert(n, ",");
        n -= 3;
    }
    return s;
}

// ----------------------------------------------------------------------------
