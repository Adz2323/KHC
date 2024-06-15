/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GPUENGINEH
#define GPUENGINEH

#include <vector>
#include "../SECP256k1.h"

#define SEARCH_COMPRESSED 0
#define SEARCH_UNCOMPRESSED 1
#define SEARCH_BOTH 2

// operating mode
#define SEARCH_MODE_MA 1 // multiple addresses
#define SEARCH_MODE_SA 2 // single address
#define SEARCH_MODE_MX 3 // multiple xpoints
#define SEARCH_MODE_SX 4 // single xpoint

#define COIN_BTC 1
#define COIN_ETH 2

// Number of key per thread (must be a multiple of GRP_SIZE) per kernel call
#define STEP_SIZE (1024 * 2)

// Number of thread per block
#define ITEM_SIZE_A 28
#define ITEM_SIZE_A32 7

#define ITEM_SIZE_X 44
#define ITEM_SIZE_X32 11

struct ITEM
{
	int thId;
	int incr;
	bool mode;
	uint8_t *hash;
};

class GPUEngine
{
public:
	// Constructor for multiple addresses mode
	GPUEngine(Secp256K1 *secp, int nbThreadGroup, int nbThreadPerGroup, int gpuId, uint32_t maxFound,
			  int searchMode, int compMode, int coinType, uint64_t BLOOM_SIZE, uint64_t BLOOM_BITS,
			  uint8_t BLOOM_HASHES, const uint8_t *BLOOM_DATA, uint8_t *DATA, uint64_t TOTAL_COUNT, bool rKey);

	// Constructor for single address mode
	GPUEngine(Secp256K1 *secp, int nbThreadGroup, int nbThreadPerGroup, int gpuId, uint32_t maxFound,
			  int searchMode, int compMode, int coinType, const uint32_t *hashORxpoint, bool rKey);

	~GPUEngine();

	// Method to print CUDA device information
	static void PrintCudaInfo();

	// Method to get the number of threads
	int GetNbThread();

	// Method to get the group size
	int GetGroupSize();

	// Method to get the device name
	std::string GetDeviceName() const;

	// Method to set the keys
	bool SetKeys(Point *p);

	// Method to launch search mode MA
	bool LaunchSEARCH_MODE_MA(std::vector<ITEM> &dataFound, bool spinWait);

	// Method to launch search mode SA
	bool LaunchSEARCH_MODE_SA(std::vector<ITEM> &dataFound, bool spinWait);

	// Method to launch search mode MX
	bool LaunchSEARCH_MODE_MX(std::vector<ITEM> &dataFound, bool spinWait);

	// Method to launch search mode SX
	bool LaunchSEARCH_MODE_SX(std::vector<ITEM> &dataFound, bool spinWait);

	// Method to initialize random keys
	void InitializeRandomKeys(uint64_t *randomKeys);

private:
	std::string deviceName;
	bool initialised;
	uint32_t maxFound;
	uint32_t *outputBuffer;
	uint32_t *outputBufferPinned;
	uint64_t *inputKey;
	uint64_t *inputKeyPinned;
	uint32_t *inputHashORxpoint;
	uint32_t *inputHashORxpointPinned;
	uint8_t *inputBloomLookUp;
	uint8_t *inputBloomLookUpPinned;
	int nbThread;
	int nbThreadPerGroup;
	int searchMode;
	int compMode;
	int coinType;
	int outputSize;
	uint64_t BLOOM_SIZE;
	uint64_t BLOOM_BITS;
	uint8_t BLOOM_HASHES;
	uint8_t *DATA;
	uint64_t TOTAL_COUNT;
	bool rKey;
	uint64_t *__2Gnx;
	uint64_t *__2Gny;
	uint64_t *_Gx;
	uint64_t *_Gy;
	bool callKernelSEARCH_MODE_MA();
	bool callKernelSEARCH_MODE_MX();
	bool callKernelSEARCH_MODE_SA();
	bool callKernelSEARCH_MODE_SX();
	void InitGenratorTable(Secp256K1 *secp);
	int CheckBinary(const uint8_t *_x, int K_LENGTH);
};

#endif
