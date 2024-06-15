#ifndef GPUENGINE_H
#define GPUENGINE_H

#include <vector>
#include <string>
#include "../Int.h"
#include "../Point.h"
#include "../SECP256k1.h"
#include "../Bloom.h"

#define COIN_BTC 0
#define COIN_ETH 1

#define SEARCH_COMPRESSED 0
#define SEARCH_UNCOMPRESSED 1
#define SEARCH_BOTH 2

#define SEARCH_MODE_SA 0 // Single Address
#define SEARCH_MODE_SX 1 // Single X point
#define SEARCH_MODE_MA 2 // Multiple Addresses
#define SEARCH_MODE_MX 3 // Multiple X points

#define STEP_SIZE 256

class GPUEngine
{
public:
	GPUEngine(Secp256K1 *secp, int gridSizeX, int gridSizeY, int gpuId, uint32_t maxFound, int searchMode, int compMode, int coinType,
			  uint64_t BLOOM_N, uint32_t bloom_bits, uint32_t bloom_hashes, uint8_t *bloom_bf, uint8_t *data, uint64_t data_count, bool useRandomKey);
	GPUEngine(Secp256K1 *secp, int gridSizeX, int gridSizeY, int gpuId, uint32_t maxFound, int searchMode, int compMode, int coinType,
			  uint32_t *hash160Keccak, bool useRandomKey);
	GPUEngine(Secp256K1 *secp, int gridSizeX, int gridSizeY, int gpuId, uint32_t maxFound, int searchMode, int compMode, int coinType,
			  uint32_t *xpoint, bool useRandomKey);
	~GPUEngine();

	bool SetKeys(Point *p);
	bool LaunchSEARCH_MODE_MA(std::vector<ITEM> &found, bool useBloom);
	bool LaunchSEARCH_MODE_MX(std::vector<ITEM> &found, bool useBloom);
	bool LaunchSEARCH_MODE_SA(std::vector<ITEM> &found, bool useBloom);
	bool LaunchSEARCH_MODE_SX(std::vector<ITEM> &found, bool useBloom);
	int GetNbThread();
	int GetGroupSize();

	std::string deviceName;

private:
	Secp256K1 *secp;
	int gridSizeX;
	int gridSizeY;
	int gpuId;
	uint32_t maxFound;
	int searchMode;
	int compMode;
	int coinType;

	uint64_t BLOOM_N;
	uint32_t bloom_bits;
	uint32_t bloom_hashes;
	uint8_t *bloom_bf;
	uint8_t *data;
	uint64_t data_count;
	uint32_t *hash160Keccak;
	uint32_t *xpoint;

	bool useRandomKey;
};

#endif // GPUENGINE_H
