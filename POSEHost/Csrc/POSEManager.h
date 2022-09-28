#ifndef POSEMANAGER_H_
#define POSEMANAGER_H_

#include "PythonWrapper.h"

#define POOL_SIZE 3
#define ADDR_SIZE 20
#define HASH_SIZE 32
#define PK_SIZE 64
#define SIG_SIZE 65

typedef unsigned char EthAddr[ADDR_SIZE];
typedef unsigned char Hash[HASH_SIZE];
typedef unsigned char EnclavePK[PK_SIZE];
typedef unsigned char EnclaveSig[SIG_SIZE];

struct addrList {
	int len_list;
	EthAddr **list;
};

struct eventData {
	int len_list;
	Hash **txhashes;
	EthAddr **froms;
	int *values; // actually an uint256 -> important for encoding
	int *len_inputs;
	unsigned char ***inputs;
};

struct eventDataEncoded {
	int len_list;
	int *len;
	unsigned char **bytesData;
};

int init(PyObject* pModule);

// MAIN CONTRACT CALLS:
int registerEnclave(PyObject* pModule, EthAddr addr, EnclavePK epk, EnclaveSig esig);
int initContractCreation(PyObject* pModule, EthAddr creator, Hash codeHash, int contractId);
int finalizeCreation(PyObject* pModule, int contractId, EthAddr poolAddr, EthAddr poolOps[POOL_SIZE], EnclaveSig esig);

// GETTER CALLS:
struct addrList getOperatorList(PyObject* pModule);
struct eventData getEventTxsSince(PyObject* pModule, int contractId, int blockNo);
struct eventDataEncoded getEventTxsSinceEncoded(PyObject* pModule, int contractId, int blockNo);

// simple python tests
char* testSimpleIntReturn();
char* testContractReturn();

void printBytesAsHex(int len, unsigned char* bytes);

#endif /* POSEMANAGER_H_ */
