#include "POSEManager.h"

#include <string.h>

int init(PyObject* pModule) {
	callMethod(pModule, "init", NULL);
	return 0;
}

int registerEnclave(PyObject* pModule, EthAddr addr, EnclavePK epk, EnclaveSig esig) {
	// construct args
	PyObject* pArgs = PyTuple_New(3);
	PyObject* pvAddr = Py_BuildValue("y#", addr, ADDR_SIZE);
	PyObject* pvEpk = Py_BuildValue("y#", epk, PK_SIZE);
	PyObject* pvEsig = Py_BuildValue("y#", esig, SIG_SIZE);
	//printf(PyUnicode_AsUTF8(PyObject_Str(pvAddr))); // mimics python's str(obj)
	PyObject* pRetValue;
	if (!pvAddr || !pvEpk || !pvEsig) {
		fprintf(stderr, "Cannot convert argument\n");
	} else {
		PyTuple_SetItem(pArgs, 0, pvAddr);
		PyTuple_SetItem(pArgs, 1, pvEpk);
		PyTuple_SetItem(pArgs, 2, pvEsig);
		// execute call
		pRetValue = callMethod(pModule, "register_enclave", pArgs);
		if (pRetValue != NULL) {
			// process return value
			return (int) PyLong_AsLong(pRetValue);
		}
		else {
			PyErr_Print();
			fprintf(stderr,"Call failed\n");
		}
	}
	Py_DECREF(pArgs);
	Py_DECREF(pvAddr);
	Py_DECREF(pvEpk);
	Py_DECREF(pvEsig);
	Py_XDECREF(pRetValue);
	return -1;
}

int initContractCreation(PyObject* pModule, EthAddr creator, Hash codeHash, int contractId) {
	// construct args
	PyObject* pArgs = PyTuple_New(3);
	PyObject* pvCreator = Py_BuildValue("y#", creator, ADDR_SIZE);
	PyObject* pvHash = Py_BuildValue("y#", codeHash, HASH_SIZE);
	PyObject* pvContractId = PyLong_FromLong(contractId);
	//printf(PyUnicode_AsUTF8(PyObject_Str(pvAddr))); // mimics python's str(obj)
	PyObject* pRetValue;
	if (!pvCreator || !pvHash || !pvContractId) {
		fprintf(stderr, "Cannot convert argument\n");
	} else {
		PyTuple_SetItem(pArgs, 0, pvCreator);
		PyTuple_SetItem(pArgs, 1, pvHash);
		PyTuple_SetItem(pArgs, 2, pvContractId);
		// execute call
		pRetValue = callMethod(pModule, "init_creation", pArgs);
		if (pRetValue != NULL) {
			// process return value
			return (int) PyLong_AsLong(pRetValue);
		}
		else {
			PyErr_Print();
			fprintf(stderr,"Call failed\n");
		}
	}
	Py_DECREF(pArgs);
	Py_DECREF(pvCreator);
	Py_DECREF(pvHash);
	Py_DECREF(pvContractId);
	Py_XDECREF(pRetValue);
	return -1;
}

int finalizeCreation(PyObject* pModule, int contractId, EthAddr poolAddr, EthAddr poolOps[POOL_SIZE], EnclaveSig esig) {
	// construct args
	PyObject* pArgs = PyTuple_New(4);
	PyObject* pvContractId = PyLong_FromLong(contractId);
	PyObject* pvPoolAddr = Py_BuildValue("y#", poolAddr, ADDR_SIZE);
	PyObject* pvPoolOps = PyList_New(POOL_SIZE);
	for(int i = 0; i < POOL_SIZE; i++) {
		PyList_SetItem(pvPoolOps, i, Py_BuildValue("y#", poolOps[i], ADDR_SIZE));
	}
	PyObject* pvEsig = Py_BuildValue("y#", esig, SIG_SIZE);
	//printf(PyUnicode_AsUTF8(PyObject_Str(pvAddr))); // mimics python's str(obj)
	PyObject* pRetValue;
	if (!pvContractId || !pvPoolAddr || !pvPoolOps || !pvEsig) {
		fprintf(stderr, "Cannot convert argument\n");
	} else {
		PyTuple_SetItem(pArgs, 0, pvContractId);
		PyTuple_SetItem(pArgs, 1, pvPoolAddr);
		PyTuple_SetItem(pArgs, 2, pvPoolOps);
		PyTuple_SetItem(pArgs, 3, pvEsig);
		// execute call
		pRetValue = callMethod(pModule, "finalize_creation", pArgs);
		if (pRetValue != NULL) {
			// process return value
			return (int) PyLong_AsLong(pRetValue);
		}
		else {
			PyErr_Print();
			fprintf(stderr,"Call failed\n");
		}
	}
	Py_DECREF(pArgs);
	Py_DECREF(pvContractId);
	Py_DECREF(pvPoolAddr);
	Py_DECREF(pvPoolOps);
	Py_DECREF(pvEsig);
	Py_XDECREF(pRetValue);
	return -1;
}

struct addrList getOperatorList(PyObject* pModule) {
	struct addrList result;
	// construct args
	PyObject* pArgs = PyTuple_New(0);
	PyObject* pRetValue;
	// execute call
	pRetValue = callMethod(pModule, "get_operator_list", pArgs);
	if (pRetValue != NULL) {
		// process return value
		result.len_list = PyList_Size(pRetValue);
		EthAddr *temp1 = (EthAddr*) malloc(sizeof(EthAddr) * result.len_list);
		EthAddr **temp = &temp1;
		for(int i = 0; i < result.len_list; i++) {
			PyObject* pAddr = PyList_GetItem(pRetValue, i);
			char *sAddr = PyBytes_AsString(pAddr);
			EthAddr *addr = (EthAddr*) malloc(sizeof(EthAddr));
			memcpy(addr, (EthAddr*) sAddr, sizeof(EthAddr));
			temp[i] = addr;
			Py_DECREF(pAddr);
		}
		result.list = temp;
		return result;
	}
	else {
		PyErr_Print();
		fprintf(stderr,"Call failed\n");
	}
	Py_DECREF(pArgs);
	Py_XDECREF(pRetValue);
	return result;
}

struct eventData getEventTxsSince(PyObject* pModule, int contractId, int blockNo) {
	struct eventData result;
	// construct args
	PyObject* pArgs = PyTuple_New(2);
	PyObject* pContractId = PyLong_FromLong(contractId);
	PyObject* pBlockNo = PyLong_FromLong(blockNo);
	PyObject* pRetValue;
	if (!pContractId || !pBlockNo) {
		fprintf(stderr, "Cannot convert argument\n");
	} else {
		PyTuple_SetItem(pArgs, 0, pContractId);
		PyTuple_SetItem(pArgs, 1, pBlockNo);
		// execute call
		pRetValue = callMethod(pModule, "get_event_txs_since", pArgs);
		if (pRetValue != NULL) {
			// process return value
			PyObject* pHashes = PyList_GetItem(pRetValue, 0);
			PyObject* pInputs = PyList_GetItem(pRetValue, 1);
			PyObject* pFroms = PyList_GetItem(pRetValue, 2);
			PyObject* pValues = PyList_GetItem(pRetValue, 3);
			result.len_list = PyList_Size(pHashes);

			// prepare result
			Hash *tmpHash1 =  (Hash*) malloc(sizeof(Hash) * result.len_list);
			Hash **tmpHash = &tmpHash1;
			int *tmpLenInputs =  (int*) malloc(sizeof(int) * result.len_list);
//			int **tmpLenInputs = &tmpLenInputs1;
			unsigned char *tmpInputs1 = (unsigned char*) malloc(sizeof(unsigned char) * result.len_list);
			unsigned char **tmpInputs = &tmpInputs1;
			EthAddr *tmpFroms1 = (EthAddr*) malloc(sizeof(EthAddr) * result.len_list);
			EthAddr **tmpFroms = &tmpFroms1;
			int *tmpValues =  (int*) malloc(sizeof(int) * result.len_list);
			//int **tmpValues = &tmpValues1;

			for(int i = 0; i < result.len_list; i++) {
				// hashes
				PyObject* pHash = PyList_GetItem(pHashes, i);
				char *sHash = PyBytes_AsString(pHash);
				Hash *hash = (Hash*) malloc(sizeof(Hash));
				memcpy(hash, (Hash*) sHash, sizeof(Hash));
				tmpHash[i] = hash;

				// inputs
				PyObject* pInput = PyList_GetItem(pInputs, i);
				// -> length
				int sLenInput = PyBytes_Size(pInput);
				tmpLenInputs[i] = sLenInput;
				// -> bytes
				char *sInput = PyBytes_AsString(pInput);
				unsigned char *input = (unsigned char*) malloc(sizeof(unsigned char) * sLenInput);
				memcpy(input, (unsigned char*) sInput, sizeof(unsigned char) * sLenInput);
				tmpInputs[i] = &input;

//				printf("entry %d: ", i);
//				printBytesAsHex(sLenInput, input);
//				printf("\n");

				// froms
				PyObject* pFrom = PyList_GetItem(pFroms, i);
				char *sFrom = PyBytes_AsString(pFrom);
				EthAddr *from = (EthAddr*) malloc(sizeof(EthAddr));
				memcpy(from, (EthAddr*) sFrom, sizeof(EthAddr));
				tmpFroms[i] = from;

//				printf("entry %d: ", i);
//				printBytesAsHex(ADDR_SIZE, from);
//				printf("\n");

				// values
				PyObject* pValue = PyList_GetItem(pValues, i);
				int sValue = (int) PyLong_AsLong(pValue);
				tmpValues[i] = sValue;

				Py_DECREF(pHash);
				Py_DECREF(pInput);
				Py_DECREF(pFrom);
				Py_DECREF(pValue);
			}
			result.txhashes = tmpHash;
			result.len_inputs = tmpLenInputs;
			result.inputs = tmpInputs;
			result.froms = tmpFroms;
			result.values = tmpValues;
			return result;
		}
		else {
			PyErr_Print();
			fprintf(stderr,"Call failed\n");
		}
	}
	Py_DECREF(pArgs);
	Py_DECREF(pContractId);
	Py_DECREF(pBlockNo);
	Py_XDECREF(pRetValue);
	return result;
}

struct eventDataEncoded getEventTxsSinceEncoded(PyObject* pModule, int contractId, int blockNo) {
	struct eventDataEncoded result;
	// construct args
	PyObject* pArgs = PyTuple_New(2);
	PyObject* pContractId = PyLong_FromLong(contractId);
	PyObject* pBlockNo = PyLong_FromLong(blockNo);
	PyObject* pRetValue;
	if (!pContractId || !pBlockNo) {
		fprintf(stderr, "Cannot convert argument\n");
	} else {
		PyTuple_SetItem(pArgs, 0, pContractId);
		PyTuple_SetItem(pArgs, 1, pBlockNo);
		// execute call
		pRetValue = callMethod(pModule, "get_event_txs_since_encoded", pArgs);
		if (pRetValue != NULL) {
			// process return value
			result.len_list = PyList_Size(pRetValue);

			// prepare result
			int *tmpLen =  (int*) malloc(sizeof(int) * result.len_list);
			unsigned char *tmpBytesData1 = (unsigned char*) malloc(sizeof(unsigned char) * result.len_list);
			unsigned char **tmpBytesData = &tmpBytesData1;

			for(int i = 0; i < result.len_list; i++) {
				// inputs
				PyObject* pBytesData = PyList_GetItem(pRetValue, i);
				// -> length
				int sLenInput = PyBytes_Size(pBytesData);
				tmpLen[i] = sLenInput;
				// -> bytes
				char *sInput = PyBytes_AsString(pBytesData);
				unsigned char *bytesData = (unsigned char*) malloc(sizeof(unsigned char) * sLenInput);
				memcpy(bytesData, (unsigned char*) sInput, sizeof(unsigned char) * sLenInput);
				tmpBytesData[i] = &bytesData;

//				printf("entry %d: ", i);
//				printBytesAsHex(sLenInput, bytesData);
//				printf("\n");

				Py_DECREF(pBytesData);
			}
			result.len = tmpLen;
			result.bytesData = tmpBytesData;
			return result;
		}
		else {
			PyErr_Print();
			fprintf(stderr,"Call failed\n");
		}
	}
	Py_DECREF(pArgs);
	Py_DECREF(pContractId);
	Py_DECREF(pBlockNo);
	Py_XDECREF(pRetValue);
	return result;
}

void printBytesAsHex(int len, unsigned char* bytes) {
	for(int i = 0; i < len; i++){
	    printf("%02X", bytes[i]);
	}
}

char* testSimpleIntReturn() {
	PyObject* pModule = initPyModule("ctest");
	PyObject* pArgs = PyTuple_New(1);
	PyObject* pValue = PyLong_FromLong(123);
	PyTuple_SetItem(pArgs, 0, pValue);
	PyObject* pRetValue = callMethod(pModule, "test_int", pArgs);
	long longResult = PyLong_AsLong(pRetValue);
	char result[20];
	sprintf(result, "%ld", longResult);
	Py_DECREF(pArgs);
	Py_DECREF(pValue);
	Py_DECREF(pRetValue);
	//destroyPyModule(pModule);  // cannot destroy & re-setup python environment...
	return strdup(result);
}

char* testContractReturn() {
	PyObject* pModule = initPyModule("ctest");
	PyObject* pRetValue = callMethod(pModule, "get_contractreturn", NULL);
	char* result = PyUnicode_AsUTF8(pRetValue);
	Py_DECREF(pRetValue);
	destroyPyModule(pModule);
	return strdup(result);
}
