#include "PythonWrapper.h"

PyObject* initPyModule(char* moduleName) {
	Py_Initialize();
	// set paths so python knows where to look for *.py files
	PyObject *sys = PyImport_ImportModule("sys");
	PyObject *path = PyObject_GetAttrString(sys, "path");
	PyList_Append(path, PyUnicode_FromString("."));
	Py_DECREF(sys);
	Py_DECREF(path);

	PyObject *pName = PyUnicode_FromString(moduleName);
	PyObject *pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (pModule == NULL) {
		PyErr_Print();
		fprintf(stderr, "Failed to load module \n");
		return NULL;
	}
	return pModule;
}

int destroyPyModule(PyObject* pModule) {
	Py_DECREF(pModule);
	if (Py_FinalizeEx() < 0) {
		return 120;
	}
	return 0;
}

PyObject* callMethod(PyObject* pModule, char* methodName, PyObject* pArgs) {
	PyObject* pFunc = PyObject_GetAttrString(pModule, methodName);
	if (pFunc && PyCallable_Check(pFunc)) {
		PyObject* pValue = PyObject_CallObject(pFunc, pArgs);
		if (pValue != NULL) {
			Py_DECREF(pFunc);
			return pValue;
		}
		else {
			Py_DECREF(pFunc);
			PyErr_Print();
			fprintf(stderr,"Call failed\n");
			return 1;
		}
	} else {
		if (PyErr_Occurred())
			PyErr_Print();
		fprintf(stderr, "Cannot find function \n");
		return NULL;
	}
}
