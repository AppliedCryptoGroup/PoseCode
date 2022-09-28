#ifndef PYTHONWRAPPER_H_
#define PYTHONWRAPPER_H_

#include <Python.h>

PyObject* initPyModule(char* moduleName);
int destroyPyModule(PyObject* pModule);
PyObject* callMethod(PyObject* pModule, char* methodName, PyObject* pArgs);

#endif /* PYTHONWRAPPER_H_ */
