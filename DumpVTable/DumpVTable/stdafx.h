#pragma once

#include "targetver.h"


// C/C++ standard headers
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <fstream>

// Other external headers
// Windows headers
#include <tchar.h>
#include <objbase.h>
#include <TlHelp32.h>
#include <Strsafe.h>
#include <Dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")

// Original headers


////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//


////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//


////////////////////////////////////////////////////////////////////////////////
//
// types
//


////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//


////////////////////////////////////////////////////////////////////////////////
//
// variables
//


////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

template<class T> inline
std::unique_ptr<T> make_unique_ptr(
    T* p)
{
    return std::unique_ptr<T>(p);
}


template<class T, class D> inline
std::unique_ptr<T, D> make_unique_ptr(
    T* p,
    D d = D())
{
    return std::unique_ptr<T, D>(p, std::forward<D>(d));
}


template <typename T1, typename T2> inline
bool is_in_range(
    T1 Value,
    T2 Min,
    T2 Max)
{
    assert(Min <= Max);
    return (Min <= Value) && (Value <= Max);
}

