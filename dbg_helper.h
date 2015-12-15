///////////////////////////////////////////////////////////////////////////////////////////////////
//   Filename: dbg_helper.h
//     Author: Joseph Malmsten
//    Purpose: replaces new and delete with my own implementations used to watch over memory
//    
//     README: To integrate the memory debugger into the program simply include the cpp and .h 
//             to your project and include the .h into any relevant files.
//             
///////////////////////////////////////////////////////////////////////////////////////////////////
#include "mallocator.h"
#include <windows.h>
#include <new>

#include <intrin.h>
#include <Dbghelp.h>
#pragma comment( lib, "Dbghelp.lib" )

//#include <iostream>
//#include <fstream>

#include <vector>
#include <algorithm>
#include <cassert>


//lists needed to keep track of symbols and leaks
typedef std::vector<void*, Mallocator<void*> > Alloc_list;
typedef std::vector<class symbol_info, Mallocator<void*> > Symbol_list;
typedef std::vector<class leak_symbol, Mallocator<void*> > Leak_list;

//my definitions for the overloaded new and delete
void * operator new(size_t size) throw (std::bad_alloc);
void * operator new(size_t size, const std::nothrow_t&) throw ();
void * operator new[](size_t size) throw (std::bad_alloc);
void * operator new[](size_t size, const std::nothrow_t&) throw ();
void operator delete(void * ptr) throw ();
void operator delete(void * ptr, const std::nothrow_t&) throw ();
void operator delete[](void * ptr) throw ();
void operator delete[](void * ptr, const std::nothrow_t&) throw ();

//a class containing the symbol information
class symbol_info{
public:
	PSYMBOL_INFO info_;
	IMAGEHLP_LINE64 line_;
};

//a class containing information for a leak
class leak_symbol{
public:
	leak_symbol():array_(false){};
	void * leak_return;
	void * ptr;
	bool array_;
	unsigned size_;
};
	
//this class contains everything needed to oversee the memory for the program
class memory_overseer{
public:
	memory_overseer();
	~memory_overseer();

	HANDLE hProcess;

	//a list of the leaks
	Leak_list leak_symbols;
	Leak_list::iterator find(void * ptr);

	//a lit of allocations
	Alloc_list stack_trace;

	//a list of symbols
	Symbol_list symbols;

	//convert addresses into symbols
	void convert_symbols(void);
};

	