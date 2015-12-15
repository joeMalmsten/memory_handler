///////////////////////////////////////////////////////////////////////////////////////////////////
//   Filename: dbg_helper.cpp
//     Author: Joseph Malmsten
//    Purpose: replaces new and delete with my own implementations used to watch over memory
///////////////////////////////////////////////////////////////////////////////////////////////////
#include "dbg_helper.h"

memory_overseer dbugger;

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: memory_overseer()
//  Purpose: constructor
///////////////////////////////////////////////////////////////////////////////////////////////////
memory_overseer::memory_overseer(){
	DWORD  error;
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

	//get a handle to the current process
	hProcess = GetCurrentProcess();

	//if the symbols didn't initialize print out an error
	if (!SymInitialize(hProcess, NULL, true))
	{
		// SymInitialize failed
		error = GetLastError();
		printf("SymInitialize returned error : %d\n", error);
		//return FALSE;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: ~memory_overseer()
//  Purpose: destructor
///////////////////////////////////////////////////////////////////////////////////////////////////
memory_overseer::~memory_overseer(){
	//if there were leaks created as we are destructing the memory overseer print out every leak to the user in a file
	if(!leak_symbols.empty()){
		//convert the symbols to the proper information we can give the user
		convert_symbols();
		Symbol_list::iterator walker_ = symbols.begin();
		FILE * myfile = fopen ("leaks.log","w");
		while(walker_ != symbols.end()){
			
			if (myfile)
			{
				fprintf(myfile, "Symbol Generated from address 0x%08x at ModBase 0x%08x\n", (intptr_t)(walker_->info_->Address), (intptr_t)(walker_->info_->ModBase));
			    fprintf(myfile, "file name: %s \nline number: %d \naddress: 0x%08x\n", walker_->line_.FileName, walker_->line_.LineNumber, (intptr_t)(walker_->line_.Address));		
				fprintf(myfile, "\n\n");
			}
			//

			++walker_;
		}
		//close the file we have been writing to
		if(myfile)
			fclose(myfile);
		
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: convert_symbols()
//  Purpose: converts the symbols from the addresses gained
///////////////////////////////////////////////////////////////////////////////////////////////////
void memory_overseer::convert_symbols(void){
	DWORD64  dwDisplacement = 0;
	DWORD64  dwAddress;


	//for every leak symbol we have lets convert it
	Leak_list::iterator walker_ = leak_symbols.begin();
	while(walker_ != leak_symbols.end()){
		dwAddress = (intptr_t)(walker_->leak_return);
		symbol_info temp;

		//set a buffer to the symbol size and set the symbol into variable up
		char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
		temp.info_ = (PSYMBOL_INFO)buffer;
		temp.info_->SizeOfStruct = sizeof(SYMBOL_INFO);
		temp.info_->MaxNameLen = MAX_SYM_NAME;

		//get the symbols from the address and print an error if it fails
		if (SymFromAddr(hProcess, dwAddress, &dwDisplacement, temp.info_)){

			//symbols.push_back(pSymbol);
			//printf("Symbol: address = 0x%08x, modbase = 0x%08x\n", (intptr_t)(temp.info_->Address), (intptr_t)(temp.info_->ModBase));
		}
		else{
			// SymFromAddr failed
			DWORD error = GetLastError();
			printf("SymFromAddr returned error : %d\n", error);
		}

		DWORD  Displacement = 0;

		SymSetOptions(SYMOPT_LOAD_LINES);

		temp.line_.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

		//get the line from the address also, and print an error if it failed
		if (SymGetLineFromAddr64(hProcess, dwAddress, &Displacement, &temp.line_))
		{
			// SymGetLineFromAddr64 returned success
		}
		else
		{
			// SymGetLineFromAddr64 failed
			DWORD error = GetLastError();
			printf("SymGetLineFromAddr64 returned error : %d\n", error);
		}
		//save the symbol
		symbols.push_back(temp);
		++walker_;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: find()
//  Purpose: finds an item on the list
//   Params: ptr - a void pointer to the address
///////////////////////////////////////////////////////////////////////////////////////////////////
Leak_list::iterator memory_overseer::find(void * ptr){
	Leak_list::iterator temp = leak_symbols.begin();
	while(temp != leak_symbols.end()){
		if(temp->ptr == ptr)
			return temp;
		temp++;
	}
	return temp;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: PageAlignedAllocate()
//  Purpose: makes allocations that are aligned to a page for buffer over/under flow
//   Params: size - the size of the memory being allocated
///////////////////////////////////////////////////////////////////////////////////////////////////
void * PageAlignedAllocate(size_t size){
	unsigned count = 2;
	while(size > 4096 * (count - 1))
		++count;
	void * p = VirtualAlloc(0, 4096 * count, MEM_RESERVE, PAGE_NOACCESS);
	p = VirtualAlloc(p, 4096 * (count - 1), MEM_COMMIT, PAGE_READWRITE);
	return (unsigned char*)p + (4096 * (count - 1) - size);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: new()
//  Purpose: makes allocations with memory checking
//   Params: size - the size of the memory being allocated
///////////////////////////////////////////////////////////////////////////////////////////////////
void * operator new(size_t size) throw (std::bad_alloc){
	//push back the return address to we can make a stack trace
	dbugger.stack_trace.push_back(_ReturnAddress());

	//allocate the memory, if we can not allocate throw an error
	void * ptr = PageAlignedAllocate(size);
	if(!ptr){
		static const std::bad_alloc nomem;
		throw nomem;
	}

	//set the leak symbol for the memory and push it back to the list of allocations
	leak_symbol temp;
	temp.ptr = ptr;
	temp.size_ = size;
	temp.leak_return = _ReturnAddress();
	dbugger.leak_symbols.push_back(temp);

	//return the memory
	return ptr;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: new()
//  Purpose: makes allocations with memory checking
//   Params: size - the size of the memory being allocated
//      nothrow_t - makes it to new will not throw an error, but simply return a NULL pointer
///////////////////////////////////////////////////////////////////////////////////////////////////
void * operator new(size_t size, const std::nothrow_t&) throw (){
	dbugger.stack_trace.push_back(_ReturnAddress());
	void * ptr = PageAlignedAllocate(size);

	leak_symbol temp;
	temp.ptr = ptr;
	temp.size_ = size;
	temp.leak_return = _ReturnAddress();
	dbugger.leak_symbols.push_back(temp);

	return ptr;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: new[]()
//  Purpose: makes allocations with memory checking for arrays
//   Params: size - the size of the memory being allocated
///////////////////////////////////////////////////////////////////////////////////////////////////
void * operator new[](size_t size) throw (std::bad_alloc){
	void * temp_ = operator new(size);
	Leak_list::iterator walker = dbugger.find(temp_);
	walker->array_ = true;
	return temp_;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: new[]()
//  Purpose: makes allocations with memory checking
//   Params: size - the size of the memory being allocated
//      nothrow_t - makes it to new will not throw an error, but simply return a NULL pointer
///////////////////////////////////////////////////////////////////////////////////////////////////
void * operator new[](size_t size, const std::nothrow_t & temp) throw (){
	void * temp_ = operator new(size, temp);
	Leak_list::iterator walker = dbugger.find(temp_);
	walker->array_ = true;
	return temp_;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: delete()
//  Purpose: deletes allocated memory
//   Params: ptr - the memory being deleted
///////////////////////////////////////////////////////////////////////////////////////////////////
void operator delete(void * ptr) throw () {

	//push back the return address so we can make a stack trace
	dbugger.stack_trace.push_back(_ReturnAddress());
	if (!ptr) { return; }

	//look for the memory on the list of allocations, if it's not there then we have a bad pointer
	Leak_list::iterator temp = dbugger.find(ptr);
	assert((temp != dbugger.leak_symbols.end()) && "Bad pointer delete!");
	assert(!temp->array_ && "Mismatch new/delete[]");

	//free the memory and decommit it, then erase the memory from the leak list
	VirtualFree(ptr, temp->size_, MEM_DECOMMIT);
	dbugger.leak_symbols.erase(temp);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: delete()
//  Purpose: deletes allocated memory
//   Params: ptr - the memory being deleted
//      nothrow_t - makes it to delete will not throw an error
///////////////////////////////////////////////////////////////////////////////////////////////////
void operator delete(void * ptr, const std::nothrow_t&) throw (){
	dbugger.stack_trace.push_back(_ReturnAddress());
	if (!ptr) { return; }

	Leak_list::iterator temp = dbugger.find(ptr);
	assert((temp != dbugger.leak_symbols.end()) && "Bad pointer delete!");
	assert(!temp->array_ && "Mismatch new/delete[]");

	VirtualFree(ptr, temp->size_, MEM_DECOMMIT);
	dbugger.leak_symbols.erase(temp);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: delete[]()
//  Purpose: deletes allocated memory, for arrays
//   Params: ptr - the memory being deleted
///////////////////////////////////////////////////////////////////////////////////////////////////
void operator delete[](void * ptr) throw (){

	Leak_list::iterator temp = dbugger.find(ptr);
	assert((temp != dbugger.leak_symbols.end()) && "Bad pointer delete!");
	assert(temp->array_ && "Mismatch new/delete[]");
	temp->array_ = false;

	operator delete(ptr);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Function: delete[]()
//  Purpose: deletes allocated memory, for arrays
//   Params: ptr - the memory being deleted
//      nothrow_t - makes it to delete will not throw an error
///////////////////////////////////////////////////////////////////////////////////////////////////
void operator delete[](void * ptr, const std::nothrow_t& temp) throw (){
	Leak_list::iterator temp_ = dbugger.find(ptr);
	assert((temp_ != dbugger.leak_symbols.end()) && "Bad pointer delete!");
	assert(temp_->array_ && "Mismatch new/delete[]");
	temp_->array_ = false;

	operator delete(ptr, temp);
}