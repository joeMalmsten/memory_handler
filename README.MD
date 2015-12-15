To integrate the memory debugger into the program simply include the cpp and .h 
to your project and include the .h into any relevant files.
In the event of a leak the proper symbols are generated, the ptr address, modbase, 
file name, line number, and stack address are presented in “leaks.log” for every 
leak. In the event of a heap bug a break point is enabled at the offending area. 