//#include "interface.h"
#include <stdio.h>
#include <dlfcn.h>

int main() 
{
  printf("Unit test \n");
  void* handle = dlopen("./libmycls.so", RTLD_LAZY);
  void (*interface)();
  void (*createCLS)();

  interface = dlsym(handle, "interface");
  createCLS = dlsym(handle, "createCLS");

  createCLS();

  interface();

  dlclose(handle);
  return 0;
}
