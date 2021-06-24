#pragma once

#ifdef _DEBUG
#include <fstream>
#define LOG(x)	do {std::fstream f("LOG.txt", std::ios::app); f << __FILE__ << " : " << __LINE__ << " - " << x << std::endl; f.close();} while(0)
#define LOG_ERROR(x, y) do {std::fstream f("LOG.txt", std::ios::app); f << __FILE__ << " : " << __LINE__ << " - " << x << " - 0x" << std::hex << y <<  std::endl; f.close();} while(0) 
#define EXCEPT(x) std::runtime_error(x)
#else
#define LOG(x)	__LINE__
#define EXCEPT(x)	std::runtime_error(std::to_string(__LINE__))
#define LOG_ERROR(x, y) (void*)0
#endif