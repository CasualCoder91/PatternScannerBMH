#pragma once

#include <string>

class ScanData
{
private:
	static const size_t hexTable[];

public:
	unsigned char* data; //byte array
	size_t size = 0;

	ScanData(const std::string input);
	ScanData(size_t size);
	~ScanData();

	void print();

};

