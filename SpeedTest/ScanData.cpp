#include "ScanData.h"


const size_t ScanData::hexTable[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

ScanData::ScanData(size_t size)
{
    this->size = size;
    this->data = new unsigned char[size];
}

ScanData::ScanData(std::string input) {
	data = new unsigned char[input.size()];
	size_t index = 0;

    std::string::iterator end_pos = std::remove(input.begin(), input.end(), ' ');
    input.erase(end_pos, input.end()); //"FF0012?3B..."

    for (int x = 0, i = 0; i < input.size(); i += 2, x += 1)
    {
        size++;
        if (input[i] == '?') {
            data[x] = '?';
            i--; //DECREMENT!
        }
        else { // 'A' - '0' = 17 ... we want 10 instead
            data[x] = (hexTable[toupper(input[i]) - '0'] << 4 | hexTable[toupper(input[i + 1]) - '0']);
        } //1100 or 0011 = 1111
    }

}

ScanData::~ScanData()
{
	delete[] data;
}

void ScanData::print() {
    for (size_t i = 0; i < size; ++i)
    {
        printf_s("0x%02x ", data[i]);
    }
    printf_s("\n");
}
