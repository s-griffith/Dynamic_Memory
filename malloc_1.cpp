#include <unistd.h>

static const int MAX_SIZE = 100000000;

void* smalloc(size_t size)
{
    if (size == 0 || size > MAX_SIZE) {
        return nullptr;
    }
    void* section = sbrk(size);
    if (section == (void*)(-1)) {
        return nullptr;
    }
    return section;
}

