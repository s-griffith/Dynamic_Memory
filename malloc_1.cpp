#include <unistd.h>

void* smalloc(size_t size)
{
    if (size == 0 || size > 100000000) {
        return nullptr;
    }
    void* section = sbrk(size);
    if (section == (void*)(-1)) {
        return nullptr;
    }
    return section;
}

