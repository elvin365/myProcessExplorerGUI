#include "stllist.h"

void moveIterator(list <info> ::iterator& iter, int index)
{
    iter= ::procInfoList.begin();
    for (int i=0; i<index; i++)
        iter++;
}
