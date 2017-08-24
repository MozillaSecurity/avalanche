# coding=utf-8
# pylint: disable=missing-docstring
################################################################################
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
################################################################################

from __future__ import unicode_literals
import bisect


class SparseList(object):
    """List-like numeric array type which supports sparse ranges.
       Maintains sorted order, and supports indexing within sparse ranges.
       Ranges cannot overlap (raises ValueError).
    """
    def __init__(self, copy=None):
        if copy is None:
            self.clear()
        else:
            self._data = copy._data
            self._len = copy._len

    def add(self, a, b=None):
        """
        Add range (a,b) inclusive. If b is not specified, default to (a,a).
        """
        if b is None:
            b = a
        elif b < a:
            raise ValueError("Only forward intervals are supported (a <= b)")
        insert = bisect.bisect_left(self._data, [a])
        # check before for conflict
        if insert and a <= self._data[insert - 1][1]:
            raise ValueError("%d is already present in the list" % a)
        # check after for conflict
        if insert < len(self._data) and b >= self._data[insert][0]:
            raise ValueError("%d is already present in the list" % b)
        # check for pre-optimize
        pre = insert and a == self._data[insert - 1][1] + 1
        # check for post optimize
        post = insert < len(self._data) and b + 1 == self._data[insert][0]
        if pre and post:
            self._data[insert - 1][1] = self._data[insert][1]
            self._data.pop(insert)
        elif pre:
            self._data[insert - 1][1] = b
        elif post:
            self._data[insert][0] = a
        else:
            self._data.insert(insert, [a, b])
        self._len += b - a + 1

    def remove(self, a, b=None):
        """
        Remove range (a,b) inclusive. If b is not specified, default to (a,a).
        No error is raised if (a,b) and self hav no overlap.
        """
        if b is None:
            b = a
        if b < a:
            raise ValueError("Only forward intervals are supported (a <= b)")
        ia = bisect.bisect_left(self._data, [a])
        ib = bisect.bisect_left(self._data, [b])
        # move a if needed
        if ia and a <= self._data[ia - 1][1]:
            #a is actually in the range before ia
            ia -= 1
        elif ia != len(self._data) and a < self._data[ia][0]:
            a = self._data[ia][0]
        if ia == len(self._data):
            return
        ahead = bool(self._data[ia][0] == a)
        # move b if needed
        if ib and b <= self._data[ib - 1][1]:
            #b is actually in the range before ib
            ib -= 1
        elif ib and b > self._data[ib - 1][1] and ib != len(self._data) and b < self._data[ib][0]:
            b = self._data[ib - 1][1]
            ib -= 1
        if b < a:
            return
        btail = bool(self._data[ib][1] == b)
        # do the deletions
        if ahead and btail:
            # delete whole range
            self._len -= sum((j - i + 1) for (i, j) in self._data[ia:ib + 1])
            del self._data[ia:ib + 1]
        elif btail:
            # modify ia
            self._len -= self._data[ia][1] - a + 1 + sum((j - i + 1) for (i, j) in self._data[ia + 1:ib + 1])
            self._data[ia][1] = a - 1
            del self._data[ia + 1:ib + 1]
        elif ahead:
            # modify ib
            self._len -= b - self._data[ib][0] + 1 + sum((j - i + 1) for (i, j) in self._data[ia:ib])
            self._data[ib][0] = b + 1
            del self._data[ia:ib]
        elif ia == ib:
            new = [b + 1, self._data[ib][1]]
            self._len -= self._data[ib][1] - a + 1
            self._data[ib][1] = a - 1
            self.add(*new)
        else:
            self._len -= b - self._data[ib][0] + self._data[ia][1] - a + 2
            self._len -= sum((j - i + 1) for (i, j) in self._data[ia + 1:ib])
            self._data[ia][1] = a - 1
            self._data[ib][0] = b + 1
            del self._data[ia + 1:ib]

    def clear(self):
        self._len = 0
        self._data = []

    def __isub__(self, other):
        for (a, b) in other._data:
            self.remove(a, b)
        return self

    def __len__(self):
        return self._len

    def __getitem__(self, key):
        if key >= len(self) or key < 0:
            [][0] # raise IndexError
        for a, b in self._data:
            len_ = b - a + 1
            if key < len_:
                return a + key
            key -= len_
