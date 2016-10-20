#!/usr/bin/env python
# coding=utf-8
################################################################################
#
# Description: Grammar based generation/fuzzer
#
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
import argparse
import logging
import os
import sys

from avalanche import Grammar, GenerationError, IntegrityError, ParseError


log = logging.getLogger("linter") # pylint: disable=invalid-name


if sys.version_info.major == 2:
    # pylint: disable=redefined-builtin,invalid-name
    str = unicode


def main():

    logging.basicConfig(level=logging.INFO)
    if bool(os.getenv("DEBUG")):
        logging.getLogger().setLevel(logging.DEBUG)

    argp = argparse.ArgumentParser(description="Generate a testcase from a grammar")
    argp.add_argument("input", type=argparse.FileType('r'), help="Input grammar definition")
    argp.add_argument("-f", "--function", action="append", nargs=2, default=[],
                      help="Function used in the grammar (eg. -f filter lambda x:x.replace('x','y')")
    args = argp.parse_args()
    args.function = {func: eval(defn) for (func, defn) in args.function}
    g = Grammar(args.input, **args.function)

    for sym in g.symtab.values():
        # check for direct recursion
        if "[" not in sym.name:
            children = set() # names of all non-implicit children
            togo = sym.children()
            while togo:
                child = togo.pop()
                if "[" in child: # implicit symbol, keep going
                    togo |= g.symtab[child].children()
                    togo -= children
                else:
                    children.add(child)
            if sym.name in children:
                log.info("%s is directly recursive", sym.name)


if __name__ == "__main__":
    main()

