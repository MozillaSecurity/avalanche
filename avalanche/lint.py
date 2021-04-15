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

from avalanche import Grammar

LOG = logging.getLogger("linter")


if sys.version_info.major == 2:
    # pylint: disable=redefined-builtin,invalid-name
    str = unicode


def main():

    logging.basicConfig(level=logging.INFO)
    if bool(os.getenv("DEBUG")):
        logging.getLogger().setLevel(logging.DEBUG)

    argp = argparse.ArgumentParser(description="Generate a testcase from a grammar")
    argp.add_argument(
        "input", type=argparse.FileType("r"), help="Input grammar definition"
    )
    argp.add_argument(
        "-f",
        "--function",
        action="append",
        nargs=2,
        default=[],
        help="Function used in the grammar (eg. -f filter lambda x:x.replace('x','y')",
    )
    args = argp.parse_args()
    args.function = {func: eval(defn) for (func, defn) in args.function}
    gmr = Grammar(args.input, **args.function)

    children = {}
    for sym in gmr.symtab.values():
        # capture children of non-implicit symbols (which includes recursing into implicit symbols)
        if "[" not in sym.name:
            children[sym.name] = set()
            togo = sym.children()
            while togo:
                child = togo.pop()
                if "[" in child:  # implicit symbol, keep going
                    togo |= gmr.symtab[child].children()
                    togo -= children[sym.name]
                else:
                    children[sym.name].add(child)

    # check for recursion
    for sym_name, sym_children in children.items():
        if sym_name in sym_children:
            LOG.info("%s is directly recursive", sym_name)
            continue
        # `issue` is a map of descendents (of any degree) to shortest ancestry from this sym_name
        issue = {child_name: [] for child_name in sym_children}
        done = set()
        while issue:
            child_name = list(issue.keys())[0]
            child_backtrace = issue.pop(child_name) + [child_name]
            done.add(child_name)
            for grandchild_name in children[child_name]:
                if grandchild_name in done | set(issue):
                    continue
                if grandchild_name == sym_name:
                    LOG.info(
                        "%s is recursive through %r (%d degree)",
                        sym_name,
                        child_backtrace,
                        len(child_backtrace),
                    )
                    issue = None
                    break
                issue[grandchild_name] = child_backtrace


if __name__ == "__main__":
    main()
