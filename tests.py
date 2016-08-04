################################################################################
# coding=utf-8
# pylint: disable=invalid-name,missing-docstring
#
# Description: Avalanche tests
#
# Portions Copyright 2014 BlackBerry Limited
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
import io
import logging as log
import os
import re
import shutil
import sys
import tempfile
import unittest
from avalanche import ChoiceSymbol, Grammar, GenerationError, IntegrityError, ParseError


class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class Backrefs(TestCase):

    def test_0(self):
        "test that basic backreferences work, generate a single digit and reference to it, make sure they match"
        gmr = Grammar("root  (/[0-9]/) @1")
        for _ in range(100):
            x1, x2 = gmr.generate()
            self.assertEqual(x1, x2)

    def test_1(self):
        "negative tests for backreferences, check use without declaration and use before declaration"
        with self.assertRaisesRegex(IntegrityError, r'^Invalid backreference'):
            Grammar("root  'a' @1")
        with self.assertRaisesRegex(IntegrityError, r'^Invalid backreference'):
            Grammar("root  'a' @1 ('b')")

    def test_2(self):
        "test that backreferences work in function args"
        gmr = Grammar("root  (/[0-9]/) rndint((/[0-9]/), @2) @2 @1")
        n_same = 0
        for _ in range(100):
            x1, y1, y2, x2 = gmr.generate()
            self.assertEqual(x1, x2)
            self.assertEqual(y1, y2)
            if x1 == y1:
                n_same += 1
        self.assertLess(n_same, 100)

    def test_3(self):
        "test that backreferences on different lines don't get messed up"
        gmr = Grammar("root  (/[0-9]/) y @1\n"
                      "y     (/[0-9]/) @1")
        n_same = 0
        for _ in range(100):
            x1, y1, y2, x2 = gmr.generate()
            self.assertEqual(x1, x2)
            self.assertEqual(y1, y2)
            if x1 == y1:
                n_same += 1
        self.assertLess(n_same, 100)


class Binary(TestCase):

    def test_bin(self):
        "test binary strings"
        gmr = Grammar("root x'68656c6c6f2c20776f726c6400'")
        self.assertEqual(gmr.generate(), b"hello, world\0")

    def test_unicode(self):
        "test for unicode in a binary string"
        with self.assertRaisesRegex(ParseError, r'^Invalid hex string'):
            Grammar("root x'000ü'")


class Choices(TestCase):

    def balanced_choice(self, grammar, values, iters=2000):
        result = {value: 0 for value in values}
        gmr = Grammar(grammar)
        for _ in range(iters):
            result[gmr.generate()] += 1
        log.debug("balanced_choice(%s) -> %s", values, result)
        for value in result.values():
            self.assertAlmostEqual(float(value)/iters, 1.0/len(values), delta=0.04)

    def test_repeat_star(self):
        "test for choice balance in a repeat sample"
        self.balanced_choice("root a<*>\n"
                             "a 1 'a'\n"
                             "  1 'b'",
                             ["ab", "ba"])

    def test_wchoice(self):
        "tests for choices with different weights"
        iters = 2500
        self.balanced_choice("root 1 '1'\n"
                             "     1 '2'\n"
                             "     1 '3'",
                             ['1', '2', '3'])
        gmr = Grammar("root .5 '1'\n"
                      "     1  '2'\n"
                      "     .5 '3'")
        result = {1: 0, 2: 0, 3: 0}
        for _ in range(iters):
            result[int(gmr.generate())] += 1
        self.assertAlmostEqual(float(result[1])/iters, 0.25, delta=.04)
        self.assertAlmostEqual(float(result[2])/iters, 0.5, delta=.04)
        self.assertAlmostEqual(float(result[3])/iters, 0.25, delta=.04)
        gmr = Grammar("root .3 '1'\n"
                      "     .1 '2'\n"
                      "     .1 '3'")
        result = {1: 0, 2: 0, 3: 0}
        for _ in range(iters):
            result[int(gmr.generate())] += 1
        self.assertAlmostEqual(float(result[1])/iters, 0.6, delta=.04)
        self.assertAlmostEqual(float(result[2])/iters, 0.2, delta=.04)
        self.assertAlmostEqual(float(result[3])/iters, 0.2, delta=.04)
        gmr = Grammar("root .25 '1'\n"
                      "     .25 '2'\n"
                      "     1   '3'")
        result = {1: 0, 2: 0, 3: 0}
        for _ in range(iters):
            result[int(gmr.generate())] += 1
        self.assertAlmostEqual(float(result[1])/iters, 1.0/6, delta=.04)
        self.assertAlmostEqual(float(result[2])/iters, 1.0/6, delta=.04)
        self.assertAlmostEqual(float(result[3])/iters, 2.0/3, delta=.04)

    def test_plus(self):
        "test choice includes with '+'"
        self.balanced_choice("var     1 'a'\n"
                             "        1 'b'\n"
                             "        1 'c'\n"
                             "root    + var\n"
                             "        1 'd'",
                             ["a", "b", "c", "d"])
        with self.assertRaisesRegex(IntegrityError, r'^Expecting exactly one ChoiceSymbol'):
            Grammar("root + 'a'")
        self.balanced_choice("var     1 'a'\n"
                             "        1 'b'\n"
                             "        1 'c'\n"
                             "root    + 'A' var\n"
                             "        1 'd'",
                             ['Aa', 'Ab', 'Ac', 'd'])
        with self.assertRaisesRegex(IntegrityError, r"^Can't resolve weight for '\+'"):
            Grammar("root + a\n"
                    "a + root\n"
                    "  1 'a'")

    def test_plus_text(self):
        "test that '+' works with text appended to the choice symbol"
        iters = 2000
        gmr = Grammar("root a\n"
                      "a + (b 'X')\n"
                      "  1 'c'\n"
                      "b 1 'a'\n"
                      "  1 'b'")
        result = {"c": 0, "aX": 0, "bX": 0}
        for _ in range(iters):
            result[gmr.generate()] += 1
        for value in result.values():
            self.assertAlmostEqual(float(value)/iters, 1.0/3, delta=0.04)

    def test_nested_choice_weight(self):
        "test that weights in a nested choice are ignored. has gone wrong before."
        gmr = Grammar("root a {1000}\n"
                      "b .9 'b'\n"
                      "a .1 'a'\n"
                      "  .1 b")
        output = gmr.generate()
        a_count = len([c for c in output if c == 'a'])
        b_count = len(output) - a_count
        self.assertAlmostEqual(a_count, b_count, delta=len(output) * 0.2)


class Concats(TestCase):

    def test_impl_concat(self):
        "test that implicit concats work"
        gmr = Grammar("root ('a' 'b') 'c'")
        self.assertEqual(gmr.generate(), "abc")
        gmr = Grammar("root 'a' ('b') 'c'")
        self.assertEqual(gmr.generate(), "abc")
        gmr = Grammar("root 'a' ('b' 'c')")
        self.assertEqual(gmr.generate(), "abc")


class Functions(TestCase):

    def test_funcs(self):
        "test that python filter functions work"
        gram = "root            func{100}\n" \
               "func    1       'z' zero(nuvar) '\\n'\n" \
               "        1       'a' alpha(alvar , '*,' rep) '\\n'\n" \
               "        1       nuvar '\\n'\n" \
               "        1       alvar '\\n'\n" \
               "nuvar           'n' /[0-9]{6}/\n" \
               "alvar           'c' /[a-z]{6}/\n" \
               "rep             /[0-9]/"
        def zero(inp):
            return inp.replace("0", "z")
        def alpha(inp, rep):
            return "%s/%s" % (rep, inp.replace("a", rep))
        gmr = Grammar(gram, zero=zero, alpha=alpha)
        for line in gmr.generate().splitlines():
            if line.startswith("zn"):
                self.assertRegex(line[2:], r"^[1-9z]{6}$")
            elif line.startswith("a"):
                self.assertRegex(line[1:], r"^(\*,[0-9])/c(\1|[b-z]){6}$")
            elif line.startswith("n"):
                self.assertRegex(line[1:], r"^[0-9]{6}$")
            elif line.startswith("c"):
                self.assertRegex(line[1:], r"^[a-z]{6}$")
            else:
                raise Exception("unexpected line: %s" % line)

    def test_builtin_rndint(self):
        "test the built-in rndint function"
        gmr = Grammar("root  rndint(1,10)")
        result = {i: 0 for i in range(1, 11)}
        for _ in range(1000):
            value = int(gmr.generate())
            result[value] += 1
        for value in result.values():
            self.assertAlmostEqual(value, 100, delta=30)
        with self.assertRaisesRegex(GenerationError, r'^ValueError'):
            Grammar('root  rndint(2,1)').generate()

    def test_builtin_rndflt(self):
        "test the built-in rndflt function"
        gmr = Grammar("root  rndflt(0,10)")
        result = {(i / 2.0): 0 for i in range(0, 20)}
        for _ in range(2000):
            value = float(gmr.generate())
            # count buckets in increments of 0.5
            result[int(value * 2) / 2.0] += 1
        for value in result.values():
            self.assertAlmostEqual(value, 100, delta=50)
        gmr = Grammar("root  rndflt(0.1,1)")
        result = {(i / 10.0): 0 for i in range(1, 10)}
        for _ in range(1000):
            value = float(gmr.generate())
            # count buckets in increments of 0.1
            result[int(value * 10) / 10.0] += 1
        for value in result.values():
            self.assertAlmostEqual(value, 111, delta=50)

    def test_builtin_rndpow2(self):
        "test the built-in rndpow2 function"
        gmr = Grammar("root  rndpow2(2,0)")
        result = {1: 0, 2: 0, 4: 0}
        for _ in range(300):
            value = int(gmr.generate())
            result[value] += 1
        for value in result.values():
            self.assertGreater(value, 0)
        gmr = Grammar("root  rndpow2(2,1)")
        result = {i: 0 for i in range(0, 6)}
        for _ in range(600):
            value = int(gmr.generate())
            result[value] += 1
        for value in result.values():
            self.assertGreater(value, 0)
        with self.assertRaisesRegex(GenerationError, r'^ValueError'):
            Grammar('root  rndpow2(-1,0)').generate()


class Imports(TestCase):

    def setUp(self):
        self.tmpd = tempfile.mkdtemp(prefix='gmrtesttmp')
        self.cwd = os.getcwd()
        os.chdir(self.tmpd)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmpd)

    def test_import_reserved(self):
        "test that 'import' is not allowed to be redefined"
        with self.assertRaisesRegex(ParseError, r"^'import' is a reserved name"):
            Grammar('import blah "blah.gmr"')

    def test_unused_import(self):
        "test for unused imports"
        open('blah.gmr', 'w').close()
        with self.assertRaisesRegex(IntegrityError, r'^Unused import'):
            Grammar("root 'a'\n"
                    "unused import('blah.gmr')")

    def test_use_before_import(self):
        "tests for use before import"
        with self.assertRaisesRegex(ParseError, r'^Attempt to use symbol from unknown prefix'):
            Grammar("root a.b")

    def test_notfound_import(self):
        "tests for bad imports"
        with self.assertRaisesRegex(ParseError, r'^Error parsing string'):
            Grammar("a import()")
        with self.assertRaisesRegex(IntegrityError, r'^Could not find imported grammar'):
            Grammar("a import('')")

    def test_simple(self):
        "test that imports work"
        with open('a.gmr', 'w') as fd:
            fd.write('a "A"')
        gmr = Grammar("b import('a.gmr')\n"
                      "root b.a")
        self.assertEqual(gmr.generate(), 'A')

    def test_nested(self):
        "test that circular imports are allowed"
        with open('a.gmr', 'w') as fd:
            fd.write('b import("b.gmr")\n'
                     'root a b.a\n'
                     'a "A"')
        with open('b.gmr', 'w') as fd:
            fd.write('x import("a.gmr")\n'
                     'a @x.a')
        with open('a.gmr') as fd:
            gmr = Grammar(fd)
        self.assertEqual(gmr.generate(), "AA")

    def test_recursive_defn(self):
        "test that infinite recursion is detected across an import"
        with open('b.gmr', 'w') as fd:
            fd.write('b import("b.gmr")\n'
                     'root b.a\n'
                     'a b.a')
        with self.assertRaisesRegex(IntegrityError, r'^Symbol has no paths to termination'):
            with open('b.gmr') as fd:
                Grammar(fd)

    def test_unused_import_sym(self):
        "test that unused symbols in an import are allowed"
        with open('a.gmr', 'w') as fd:
            fd.write('a "A"\n'
                     'b "B"')
        gmr = Grammar('a import("a.gmr")\n'
                      'root a.a')
        self.assertEqual(gmr.generate(), "A")

    def test_imported_choice(self):
        "test that repeat sample works across an import"
        with open('a.gmr', 'w') as fd:
            fd.write('a 1 "A"')
        gmr = Grammar("b import('a.gmr')\n"
                      "root a<*>\n"
                      "a b.a")
        self.assertEqual(gmr.generate(), 'A')


class Inputs(TestCase):

    def test_str(self):
        "test grammar with byte string as input"
        gmr = Grammar(b"root 'a'")
        self.assertEqual(gmr.generate(), 'a')

    def test_binfilelike(self):
        "test grammar with binary file-like object as input"
        infile = io.BytesIO(b'root "a"')
        gmr = Grammar(infile)
        self.assertEqual(gmr.generate(), 'a')

    def test_filelike(self):
        "test grammar with utf-8 file-like object as input"
        infile = io.StringIO('root "a"')
        gmr = Grammar(infile)
        self.assertEqual(gmr.generate(), 'a')

    def test_binfile(self):
        "test grammar with binary file as input"
        with tempfile.NamedTemporaryFile('w+b') as gmrfile:
            gmrfile.write(b'root "a"')
            gmrfile.seek(0)
            gmr = Grammar(gmrfile)
        self.assertEqual(gmr.generate(), 'a')

    def test_file(self):
        "test grammar with utf-8 file as input"
        with tempfile.NamedTemporaryFile('w+') as gmrfile:
            gmrfile.write('root "a"')
            gmrfile.seek(0)
            gmr = Grammar(gmrfile)
        self.assertEqual(gmr.generate(), 'a')


class Parser(TestCase):

    def test_broken(self):
        "test broken lines"
        gmr = Grammar("root 'a' 'b'\\\n"
                      "     'c'")
        self.assertEqual(gmr.generate(), "abc")

    def test_basic(self):
        "test basic grammar features"
        gmr = Grammar("root    ok\n"
                    "ok      '1'")
        self.assertEqual(gmr.generate(), "1")
        gmr = Grammar("root   a\n"
                      "a      '1234' /[a-z]/ b\n"
                      "b      1 c\n"
                      "       1 d\n"
                      "c      'C'\n"
                      "d      'D'")
        result = {"C": 0, "D": 0}
        for _ in range(1000):
            value = gmr.generate()
            self.assertRegex(value, r"^1234[a-z][CD]$")
            result[value[-1]] += 1
        self.assertAlmostEqual(result["C"], 500, delta=50)
        self.assertAlmostEqual(result["D"], 500, delta=50)

    def test_dashname(self):
        "test that dash is allowed in symbol names"
        gmr = Grammar("root a-a\n"
                      "a-a 'a'\n")
        self.assertEqual(gmr.generate(), "a")

    def test_limit(self):
        "test that limit is respected"
        gmr = Grammar("root       foo bar\n"
                      "bar        (@foo bar) {1}\n"
                      "foo        'i0'", limit=10)
        self.assertEqual(len(gmr.generate()), 10)

    def test_altstart(self):
        "test that starting symbols other than 'root' work"
        gmr = Grammar("root a 'B'\n"
                      "a 'A'")
        self.assertEqual(gmr.generate(start='a'), 'A')

    def test_incomplete_sym_defn(self):
        "test incomplete symbol definitions raise ParseError"
        with self.assertRaisesRegex(ParseError, r'^Failed to parse definition.*\(line 2\)'):
            Grammar("root a\n"
                    "a")
        with self.assertRaisesRegex(ParseError, r'^Failed to parse definition.*\(line 2\)'):
            Grammar("root a\n"
                    "a  ")
        # just being mean here
        with self.assertRaisesRegex(ParseError, r'^Failed to parse definition.*\(line 2\)'):
            Grammar("root a\n"
                    "a\r\t")

    def test_recursive_defn(self):
        "test recursive definition"
        with self.assertRaisesRegex(IntegrityError, r'^Symbol has no paths to termination'):
            Grammar("root root")

    def test_unused_sym(self):
        "tests for unused symbols"
        with self.assertRaisesRegex(IntegrityError, r'^Unused symbol:'):
            Grammar('root a\n'
                    'a "A"\n'
                    'b "B"')
        with self.assertRaisesRegex(IntegrityError, r'^Symbol.*used but not defined'):
            Grammar('root + undef')
        with self.assertRaisesRegex(IntegrityError, r'^Unused symbols:'):
            Grammar('root "A"\n'
                    'a b\n'
                    'b a')


class Regexes(TestCase):

    def test_0(self):
        "test for some bad thing tyson did once"
        gmr = Grammar('root   /[0-1]{1}/ "]"')
        self.assertIn(gmr.generate(), ["0]", "1]"])

    def test_1(self):
        "test for invalid range in a regex"
        with self.assertRaisesRegex(ParseError, r'^Empty range in regex'):
            Grammar('root /[+-*]/')


class Repeats(TestCase):

    def test_repeat(self):
        "tests for simple repeats"
        gmr = Grammar('root "A"{1,10}')
        lengths = set()
        for _ in range(2000):
            result = gmr.generate()
            self.assertEqual(len(set(result)), 1)
            self.assertEqual(result[0], "A")
            self.assertIn(len(result), range(1, 11))
            lengths.add(len(result))
        self.assertEqual(len(lengths), 10)
        gmr = Grammar('root ("A" "B" ","){ 0 , 10 } "AB"')
        lengths = set()
        for _ in range(2000):
            result = gmr.generate().split(",")
            self.assertEqual(len(set(result)), 1)
            self.assertEqual(result[0], "AB")
            self.assertIn(len(result), range(1, 12))
            lengths.add(len(result))
        self.assertEqual(len(lengths), 11)

    def test_repeat_sample(self):
        "tests for repeat sample"
        with self.assertRaisesRegex(IntegrityError, r'^Expecting exactly one ChoiceSymbol'):
            Grammar('root "A" <1,10>')
        with self.assertRaisesRegex(IntegrityError, r'^Expecting exactly one ChoiceSymbol'):
            Grammar('root (a a) <1,10>\n'
                    'a 1 "A"')
        gmr = Grammar('root a<1,10>\n'
                      'a 1 "A"')
        for _ in range(100):
            self.assertEqual(gmr.generate(), "A")
        gmr = Grammar('root ("a" a)<1,10>\n'
                      'a 1 "A"')
        for _ in range(100):
            self.assertEqual(gmr.generate(), "aA")
        gmr = Grammar('root a<1,10>\n'
                      'a   "a" b\n'
                      'b 1 "A"')
        for _ in range(100):
            self.assertEqual(gmr.generate(), "aA")
        gmr = Grammar('root a <1,10>\n'
                      'a .9 "A"\n'
                      '  .1 "B"')
        outs = {"A": 0, "B": 0, "BA": 0, "AB": 0}
        for _ in range(1000):
            outs[gmr.generate()] += 1
        self.assertGreater(outs["AB"] + outs["BA"], outs["A"] + outs["B"])
        self.assertGreater(outs["AB"], outs["BA"])
        self.assertGreater(outs["A"], outs["B"])

    def test_maybe(self):
        "tests for '?' shortcut for {0,1}"
        gmr = Grammar('root "A"?')
        lengths = set()
        for _ in range(100):
            result = gmr.generate()
            self.assertIn(result, {"", "A"})
            lengths.add(len(result))
        self.assertEqual(len(lengths), 2)
        gmr = Grammar('root ("A" "B")?')
        lengths = set()
        for _ in range(100):
            result = gmr.generate()
            self.assertIn(result, {"", "AB"})
            lengths.add(len(result))
        self.assertEqual(len(lengths), 2)

    def test_repeat_star(self):
        "tests for '*' as a repeat arg"
        gmr = Grammar("root a<0,*>\n"
                      "a 1 'a'\n"
                      "  1 'b'")
        result = {"ab": 0, "ba": 0, "a": 0, "b": 0, "": 0}
        for _ in range(1000):
            result[gmr.generate()] += 1
        self.assertGreater(result["a"] + result["b"], result["ab"] + result["ba"])
        self.assertGreater(result[""], result["a"] + result["b"])
        with self.assertRaisesRegex(IntegrityError, r'^Expecting exactly one ChoiceSymbol'):
            Grammar("root 'a'{*}")
        with self.assertRaisesRegex(IntegrityError, r'^Expecting exactly one ChoiceSymbol'):
            Grammar("root 'a'<*>")
        with self.assertRaisesRegex(IntegrityError, r'^Invalid range for repeat'):
            Grammar("root a{*,0}\n"
                    "a 1 'a'")
        gmr = Grammar("root a{*}\n"
                    "a 1 'a'\n")
        result = gmr.generate()
        self.assertEqual(len(result), 1)
        self.assertEqual(result, "a")

    def test_tracked_repeatsample(self):
        "test for tracked repeatsample symbols"
        gmr = Grammar("root b<*> @b\n"
                      "a 1 /[0-9]/\n"
                      "b a 'A'")
        for _ in range(100):
            result = gmr.generate()
            self.assertEqual(len(result), 4)
            self.assertEqual(result[:2], result[2:])
        gmr = Grammar("root a<*> @a\n"
                      "a 1 b\n"
                      "b /[0-9]/")
        for _ in range(100):
            result = gmr.generate()
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0], result[1])


class References(TestCase):

    def test_0(self):
        "test for tracked symbol use as a function arg"
        gmr = Grammar("root   id a(b(@id))\n"
                      "id     /[a-z]/\n"
                      , a=lambda x: "a" + x, b=lambda x: "b" + x)
        for _ in range(100):
            result = gmr.generate()
            self.assertEqual(result[0], result[-1])
            self.assertEqual(result[1:-1], "ab")

    def test_1(self):
        "test for tracked symbols"
        gmr = Grammar("root    id '\\n' esc(\"'\" @id \"'\")\n"
                      "id      'id' /[0-9]/",
                      esc=lambda x: re.sub(r"'", "\\'", x))
        for _ in range(100):
            defn, use = gmr.generate().splitlines()
            self.assertRegex(defn, r"^id[0-9]$")
            self.assertEqual(use, "\\'%s\\'" % defn)

    def test_2(self):
        "test for tracked symbols"
        gmr = Grammar("root    id '\\n' esc('not', @id)\n"
                      "id      'id' /[0-9]/",
                      esc=lambda x, y: x)
        defn, use = gmr.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual(use, "not")

    def test_3(self):
        "test for tracked symbols"
        gmr = Grammar("root    esc(id) '\\n' @id\n"
                      "id      'id' /[0-9]/",
                      esc=lambda x: "%s\n%s" % (x, "".join("%02x" % ord(c) for c in x)))
        defn, hexn, use = gmr.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual("".join("%02x" % ord(c) for c in defn), hexn)
        self.assertEqual(defn, use)

    def test_4(self):
        "test for generating symbol references before use"
        gmr = Grammar("root    @id\n"
                      "id      'id' /[0-9]/")
        self.assertRegex(gmr.generate(), r"^id[0-9]$")

    def test_5(self):
        "test that symbols are tracked even when not output"
        out = [0]
        def esc(x):
            out[0] = x
            return ""
        gmr = Grammar("root    esc(id) @id\n"
                      "id      'id' /[0-9]/",
                      esc=esc)
        for _ in range(100):
            result = gmr.generate()
            self.assertRegex(result, r"^id[0-9]$")
            self.assertEqual(out[0], result)


class Strings(TestCase):

    def test_0(self):
        "test for string quoting and escaping"
        quotes = {"root    '\\\\'": "\\",
                  "root    \"\\\\\"": "\\",
                  "root    '\\''": "'",
                  "root    \"\\\"\"": "\"",
                  "root    '\\'some'": "'some",
                  "root    \"\\\"some\"": "\"some",
                  "root    'some\\''": "some'",
                  "root    \"some\\\"\"": "some\"",
                  r"root    '\\\\\\\'\\'": "\\\\\\'\\",
                  r'root    "\\\\\\\"\\"': "\\\\\\\"\\",
                  "root    \"'some\"": "'some",
                  "root    '\"some'": "\"some",
                  "root    \"'\"": "'",
                  "root    \"''\"": "''",
                  "root    \"'''\"": "'''",
                  "root    '\"'": "\"",
                  "root    '\"\"'": "\"\"",
                  "root    '\"\"\"'": "\"\"\""}
        for gmr_s, expected in quotes.items():
            gmr = Grammar(gmr_s)
            self.assertEqual(gmr.generate(), expected)

    def test_1(self):
        "test something else tyson did"
        #right: "<h5 id='id824837' onload='chat(\'id705147\',1,\' width=\\\'2pt\\\'\')'>"
        #                                                        ^  -- esc() --   ^
        #wrong: "<h5 id='id824837' onload='chat(\'id705147\',1,\\\' width=\\\'2pt\'\')'>"
        #                                                      ^  -- esc() --   ^
        gmr = Grammar("root   \"<h5 id='\" id \"' onload='\" esc(func) \"'>\"\n"
                      "id     'id' /[0-9]{6}/\n"
                      "func   \"chat('\" id \"',\" /[0-9]/ \",'\" esc(\" width='2pt'\") \"')\"\n"
                      , esc=lambda x: re.sub(r"('|\\)", r"\\\1", x))
        self.assertRegex(gmr.generate(), r"^<h5 id='id[0-9]{6}' onload='chat\(\\'id[0-9]{6}"
                                         r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$")
        # same grammar with '@id' in chat() instead of 'id'
        gmr = Grammar("root   \"<h5 id='\" id \"' onload='\" esc(func) \"'>\"\n"
                      "id     'id' /[0-9]{6}/\n"
                      "func   \"chat('\" @id \"',\" /[0-9]/ \",'\" esc(\" width='2pt'\") \"')\"\n"
                      , esc=lambda x: re.sub(r"('|\\)", r"\\\1", x))
        self.assertRegex(gmr.generate(), r"^<h5 id='(id[0-9]{6})' onload='chat\(\\'\1"
                                         r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$")

    def test_2(self):
        "tests for unbalanced escapes"
        with self.assertRaisesRegex(ParseError, r'^Unterminated string literal'):
            Grammar(r"root    '\\\\\\\'")
        with self.assertRaisesRegex(ParseError, r'^Unterminated string literal'):
            Grammar(r'root    "\\\\\\\"')

    def test_3(self):
        "test for unicode strings"
        gmr = Grammar("root 'ü'")
        self.assertEqual(gmr.generate(), "ü")


