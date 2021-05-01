################################################################################
# coding=utf-8
# pylint: disable=invalid-name,missing-docstring,protected-access
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
import logging
import os
import re
import shutil
import string
import sys
import tempfile
import unittest

from avalanche.core import (
    GenerationError,
    Grammar,
    IntegrityError,
    ParseError,
    SparseList,
    main,
    unichr_,
)

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("avalanche_test")


# delta for inexact tests
DELTA = 0.05


class TestCase(unittest.TestCase):
    def setUp(self):
        self.tmpd = tempfile.mkdtemp(prefix="gmrtesttmp")
        self.cwd = os.getcwd()
        os.chdir(self.tmpd)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmpd)


class Backrefs(TestCase):
    def test_0(self):
        """test that basic backreferences work, generate a single digit and reference
        to it, make sure they match
        """
        gmr = Grammar("root  (/[0-9]/) @1")
        for _ in range(100):
            x1, x2 = gmr.generate()
            self.assertEqual(x1, x2)
        gmr = Grammar("root  (/[0-9]/|/[a-z]/) @1")
        for _ in range(100):
            x1, x2 = gmr.generate()
            self.assertEqual(x1, x2)

    def test_1(self):
        """negative tests for backreferences, check use without declaration and use
        before declaration"""
        with self.assertRaisesRegex(IntegrityError, r"^Invalid backreference"):
            Grammar("root  'a' @1")
        with self.assertRaisesRegex(IntegrityError, r"^Invalid backreference"):
            Grammar("root  'a' @1 ('b')")

    def test_2(self):
        """test that backreferences work in function args"""
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
        """test that backreferences on different lines don't get messed up"""
        gmr = Grammar("root  (/[0-9]/) y @1\n" "y     (/[0-9]/) @1")
        n_same = 0
        for _ in range(100):
            x1, y1, y2, x2 = gmr.generate()
            self.assertEqual(x1, x2)
            self.assertEqual(y1, y2)
            if x1 == y1:
                n_same += 1
        self.assertLess(n_same, 100)

    def test_4(self):
        """test that backreferences in repeats don't get confused"""
        gmr = Grammar(
            "choice   1   'a'\n"
            "         1   'b'\n"
            "         1   'c'\n"
            "root     ((choice) ':' @2 '\\n'){100}\n"
        )
        for out in gmr.generate().splitlines():
            out = out.split(":")
            self.assertEqual(out[0], out[1])
        gmr = Grammar(
            "choice   1   'a'\n"
            "         1   'b'\n"
            "         1   'c'\n"
            "         1   'd'\n"
            "         1   'e'\n"
            "         1   'f'\n"
            "root     ((choice) ':' @2 '\\n')<*>\n"
        )
        seen = set()
        for out in gmr.generate().splitlines():
            out = out.split(":")
            self.assertEqual(out[0], out[1])
            self.assertTrue(out[0] not in seen)
            seen.add(out[0])
        self.assertEqual(len(seen), len(gmr.symtab["choice"].children()))


class Binary(TestCase):
    def test_bin(self):
        """test binary strings"""
        gmr = Grammar("root x'68656c6c6f2c20776f726c6400'")
        self.assertEqual(gmr.generate(), b"hello, world\0")

    def test_unicode(self):
        """test for unicode in a binary string"""
        with self.assertRaisesRegex(ParseError, r"^Invalid hex string"):
            Grammar("root x'000ü'")


class Choices(TestCase):
    def balanced_choice(self, grammar, values, iters=2000):
        result = {value: 0 for value in values}
        gmr = Grammar(grammar)
        for _ in range(iters):
            result[gmr.generate()] += 1
        log.debug("balanced_choice(%s) -> %s", values, result)
        for value in result.values():
            self.assertAlmostEqual(float(value) / iters, 1.0 / len(values), delta=DELTA)

    def test_0(self):
        """test for choice balance in a repeat sample"""
        self.balanced_choice("root a<*>\n" "a 1 'a'\n" "  1 'b'", ["ab", "ba"])

    def test_1(self):
        """tests for choices with different weights"""
        iters = 10000
        self.balanced_choice(
            "root 1 '1'\n" "     1 '2'\n" "     1 '3'", ["1", "2", "3"]
        )
        gmr = Grammar("root .5 '1'\n" "     1  '2'\n" "     .5 '3'")
        result = {1: 0, 2: 0, 3: 0}
        for _ in range(iters):
            result[int(gmr.generate())] += 1
        self.assertAlmostEqual(float(result[1]) / iters, 0.25, delta=DELTA)
        self.assertAlmostEqual(float(result[2]) / iters, 0.5, delta=DELTA)
        self.assertAlmostEqual(float(result[3]) / iters, 0.25, delta=DELTA)
        gmr = Grammar("root .3 '1'\n" "     .1 '2'\n" "     .1 '3'")
        result = {1: 0, 2: 0, 3: 0}
        for _ in range(iters):
            result[int(gmr.generate())] += 1
        self.assertAlmostEqual(float(result[1]) / iters, 0.6, delta=DELTA)
        self.assertAlmostEqual(float(result[2]) / iters, 0.2, delta=DELTA)
        self.assertAlmostEqual(float(result[3]) / iters, 0.2, delta=DELTA)
        gmr = Grammar("root .25 '1'\n" "     .25 '2'\n" "     1   '3'")
        result = {1: 0, 2: 0, 3: 0}
        for _ in range(iters):
            result[int(gmr.generate())] += 1
        self.assertAlmostEqual(float(result[1]) / iters, 1.0 / 6, delta=DELTA)
        self.assertAlmostEqual(float(result[2]) / iters, 1.0 / 6, delta=DELTA)
        self.assertAlmostEqual(float(result[3]) / iters, 2.0 / 3, delta=DELTA)

    def test_2(self):
        """tests invalid weights"""
        with self.assertRaisesRegex(
            IntegrityError, r"^Invalid weight value for choice.*"
        ):
            Grammar("root 1 '1'\n" "     2 '2'\n")
        with self.assertRaisesRegex(
            IntegrityError, r"^Symbol -1 used but not defined \(*"
        ):
            Grammar("root -1 '1'\n")

    def test_3(self):
        """test choice includes with '+'"""
        self.balanced_choice(
            "var     1 'a'\n"
            "        1 'b'\n"
            "        1 'c'\n"
            "root    + var\n"
            "        1 'd'",
            ["a", "b", "c", "d"],
        )
        self.balanced_choice(
            "var     1 'a'\n"
            "        1 'b'\n"
            "        1 'c'\n"
            "root    + 'A' var\n"
            "        1 'd'",
            ["Aa", "Ab", "Ac", "d"],
        )
        with self.assertRaisesRegex(IntegrityError, r"^Can't resolve weight for '\+'"):
            Grammar("root + a\n" "a + root\n" "  1 'a'")

    def test_4(self):
        """test that '+' raises with no choice symbols or with multiple choice
        symbols"""
        with self.assertRaisesRegex(
            IntegrityError, r"^Expecting exactly one ChoiceSymbol"
        ):
            Grammar(
                "root   + ChSym1 ChSym2\n"
                "       1 'a'\n"
                "ChSym1 1 '1'\n"
                "       1 '2'\n"
                "ChSym2 1 '3'\n"
                "       1 '4'\n"
            )
        with self.assertRaisesRegex(
            IntegrityError, r"^Expecting exactly one ChoiceSymbol"
        ):
            Grammar("root + 'a'")

    def test_5(self):
        """test that '+' works with text appended to the choice symbol"""
        iters = 10000
        gmr = Grammar("root a\n" "a + (b 'X')\n" "  1 'c'\n" "b 1 'a'\n" "  1 'b'")
        result = {"c": 0, "aX": 0, "bX": 0}
        for _ in range(iters):
            result[gmr.generate()] += 1
        for value in result.values():
            self.assertAlmostEqual(float(value) / iters, 1.0 / 3, delta=DELTA)

    def test_6(self):
        """test that '+' works with tracked references"""
        g = Grammar(
            "root     Ref '\\n' test\n"
            "test   + @Ref ':' ChSym\n"
            "       1 @Ref ':3'\n"
            "       1 @Ref ':4'\n"
            "ChSym  1 '1'\n"
            "       1 '2'\n"
            "Ref      'ref' /[0-2]{1}/"
        )
        r = {"1": 0, "2": 0, "3": 0, "4": 0}
        count = 10000
        for _ in range(count):
            v = g.generate()
            self.assertRegex(v, r"\nref[0-2]:[0-4]$")
            r[v[-1]] += 1
        self.assertAlmostEqual(float(r["1"]) / count, 0.25, delta=DELTA)
        self.assertAlmostEqual(float(r["2"]) / count, 0.25, delta=DELTA)
        self.assertAlmostEqual(float(r["3"]) / count, 0.25, delta=DELTA)
        self.assertAlmostEqual(float(r["4"]) / count, 0.25, delta=DELTA)

    def test_7(self):
        """test that weights in a nested choice are ignored. has gone wrong before."""
        gmr = Grammar("root a {10000}\n" "b .9 'b'\n" "a .1 'a'\n" "  .1 b")
        output = gmr.generate()
        a_count = len([c for c in output if c == "a"]) / 10000.0
        b_count = 1.0 - a_count
        self.assertAlmostEqual(a_count, b_count, delta=DELTA)

    def test_8(self):
        with self.assertRaisesRegex(IntegrityError, r"^Invalid.*weight.*0\.0"):
            Grammar("root 0 '1'")

    def test_9(self):  # pylint: disable=no-self-use
        """test for limit case of Choice."""
        # this will fail intermittently if self.total is used instead of total
        # in ChoiceSymbol.choice()
        # XXX: why intermittently??
        gmr = Grammar(
            "root     ('x' t 'x'){10}\n"
            "t    +   u\n"
            "     1   'x'\n"
            "u    1   'x'\n"
            "     1   'x'\n",
            limit=4,
        )
        for _ in range(100):
            gmr.generate()

    def test_10(self):
        """test for implicit Choice"""
        self.balanced_choice("root ('a' | 'b')", ["a", "b"])


class Concats(TestCase):
    def test_impl_concat(self):
        """test that implicit concats work"""
        gmr = Grammar("root ('a' 'b') 'c'")
        self.assertEqual(gmr.generate(), "abc")
        gmr = Grammar("root 'a' ('b') 'c'")
        self.assertEqual(gmr.generate(), "abc")
        gmr = Grammar("root 'a' ('b' 'c')")
        self.assertEqual(gmr.generate(), "abc")
        gmr = Grammar("root ('a' 'b' 'c')")
        self.assertEqual(gmr.generate(), "abc")


class Functions(TestCase):
    def test_funcs(self):
        """test that python filter functions work"""
        gram = (
            "root            func{100}\n"
            "func    1       'z' zero(nuvar) '\\n'\n"
            "        1       'a' alpha(alvar , '*,' rep) '\\n'\n"
            "        1       nuvar '\\n'\n"
            "        1       alvar '\\n'\n"
            "nuvar           'n' /[0-9]{6}/\n"
            "alvar           'c' /[a-z]{6}/\n"
            "rep             /[0-9]/"
        )

        def zero(inp):
            return inp.replace("0", "z")

        def alpha(inp, rep):
            return "%s/%s" % (rep, inp.replace("a", rep))

        gmr = Grammar(gram, zero=zero, alpha=alpha)
        for line in gmr.generate().splitlines():
            self.assertTrue(line.startswith("zn") or line[0] in "anc")
            if line.startswith("zn"):
                self.assertRegex(line[2:], r"^[1-9z]{6}$")
            elif line.startswith("a"):
                self.assertRegex(line[1:], r"^(\*,[0-9])/c(\1|[b-z]){6}$")
            elif line.startswith("n"):
                self.assertRegex(line[1:], r"^[0-9]{6}$")
            elif line.startswith("c"):
                self.assertRegex(line[1:], r"^[a-z]{6}$")

    def test_builtin_rndint(self):
        """test the built-in rndint function"""
        gmr = Grammar("root  rndint(1,10)")
        result = {i: 0 for i in range(1, 11)}
        iters = 10000
        for _ in range(iters):
            value = int(gmr.generate())
            result[value] += 1
        for value in result.values():
            self.assertAlmostEqual(float(value) / iters, 0.1, delta=DELTA)
        with self.assertRaisesRegex(GenerationError, r"^ValueError"):
            Grammar("root  rndint(2,1)").generate()

    def test_builtin_rndflt(self):
        """test the built-in rndflt function"""
        iters = 10000
        gmr = Grammar("root  rndflt(0,10)")
        result = {(i / 2.0): 0 for i in range(0, 20)}
        for _ in range(iters):
            value = float(gmr.generate())
            # count buckets in increments of 0.5
            result[int(value * 2) / 2.0] += 1
        for value in result.values():
            self.assertAlmostEqual(float(value) / iters, 0.05, delta=DELTA)
        gmr = Grammar("root  rndflt(0.1,1)")
        result = {(i / 10.0): 0 for i in range(1, 10)}
        for _ in range(iters):
            value = float(gmr.generate())
            # count buckets in increments of 0.1
            result[int(value * 10) / 10.0] += 1
        for value in result.values():
            self.assertAlmostEqual(float(value) / iters, 1.0 / 9, delta=DELTA)

    def test_builtin_rndpow2(self):
        """test the built-in rndpow2 function"""
        iters = 10000
        gmr = Grammar("root  rndpow2(2,0)")
        result = {1: 0, 2: 0, 4: 0}
        for _ in range(iters):
            value = int(gmr.generate())
            result[value] += 1
        for value in result.values():
            self.assertGreater(value, 0)
        gmr = Grammar("root  rndpow2(2,1)")
        result = {i: 0 for i in range(0, 6)}
        for _ in range(iters):
            value = int(gmr.generate())
            result[value] += 1
        for value in result.values():
            self.assertGreater(value, 0)
        with self.assertRaisesRegex(GenerationError, r"^ValueError"):
            Grammar("root  rndpow2(-1,0)").generate()

    def test_buildin_eval(self):
        """test the built-in eval function"""
        # XXX: test eval of non-existent symbol
        # XXX: test eval with <>
        # XXX: test that references work within eval (ie, a-value could
        # use an @ reference from outside the eval)
        iters = 1000
        gmr = Grammar(
            "root decl unused{0}\n"
            "decl (name) ':' eval(@1 '-value')\n"
            "name 1 'a'\n"
            "     1 'b'\n"
            "a-value 'AAA'\n"
            "b-value 'BBB'\n"
            "unused a-value b-value"
        )
        result = {"a": 0, "b": 0}
        expected = {"a": "AAA", "b": "BBB"}
        for _ in range(iters):
            name, value = gmr.generate().split(":")
            self.assertEqual(value, expected[name])
            result[name] += 1
        self.assertGreater(result["a"], 0)
        self.assertGreater(result["b"], 0)
        # test eval with unused (will raise for now ... should fix that?)
        with self.assertRaisesRegex(IntegrityError, r"^Unused symbols:"):
            Grammar(
                "root decl\n"
                "decl (name) ':' eval(@1 '-value')\n"
                "name 1 'a'\n"
                "     1 'b'\n"
                "a-value 'AAA'\n"
                "b-value 'BBB'"
            )

    def test_builtin_id(self):
        """test the built-in id function"""
        gmr = Grammar("root id() ' ' id() ' ' id()")
        self.assertEqual(gmr.generate(), "0 1 2")
        self.assertEqual(gmr.generate(), "0 1 2")
        with self.assertRaisesRegex(
            GenerationError, r"^TypeError: id\(\) takes 0 arguments \(1 given\)"
        ):
            Grammar("root id('')").generate()

    def test_builtin_push(self):
        """test the built-in push/pop functions"""
        gmr = Grammar("root push('B') push('123') 'A' pop() pop()")
        self.assertEqual(gmr.generate(), "A123B")


class Imports(TestCase):
    def test_import_reserved(self):
        """test that 'import' is not allowed to be redefined"""
        with self.assertRaisesRegex(ParseError, r"^'import' is a reserved name"):
            Grammar('import blah "blah.gmr"')

    def test_unused_import(self):
        """test for unused imports"""
        open("blah.gmr", "w").close()
        with self.assertRaisesRegex(IntegrityError, r"^Unused import"):
            Grammar("root 'a'\n" "unused import('blah.gmr')")

    def test_use_before_import(self):
        """tests for use before import"""
        with self.assertRaisesRegex(
            ParseError, r"^Attempt to use symbol from unknown prefix"
        ):
            Grammar("root a.b")

    def test_notfound_import(self):
        """tests for bad imports"""
        with self.assertRaisesRegex(ParseError, r"^Error parsing string"):
            Grammar("a import()")
        with self.assertRaisesRegex(
            IntegrityError, r"^Could not find imported grammar"
        ):
            Grammar("a import('')")

    def test_simple(self):
        """test that imports work"""
        with open("a.gmr", "w") as fd:
            fd.write('a "A"')
        gmr = Grammar("b import('a.gmr')\n" "root b.a")
        self.assertEqual(gmr.generate(), "A")

    def test_nested(self):
        """test that circular imports are allowed"""
        with open("a.gmr", "w") as fd:
            fd.write('b import("b.gmr")\n' "root a b.a\n" 'a "A"')
        with open("b.gmr", "w") as fd:
            fd.write('x import("a.gmr")\n' "a @x.a")
        with open("a.gmr") as fd:
            gmr = Grammar(fd)
        self.assertEqual(gmr.generate(), "AA")

    def test_recursive_defn(self):
        """test that infinite recursion is detected across an import"""
        with open("b.gmr", "w") as fd:
            fd.write('b import("b.gmr")\n' "root b.a\n" "a b.a")
        with self.assertRaisesRegex(
            IntegrityError, r"^Symbol has no paths to termination"
        ):
            with open("b.gmr") as fd:
                Grammar(fd)

    def test_unused_import_sym(self):
        """test that unused symbols in an import are allowed"""
        with open("a.gmr", "w") as fd:
            fd.write('a "A"\n' 'b "B"')
        gmr = Grammar('a import("a.gmr")\n' "root a.a")
        self.assertEqual(gmr.generate(), "A")

    def test_imported_choice(self):
        """test that repeat sample works across an import"""
        with open("a.gmr", "w") as fd:
            fd.write('a 1 "A"')
        gmr = Grammar("b import('a.gmr')\n" "root a<*>\n" "a b.a")
        self.assertEqual(gmr.generate(), "A")

    def test_import_in_error(self):
        """test that imported filename shows up in the exception message"""
        with open("a.gmr", "w") as fd:
            fd.write("a 20 b")
        with self.assertRaisesRegex(
            IntegrityError, r"^Invalid weight value for choice.* \(a\.gmr line 1\)"
        ):
            Grammar('a import("a.gmr")\n' "root a.a")

    def test_import_name_integrity(self):
        """test that import names don't get overwritten"""
        with open("a.gmr", "w") as fd:
            fd.write('X import("b.gmr")\n')
            fd.write("B X.B\n")
        with open("b.gmr", "w") as fd:
            fd.write('B "B"\n')
        with open("c.gmr", "w") as fd:
            fd.write('C "C"\n')
        gmr = Grammar('A import("a.gmr")\n' 'X import("c.gmr")\n' "root A.B X.C\n")
        self.assertEqual(gmr.generate(), "BC")

    def test_import_file_containing_eval(self):
        """test that importing files containing evals works as expected"""
        with open("a.gmr", "w") as fd:
            fd.write('IB import("b.gmr")\n')
            fd.write("B  IB.X\n")
        with open("b.gmr", "w") as fd:
            fd.write('X eval("Z")\n')
            fd.write('Z "z"\n')
        gmr = Grammar('A import("a.gmr")\n' "root A.B\n")
        self.assertEqual(gmr.generate(), "z")

    def test_import_with_unicode(self):
        """test that imports with unicode characters work"""
        with open("a.gmr", "wb") as fd:
            fd.write('a "ü"'.encode("utf-8"))
        gmr = Grammar("b import('a.gmr')\n" "root b.a")
        self.assertEqual(gmr.generate(), "ü")


class Inputs(TestCase):
    def test_str(self):
        """test grammar with byte string as input"""
        gmr = Grammar(b"root 'a'")
        self.assertEqual(gmr.generate(), "a")

    def test_binfilelike(self):
        """test grammar with binary file-like object as input"""
        infile = io.BytesIO(b'root "a"')
        gmr = Grammar(infile)
        self.assertEqual(gmr.generate(), "a")

    def test_filelike(self):
        """test grammar with utf-8 file-like object as input"""
        infile = io.StringIO('root "a"')
        gmr = Grammar(infile)
        self.assertEqual(gmr.generate(), "a")

    def test_binfile(self):
        """test grammar with binary file as input"""
        with open("a.gmr", "w+b") as fd:
            fd.write(b'root "a"')
            fd.seek(0)
            gmr = Grammar(fd)
        self.assertEqual(gmr.generate(), "a")

    def test_file(self):
        """test grammar with utf-8 file as input"""
        with io.open("a.gmr", "w+", encoding="utf-8") as fd:
            fd.write('root "aü"')
            fd.seek(0)
            gmr = Grammar(fd)
        self.assertEqual(gmr.generate(), "aü")


class Parser(TestCase):
    def test_broken(self):
        """test broken lines"""
        gmr = Grammar("root 'a' 'b'\\\n" "     'c'")
        self.assertEqual(gmr.generate(), "abc")

    def test_comment_in_broken(self):
        """test that you can comment out a broken line"""
        gmr = Grammar("root 'some broken ' \\\n" "# blah\n" " 'string'")
        self.assertEqual(gmr.generate(), "some broken string")

    def test_basic(self):
        """test basic grammar features"""
        gmr = Grammar("root    ok\n" "ok      '1'")
        self.assertEqual(gmr.generate(), "1")
        gmr = Grammar(
            "root   a\n"
            "a      '1234' /[a-z]/ b\n"
            "b      1 c\n"
            "       1 d\n"
            "c      'C'\n"
            "d      'D'"
        )
        result = {"C": 0, "D": 0}
        count = 10000
        for _ in range(count):
            value = gmr.generate()
            self.assertRegex(value, r"^1234[a-z][CD]$")
            result[value[-1]] += 1
        self.assertAlmostEqual(float(result["C"]) / count, 0.5, delta=DELTA)
        self.assertAlmostEqual(float(result["D"]) / count, 0.5, delta=DELTA)

    def test_dashname(self):
        """test that dash is allowed in symbol names"""
        gmr = Grammar("root a-a\n" "a-a 'a'\n")
        self.assertEqual(gmr.generate(), "a")

    def test_limit(self):
        """test that limit is respected"""
        gmr = Grammar(
            "root       foo bar\n" "bar        (@foo bar) {1}\n" "foo        'i0'",
            limit=10,
        )
        self.assertLessEqual(len(gmr.generate()), 10)

    def test_altstart(self):
        """test that starting symbols other than 'root' work"""
        gmr = Grammar("root a 'B'\n" "a 'A'")
        self.assertEqual(gmr.generate(start="a"), "A")

    def test_incomplete_sym_defn(self):
        """test incomplete symbol definitions raise ParseError"""
        with self.assertRaisesRegex(
            ParseError, r"^Failed to parse definition.*\(line 2\)"
        ):
            Grammar("root a\n" "a")
        with self.assertRaisesRegex(
            ParseError, r"^Failed to parse definition.*\(line 2\)"
        ):
            Grammar("root a\n" "a  ")
        # just being mean here
        with self.assertRaisesRegex(
            ParseError, r"^Failed to parse definition.*\(line 2\)"
        ):
            Grammar("root a\n" "a\r\t")

    def test_recursive_defn(self):
        """test recursive definition"""
        with self.assertRaisesRegex(
            IntegrityError, r"^Symbol has no paths to termination"
        ):
            Grammar("root root")

    def test_unused_sym(self):
        """tests for unused symbols"""
        with self.assertRaisesRegex(IntegrityError, r"^Unused symbol:"):
            Grammar("root a\n" 'a "A"\n' 'b "B"')
        with self.assertRaisesRegex(IntegrityError, r"^Unused symbols:"):
            Grammar('root "A"\n' "a b\n" "b a")

    def test_undefined_sym(self):
        """tests use unused symbols"""
        with self.assertRaisesRegex(IntegrityError, r"^Symbol.*used but not defined"):
            Grammar("root   undef")
        with self.assertRaisesRegex(IntegrityError, r"^Symbol.*used but not defined"):
            Grammar("root + undef")
        with self.assertRaisesRegex(IntegrityError, r"^Symbol.*used but not defined"):
            Grammar("root 1 undef" "     1 undef")
        with self.assertRaisesRegex(IntegrityError, r"^Symbol.*used but not defined"):
            Grammar("root   (undef){1,2}")
        with self.assertRaisesRegex(IntegrityError, r"^Symbol.*used but not defined"):
            Grammar("root   undef<*>")


class Regexes(TestCase):
    def test_0(self):
        """test for some bad thing tyson did once"""
        gmr = Grammar('root   /[0-1]{1}/ "]"')
        self.assertIn(gmr.generate(), ["0]", "1]"])

    def test_1(self):
        """test for invalid range in a regex"""
        with self.assertRaisesRegex(ParseError, r"^Empty range in regex"):
            Grammar("root /[+-*]/")

    def test_2(self):
        """test that '.' works in a regex"""
        iters = 10000
        out = set(Grammar("root /./{%d}" % iters).generate())
        self.assertEqual(
            out, set(string.digits + string.ascii_letters + string.punctuation + " ")
        )

    def test_3(self):
        """test for excluded char in range"""
        iters = 10000
        out = set(Grammar('root /[^"]{%d}/' % iters).generate())
        self.assertEqual(
            out - set(string.digits + string.ascii_letters + string.punctuation + " "),
            set(),
        )
        self.assertEqual(
            set(string.digits + string.ascii_letters + string.punctuation + " ") - out,
            {'"'},
        )

    def test_4(self):
        """test unicode ranges"""
        iters = 100000
        out = Grammar("root /[\U0001f300-\U0001f5ff]/{%d}" % iters).generate()
        if sys.maxunicode == 65535:
            out = {out[i : i + 2] for i in range(0, len(out), 2)}
        else:
            out = set(out)
        self.assertEqual(set(out), set(unichr_(c) for c in range(0x1F300, 0x1F600)))


class Repeats(TestCase):
    def test_0(self):
        """tests for simple repeats"""
        gmr = Grammar('root "A"{1,10}')
        lengths = set()
        for _ in range(2000):
            result = gmr.generate()
            self.assertEqual(len(set(result)), 1)
            self.assertEqual(result[0], "A")
            self.assertIn(len(result), range(1, 11))
            lengths.add(len(result))
        self.assertEqual(len(lengths), 10)

    def test_1(self):
        """test for repeat of implicit concatenation"""
        gmr = Grammar('root ("A" "B" ","){ 0 , 10 } "AB"')
        lengths = set()
        for _ in range(2000):
            result = gmr.generate().split(",")
            self.assertEqual(len(set(result)), 1)
            self.assertEqual(result[0], "AB")
            self.assertIn(len(result), range(1, 12))
            lengths.add(len(result))
        self.assertEqual(len(lengths), 11)

    def test_2(self):
        """tests for repeat sample"""
        with self.assertRaisesRegex(
            IntegrityError, r"^Expecting exactly one ChoiceSymbol"
        ):
            Grammar('root "A" <1,10>')
        with self.assertRaisesRegex(
            IntegrityError, r"^Expecting exactly one ChoiceSymbol"
        ):
            Grammar("root (a a) <1,10>\n" 'a 1 "A"')
        gmr = Grammar("root a<1,10>\n" 'a 1 "A"')
        for _ in range(100):
            self.assertEqual(gmr.generate(), "A")
        gmr = Grammar('root ("a" a)<1,10>\n' 'a 1 "A"')
        for _ in range(100):
            self.assertEqual(gmr.generate(), "aA")
        gmr = Grammar("root a<1,10>\n" 'a   "a" b\n' 'b 1 "A"')
        for _ in range(100):
            self.assertEqual(gmr.generate(), "aA")
        gmr = Grammar("root a <1,10>\n" 'a .9 "A"\n' '  .1 "B"')
        outs = {"A": 0, "B": 0, "BA": 0, "AB": 0}
        for _ in range(1000):
            outs[gmr.generate()] += 1
        self.assertGreater(outs["AB"] + outs["BA"], outs["A"] + outs["B"])
        self.assertGreater(outs["AB"], outs["BA"])
        self.assertGreater(outs["A"], outs["B"])
        gmr = Grammar('root ("A"|"A")<1,10>')
        for _ in range(100):
            self.assertIn(gmr.generate(), {"A", "AA"})

    def test_3(self):
        """tests for '?' shortcut for {0,1}"""
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

    def test_4(self):
        """tests for '*' as a repeat arg"""
        gmr = Grammar("root a<0,*>\n" "a 1 'a'\n" "  1 'b'")
        result = {"ab": 0, "ba": 0, "a": 0, "b": 0, "": 0}
        for _ in range(1000):
            result[gmr.generate()] += 1
        self.assertGreater(result["a"] + result["b"], result["ab"] + result["ba"])
        self.assertGreater(result[""], result["a"] + result["b"])
        with self.assertRaisesRegex(
            IntegrityError, r"^Expecting exactly one ChoiceSymbol"
        ):
            Grammar("root 'a'{*}")
        with self.assertRaisesRegex(
            IntegrityError, r"^Expecting exactly one ChoiceSymbol"
        ):
            Grammar("root 'a'<*>")
        with self.assertRaisesRegex(IntegrityError, r"^Invalid range for repeat"):
            Grammar("root a{*,0}\n" "a 1 'a'")
        gmr = Grammar("root a{*}\n" "a 1 'a'\n")
        result = gmr.generate()
        self.assertEqual(len(result), 1)
        self.assertEqual(result, "a")
        gmr = Grammar("root ('a'|'b')<0,*>")
        result = {"ab": 0, "ba": 0, "a": 0, "b": 0, "": 0}
        for _ in range(1000):
            result[gmr.generate()] += 1
        self.assertGreater(result["a"] + result["b"], result["ab"] + result["ba"])
        self.assertGreater(result[""], result["a"] + result["b"])

    def test_5(self):
        """test that '*' uses all choices from a choice included with '+'"""
        gmr = Grammar(
            "root a<*>\n"
            "a 1 'a'\n"
            "  + b\n"
            "b 1 'b'\n"
            "  1 'c'\n"
            "  +  c\n"
            "c 1 'd'\n"
            "  1 'e'"
        )
        result = gmr.generate()
        self.assertEqual("".join(sorted(result)), "abcde")

    def test_6(self):
        """test for tracked repeatsample symbols"""
        gmr = Grammar("root b<*> @b\n" "a 1 /[0-9]/\n" "b a 'A'")
        for _ in range(100):
            result = gmr.generate()
            self.assertEqual(len(result), 4)
            self.assertEqual(result[:2], result[2:])
        gmr = Grammar("root a<*> @a\n" "a 1 b\n" "b /[0-9]/")
        for _ in range(100):
            result = gmr.generate()
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0], result[1])
        gmr = Grammar("root a<*> @b @c\n" "a + b\n" "b 1 c\n" "c /[0-9]/")
        for _ in range(100):
            result = gmr.generate()
            self.assertEqual(len(result), 3)
            self.assertEqual(len(set(result)), 1)

    def test_7(self):
        """test for repeat of implicit choice"""
        gmr = Grammar('root ("A," | "B,"){ 0 , 10 } ("A" | "B")')
        lengths = set()
        for _ in range(2000):
            result = gmr.generate().split(",")
            self.assertIn(len(set(result)), range(1, 3))
            if len(set(result)) == 1:
                self.assertIn(result[0], "AB")
            else:
                vals = sorted(set(result))
                self.assertEqual(vals, ["A", "B"])
            self.assertIn(len(result), range(1, 12))
            lengths.add(len(result))
        self.assertEqual(len(lengths), 11)


class References(TestCase):
    def test_0(self):
        """test for tracked symbol use as a function arg"""
        gmr = Grammar(
            "root   id a(b(@id))\n" "id     /[a-z]/\n",
            a=lambda x: "a" + x,
            b=lambda x: "b" + x,
        )
        for _ in range(100):
            result = gmr.generate()
            self.assertEqual(result[0], result[-1])
            self.assertEqual(result[1:-1], "ab")

    def test_1(self):
        """test for tracked symbols"""
        gmr = Grammar(
            "root    id '\\n' esc(\"'\" @id \"'\")\n" "id      'id' /[0-9]/",
            esc=lambda x: re.sub(r"'", "\\'", x),
        )
        for _ in range(100):
            defn, use = gmr.generate().splitlines()
            self.assertRegex(defn, r"^id[0-9]$")
            self.assertEqual(use, "\\'%s\\'" % defn)

    def test_2(self):
        """test for tracked symbols"""
        gmr = Grammar(
            "root    id '\\n' esc('not', @id)\n" "id      'id' /[0-9]/",
            esc=lambda x, y: x,
        )
        defn, use = gmr.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual(use, "not")

    def test_3(self):
        """test for tracked symbols"""
        gmr = Grammar(
            "root    esc(id) '\\n' @id\n" "id      'id' /[0-9]/",
            esc=lambda x: "%s\n%s" % (x, "".join("%02x" % ord(c) for c in x)),
        )
        defn, hexn, use = gmr.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual("".join("%02x" % ord(c) for c in defn), hexn)
        self.assertEqual(defn, use)

    def test_4(self):
        """test for generating symbol references before use"""
        gmr = Grammar("root    @id\n" "id      'id' /[0-9]/")
        self.assertRegex(gmr.generate(), r"^id[0-9]$")

    def test_5(self):
        """test that symbols are tracked even when not output"""
        out = [0]

        def esc(x):
            out[0] = x
            return ""

        gmr = Grammar("root    esc(id) @id\n" "id      'id' /[0-9]/", esc=esc)
        for _ in range(100):
            result = gmr.generate()
            self.assertRegex(result, r"^id[0-9]$")
            self.assertEqual(out[0], result)

    def test_6(self):
        """test that reference before definition are handled properly"""
        count = 100
        gmr = Grammar(
            "root     (Ref '\\n'){%d} '-' (Def '\\n'){%d}\n"
            "Ref      @SymName\n"
            "Def      SymName\n"
            "SymName  'sym' /[0-9A-Z]/{8}" % (count, count)
        )
        refs, defs = gmr.generate().split("-")
        defs = set(defs.split())
        refs = set(refs.split())
        # all references should be defined in defs if gen count for both is equal
        self.assertEqual(
            len(refs.difference(defs)), 0, "Defs does not contain all refs"
        )
        # all definitions generated should be unique
        self.assertEqual(len(defs), count, "All defs not unique")
        # all references used should not all be the same
        self.assertLess(len(refs), count, "All refs are unique")
        # more than a single reference should be used
        self.assertGreater(
            len(refs), 1, "Expecting more than a single reference be used"
        )


class SparseList_(TestCase):
    def test_0(self):
        """test for basic function of sparse lists"""
        lst = SparseList()
        lst.add(1, 2)  # 2
        lst.add(5)  # 1
        lst.add(7, 8)  # 2
        self.assertEqual(len(lst), 5)
        self.assertEqual(lst[0], 1)
        self.assertEqual(lst[1], 2)
        self.assertEqual(lst[2], 5)
        self.assertEqual(lst[3], 7)
        self.assertEqual(lst[4], 8)
        self.assertEqual(len(lst._data), 3)

    def test_1(self):
        """test sorted order of sparse lists"""
        lst = SparseList()
        lst.add(5)
        lst.add(3)
        lst.add(1)
        self.assertEqual(len(lst), 3)
        self.assertEqual(lst[0], 1)
        self.assertEqual(lst[1], 3)
        self.assertEqual(lst[2], 5)
        self.assertEqual(len(lst._data), 3)

    def test_2(self):
        """test optimization of sparse lists"""
        lst = SparseList()
        lst.add(6)
        lst.add(4)
        self.assertEqual(len(lst._data), 2)
        lst.add(5)
        self.assertEqual(len(lst._data), 1)
        lst.add(3)
        self.assertEqual(len(lst._data), 1)
        lst.add(7)
        self.assertEqual(len(lst._data), 1)
        self.assertEqual(len(lst), 5)
        self.assertEqual(lst[0], 3)
        self.assertEqual(lst[1], 4)
        self.assertEqual(lst[2], 5)
        self.assertEqual(lst[3], 6)
        self.assertEqual(lst[4], 7)

    def test_3(self):
        """test removal from sparse lists"""
        lst = SparseList()
        lst.add(1)
        lst.add(3)
        self.assertEqual(len(lst._data), 2)
        lst.remove(2)
        self.assertEqual(len(lst._data), 2)
        self.assertEqual(len(lst), 2)
        self.assertEqual(lst[0], 1)
        self.assertEqual(lst[1], 3)

        lst = SparseList()
        lst.add(1)
        self.assertEqual(len(lst._data), 1)
        lst.remove(1)
        self.assertEqual(len(lst._data), 0)
        self.assertEqual(len(lst), 0)

        lst = SparseList()
        lst.add(1)
        self.assertEqual(len(lst._data), 1)
        lst.add(3)
        self.assertEqual(len(lst._data), 2)
        lst.remove(1, 3)
        self.assertEqual(len(lst._data), 0)
        self.assertEqual(len(lst), 0)

        lst = SparseList()
        lst.add(1, 2)
        self.assertEqual(len(lst._data), 1)
        lst.remove(2)
        self.assertEqual(len(lst._data), 1)
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0], 1)

        lst = SparseList()
        lst.add(1, 3)
        self.assertEqual(len(lst._data), 1)
        lst.add(5)
        self.assertEqual(len(lst._data), 2)
        lst.remove(2, 5)
        self.assertEqual(len(lst._data), 1)
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0], 1)

        lst = SparseList()
        lst.add(1, 2)
        self.assertEqual(len(lst._data), 1)
        lst.remove(1)
        self.assertEqual(len(lst._data), 1)
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0], 2)

        lst = SparseList()
        lst.add(1)
        self.assertEqual(len(lst._data), 1)
        lst.add(3, 5)
        self.assertEqual(len(lst._data), 2)
        lst.remove(1, 4)
        self.assertEqual(len(lst._data), 1)
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0], 5)

        lst = SparseList()
        lst.add(1, 3)
        self.assertEqual(len(lst._data), 1)
        lst.remove(2)
        self.assertEqual(len(lst._data), 2)
        self.assertEqual(len(lst), 2)
        self.assertEqual(lst[0], 1)
        self.assertEqual(lst[1], 3)

        lst = SparseList()
        lst.add(1, 3)
        self.assertEqual(len(lst._data), 1)
        lst.add(24, 26)
        self.assertEqual(len(lst._data), 2)
        lst.remove(2, 25)
        self.assertEqual(len(lst._data), 2)
        self.assertEqual(len(lst), 2)
        self.assertEqual(lst[0], 1)
        self.assertEqual(lst[1], 26)

    def test_4(self):
        """test error cases of sparse lists"""
        with self.assertRaisesRegex(ValueError, r"^1 is already present in the list$"):
            lst = SparseList()
            lst.add(1)
            lst.add(1)
        with self.assertRaisesRegex(ValueError, r"^2 is already present in the list$"):
            lst = SparseList()
            lst.add(1, 3)
            lst.add(2)
        with self.assertRaisesRegex(
            ValueError, r"^\d+ is already present in the list$"
        ):
            lst = SparseList()
            lst.add(2, 6)
            lst.add(1, 3)
        with self.assertRaisesRegex(
            ValueError, r"^\d+ is already present in the list$"
        ):
            lst = SparseList()
            lst.add(2, 6)
            lst.add(3, 7)
        with self.assertRaisesRegex(IndexError, r"^list index out of range$"):
            lst = SparseList()
            lst[0]  # pylint: disable=pointless-statement
        with self.assertRaisesRegex(IndexError, r"^list index out of range$"):
            lst = SparseList()
            lst.add(1)
            lst[1]  # pylint: disable=pointless-statement
        with self.assertRaisesRegex(IndexError, r"^list index out of range$"):
            lst = SparseList()
            lst.add(1)
            lst[-1]  # pylint: disable=pointless-statement
        with self.assertRaisesRegex(
            ValueError, r"^Only forward intervals are supported \(a <= b\)$"
        ):
            lst = SparseList()
            lst.add(2, 1)
        with self.assertRaisesRegex(
            ValueError, r"^Only forward intervals are supported \(a <= b\)$"
        ):
            lst = SparseList()
            lst.remove(2, 1)


class Strings(TestCase):
    def test_0(self):
        """test for string quoting and escaping"""
        quotes = {
            "root    '\\\\'": "\\",
            'root    "\\\\"': "\\",
            "root    '\\''": "'",
            'root    "\\""': '"',
            "root    '\\'some'": "'some",
            'root    "\\"some"': '"some',
            "root    'some\\''": "some'",
            'root    "some\\""': 'some"',
            r"root    '\\\\\\\'\\'": "\\\\\\'\\",
            r'root    "\\\\\\\"\\"': '\\\\\\"\\',
            'root    "\'some"': "'some",
            "root    '\"some'": '"some',
            'root    "\'"': "'",
            "root    \"''\"": "''",
            "root    \"'''\"": "'''",
            "root    '\"'": '"',
            "root    '\"\"'": '""',
            'root    \'"""\'': '"""',
        }
        for gmr_s, expected in quotes.items():
            gmr = Grammar(gmr_s)
            self.assertEqual(gmr.generate(), expected)

    def test_1(self):
        """test something else tyson did"""
        # right: "<h5 id='id837' onload='chat(\'id705147\',1,\' width=\\\'2pt\\\'\')'>"
        #                                                        ^  -- esc() --   ^
        # wrong: "<h5 id='id837' onload='chat(\'id705147\',1,\\\' width=\\\'2pt\'\')'>"
        #                                                      ^  -- esc() --   ^
        gmr = Grammar(
            'root   "<h5 id=\'" id "\' onload=\'" esc(func) "\'>"\n'
            "id     'id' /[0-9]{6}/\n"
            'func   "chat(\'" id "\'," /[0-9]/ ",\'" esc(" width=\'2pt\'") "\')"\n',
            esc=lambda x: re.sub(r"('|\\)", r"\\\1", x),
        )
        self.assertRegex(
            gmr.generate(),
            r"^<h5 id='id[0-9]{6}' onload='chat\(\\'id[0-9]{6}"
            r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$",
        )
        # same grammar with '@id' in chat() instead of 'id'
        gmr = Grammar(
            'root   "<h5 id=\'" id "\' onload=\'" esc(func) "\'>"\n'
            "id     'id' /[0-9]{6}/\n"
            'func   "chat(\'" @id "\'," /[0-9]/ ",\'" esc(" width=\'2pt\'") "\')"\n',
            esc=lambda x: re.sub(r"('|\\)", r"\\\1", x),
        )
        self.assertRegex(
            gmr.generate(),
            r"^<h5 id='(id[0-9]{6})' onload='chat\(\\'\1"
            r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$",
        )

    def test_2(self):
        """tests for unbalanced escapes"""
        with self.assertRaisesRegex(ParseError, r"^Unterminated string literal"):
            Grammar(r"root    '\\\\\\\'")
        with self.assertRaisesRegex(ParseError, r"^Unterminated string literal"):
            Grammar(r'root    "\\\\\\\"')

    def test_3(self):
        """test for unicode strings"""
        test_strings = [
            "ü",
            "Ⱥ",
            "Ω≈ç√∫˜µ≤≥÷",
            "åß∂ƒ©˙∆˚¬…æ",
            "œ∑´®†¥¨ˆøπ“‘",
            "¡™£¢∞§¶•ªº–≠",
            "¸˛Ç◊ı˜Â¯˘¿",
            "ÅÍÎÏ˝ÓÔÒÚÆ☃",
            "Œ„´‰ˇÁ¨ˆØ∏”’",
            "`⁄€‹›ﬁﬂ‡°·‚—±",
            "⅛⅜⅝⅞",
            "ЁЂЃЄЅІЇЈЉЊтуфхцчшщъыьэюя",
            "٠١٢٣٤٥٦٧٨٩",
            "田中さんにあげて下さい",
            "𠜎𠜱𠝹𠱓𠱸𠲖𠳏",
            "ثم نفس سقطت وبالتحديد،,",
            "בְּרֵאשִׁית, בָּרָא",
            "ﷺ",
            "̡͓̞ͅI̗c҉͔̫͖͓͇͖ͅh̵̤̣͚͔á̗̼͕ͅo̼̣̥s̱͈̺̖̦̻͢.̛̖̞̠̯̹̞͓G̻O̭̗̮",
            "\U0001f300\U0001f5ff",
        ]

        for test_str in test_strings:
            gmr = Grammar("root '%s'" % test_str)
            self.assertEqual(gmr.generate(), test_str)


class Script(TestCase):
    def test_01(self):
        """test calling main with '-h'"""
        with self.assertRaisesRegex(SystemExit, "0"):
            main(["-h"])

    def test_02(self):
        """test simple test generation"""
        with open("a.gmr", "w") as fd:
            fd.write('root "A"')
        main(["a.gmr", "a.txt"])
        self.assertTrue(os.path.isfile("a.txt"))
        with open("a.txt", "r") as fd:
            self.assertEqual(fd.read(), "A")

    def test_03(self):
        """test unicode I/O with main"""
        test_strings = [
            "ü",
            "Ⱥ",
            "Ω≈ç√∫˜µ≤≥÷",
            "åß∂ƒ©˙∆˚¬…æ",
            "œ∑´®†¥¨ˆøπ“‘",
            "¡™£¢∞§¶•ªº–≠",
            "¸˛Ç◊ı˜Â¯˘¿",
            "ÅÍÎÏ˝ÓÔÒÚÆ☃",
            "Œ„´‰ˇÁ¨ˆØ∏”’",
            "`⁄€‹›ﬁﬂ‡°·‚—±",
            "⅛⅜⅝⅞",
            "ЁЂЃЄЅІЇЈЉЊтуфхцчшщъыьэюя",
            "٠١٢٣٤٥٦٧٨٩",
            "田中さんにあげて下さい",
            "𠜎𠜱𠝹𠱓𠱸𠲖𠳏",
            "ثم نفس سقطت وبالتحديد،,",
            "בְּרֵאשִׁית, בָּרָא",
            "ﷺ",
            "̡͓̞ͅI̗c҉͔̫͖͓͇͖ͅh̵̤̣͚͔á̗̼͕ͅo̼̣̥s̱͈̺̖̦̻͢.̛̖̞̠̯̹̞͓G̻O̭̗̮",
            "\U0001f300\U0001f5ff",
        ]

        for test_str in test_strings:
            with io.open("a.gmr", "w", encoding="utf-8") as fd:
                fd.write("root '%s'" % test_str)
            main(["a.gmr", "a.txt"])
            self.assertTrue(os.path.isfile("a.txt"))
            with io.open("a.txt", encoding="utf-8") as fd:
                self.assertEqual(fd.read(), test_str)
            os.unlink("a.txt")
