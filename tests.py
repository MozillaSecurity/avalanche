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
from avalanche import Grammar, ChoiceSymbol, ParseError, IntegrityError


class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class Tests(TestCase):
    # anything not in a proper testcase or cleaned up yet

    def test_broken(self):
        "test broken lines"
        gmr = Grammar("root 'a' 'b'\\\n"
                      "     'c'")
        self.assertEqual(gmr.generate(), "abc")

    def test_wchoice(self):
        iters = 10000
        w = ChoiceSymbol([(1, 1), (2, 1), (3, 1)], _test=True)
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        for v in r.values():
            self.assertAlmostEqual(float(v)/iters, 1.0/3, delta=.02)
        w = ChoiceSymbol([(1, 1), (2, 2), (3, 1)], _test=True)
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        self.assertAlmostEqual(float(r[1])/iters, 0.25, delta=.02)
        self.assertAlmostEqual(float(r[2])/iters, 0.5, delta=.02)
        self.assertAlmostEqual(float(r[3])/iters, 0.25, delta=.02)
        w = ChoiceSymbol([(1, 3), (2, 1), (3, 1)], _test=True)
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        self.assertAlmostEqual(float(r[1])/iters, 0.6, delta=.02)
        self.assertAlmostEqual(float(r[2])/iters, 0.2, delta=.02)
        self.assertAlmostEqual(float(r[3])/iters, 0.2, delta=.02)
        w = ChoiceSymbol([(1, 1), (2, 1), (3, 4)], _test=True)
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        self.assertAlmostEqual(float(r[1])/iters, 1.0/6, delta=.02)
        self.assertAlmostEqual(float(r[2])/iters, 1.0/6, delta=.02)
        self.assertAlmostEqual(float(r[3])/iters, 2.0/3, delta=.02)

    def test_funcs(self):
        iters = 10
        gram = "root            func{1,10}\n" \
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
        w = Grammar(gram, zero=zero, alpha=alpha)
        i = 0
        while i < iters:
            i += 1
            for line in w.generate().splitlines():
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

    def test_plus(self):
        self.balanced_choice("var     1 'a'\n"
                             "        1 'b'\n"
                             "        1 'c'\n"
                             "root    + var\n"
                             "        1 'd'",
                             ["a", "b", "c", "d"])
        with self.assertRaises(IntegrityError):
            Grammar("root + 'a'")
        self.balanced_choice("var     1 'a'\n"
                             "        1 'b'\n"
                             "        1 'c'\n"
                             "root    + 'A' var\n"
                             "        1 'd'",
                             ['Aa', 'Ab', 'Ac', 'd'])
        with self.assertRaises(IntegrityError):
            Grammar("root + a\n"
                    "a + root\n"
                    "  1 'a'")

    def test_basic(self):
        w = Grammar("root    ok\n"
                    "ok      '1'")
        self.assertEqual(w.generate(), "1")
        w = Grammar("root   a\n"
                    "a      '1234' /[a-z]/ b\n"
                    "b      1 c\n"
                    "       1 d\n"
                    "c      'C'\n"
                    "d      'D'")
        r = {"C": 0, "D": 0}
        for _ in range(1000):
            v = w.generate()
            self.assertRegex(v, r"^1234[a-z][CD]$")
            r[v[-1]] += 1
        self.assertAlmostEqual(r["C"], 500, delta=50)
        self.assertAlmostEqual(r["D"], 500, delta=50)

    def test_quo1(self):
        w = Grammar("root    '\\\\'")
        g = w.generate()
        self.assertEqual(g, "\\")
        w = Grammar("root    \"\\\\\"")
        g = w.generate()
        self.assertEqual(g, "\\")

    def test_quo2(self):
        w = Grammar("root    '\\''")
        g = w.generate()
        self.assertEqual(g, "'")
        w = Grammar("root    \"\\\"\"")
        g = w.generate()
        self.assertEqual(g, "\"")

    def test_quo3(self):
        w = Grammar("root    '\\'some'")
        g = w.generate()
        self.assertEqual(g, "'some")
        w = Grammar("root    \"\\\"some\"")
        g = w.generate()
        self.assertEqual(g, "\"some")

    def test_quo4(self):
        w = Grammar("root    'some\\''")
        g = w.generate()
        self.assertEqual(g, "some'")
        w = Grammar("root    \"some\\\"\"")
        g = w.generate()
        self.assertEqual(g, "some\"")

    def test_quo5(self):
        # unbalanced parens, end paren is escaped .. should raise
        with self.assertRaises(ParseError):
            Grammar(r"root    '\\\\\\\'")
        with self.assertRaises(ParseError):
            Grammar(r'root    "\\\\\\\"')

    def test_quo6(self):
        w = Grammar(r"root    '\\\\\\\'\\'")
        g = w.generate()
        self.assertEqual(g, "\\\\\\'\\")
        w = Grammar(r'root    "\\\\\\\"\\"')
        g = w.generate()
        self.assertEqual(g, "\\\\\\\"\\")

    def test_quo7(self):
        w = Grammar("root    \"'some\"")
        g = w.generate()
        self.assertEqual(g, "'some")
        w = Grammar("root    '\"some'")
        g = w.generate()
        self.assertEqual(g, "\"some")

    def test_quo8(self):
        w = Grammar("root    \"'\"")
        g = w.generate()
        self.assertEqual(g, "'")
        w = Grammar("root    \"''\"")
        g = w.generate()
        self.assertEqual(g, "''")
        w = Grammar("root    \"'''\"")
        g = w.generate()
        self.assertEqual(g, "'''")
        w = Grammar("root    '\"'")
        g = w.generate()
        self.assertEqual(g, "\"")
        w = Grammar("root    '\"\"'")
        g = w.generate()
        self.assertEqual(g, "\"\"")
        w = Grammar("root    '\"\"\"'")
        g = w.generate()
        self.assertEqual(g, "\"\"\"")

    def test_quo9(self):
        #right: "<h5 id='id824837' onload='chat(\'id705147\',1,\' width=\\\'2pt\\\'\')'>"
        #                                                        ^  -- esc() --   ^
        #wrong: "<h5 id='id824837' onload='chat(\'id705147\',1,\\\' width=\\\'2pt\'\')'>"
        #                                                      ^  -- esc() --   ^
        w = Grammar("root   \"<h5 id='\" id \"' onload='\" esc(func) \"'>\"\n"
                    "id     'id' /[0-9]{6}/\n"
                    "func   \"chat('\" id \"',\" /[0-9]/ \",'\" esc(\" width='2pt'\") \"')\"\n"
                    , esc=lambda x: re.sub(r"('|\\)", r"\\\1", x))
        self.assertRegex(w.generate(), r"^<h5 id='id[0-9]{6}' onload='chat\(\\'id[0-9]{6}"
                                       r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$")
        # same grammar with '@id' in chat() instead of 'id'
        w = Grammar("root   \"<h5 id='\" id \"' onload='\" esc(func) \"'>\"\n"
                    "id     'id' /[0-9]{6}/\n"
                    "func   \"chat('\" @id \"',\" /[0-9]/ \",'\" esc(\" width='2pt'\") \"')\"\n"
                    , esc=lambda x: re.sub(r"('|\\)", r"\\\1", x))
        self.assertRegex(w.generate(), r"^<h5 id='(id[0-9]{6})' onload='chat\(\\'\1"
                                       r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$")

    def test_func_nest_tracked(self):
        w = Grammar("root   id a(b(@id))\n"
                    "id     'i'\n"
                    , a=lambda x: "a" + x, b=lambda x: "b" + x)
        self.assertEqual(w.generate(), "iabi")

    def test_tracked1(self):
        w = Grammar("root    id '\\n' esc(\"'\" @id \"'\")\n"
                    "id      'id' /[0-9]/",
                    esc=lambda x: re.sub(r"'", "\\'", x))
        defn, use = w.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual(use, "\\'%s\\'" % defn)

    def test_tracked2(self):
        w = Grammar("root    id '\\n' esc('not', @id)\n"
                    "id      'id' /[0-9]/",
                    esc=lambda x, y: x)
        defn, use = w.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual(use, "not")

    def test_tracked3(self):
        w = Grammar("root    esc(id) '\\n' @id\n"
                    "id      'id' /[0-9]/",
                    esc=lambda x: "%s\n%s" % (x, "".join("%02x" % ord(c) for c in x)))
        defn, hexn, use = w.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual("".join("%02x" % ord(c) for c in defn), hexn)
        self.assertEqual(defn, use)

    def test_tracked4(self):
        w = Grammar("root    @id\n"
                    "id      'id' /[0-9]/")
        self.assertRegex(w.generate(), r"^id[0-9]$")

    def test_tracked5(self):
        w = Grammar("root    esc(id) @id\n"
                    "id      'id' /[0-9]/",
                    esc=lambda x: "")
        self.assertRegex(w.generate(), r"^id[0-9]$")

    def test_tyson(self):
        w = Grammar('root   /[0-1]{1}/ "]"')
        o = w.generate()
        self.assertIn(o, ["0]", "1]"])

    def test_bin(self):
        w = Grammar("root x'68656c6c6f2c20776f726c6400'")
        self.assertEqual(w.generate(), b"hello, world\0")

    def test_dashname(self):
        w = Grammar("root a-a\n"
                    "a-a 'a'\n")
        self.assertEqual(w.generate(), "a")

    def test_limit(self):
        w = Grammar("root       foo bar\n"
                    "bar        (@foo bar) {1}\n"
                    "foo        'i0'", limit=10)
        self.assertEqual(len(w.generate()), 10)

    def test_builtin_rndint(self):
        w = Grammar("root       rndint(1,10)")
        self.assertGreaterEqual(int(w.generate()), 1)
        self.assertLessEqual(int(w.generate()), 10)

    def test_builtin_rndflt(self):
        w = Grammar("root       rndflt(1,10)")
        self.assertGreaterEqual(float(w.generate()), 1)
        self.assertLessEqual(float(w.generate()), 10)

    def test_nested_choice_weight(self):
        w = Grammar("root a {1000}\n"
                    "b 9 'b'\n"
                    "a 1 'a'\n"
                    "  1 b")
        o = w.generate()
        a_count = len([c for c in o if c == 'a'])
        b_count = len(o) - a_count
        self.assertAlmostEqual(a_count, b_count, delta=len(o) * 0.2)

    def test_recursive_defn(self):
        with self.assertRaises(IntegrityError):
            Grammar("root root")

    def test_unused_sym(self):
        with self.assertRaisesRegex(IntegrityError, r'^Unused symbol:'):
            Grammar('root a\n'
                    'a "A"\n'
                    'b "B"')

    def test_unused_cycle(self):
        with self.assertRaises(IntegrityError):
            Grammar('root "A"\n'
                    'a b\n'
                    'b a')

    def test_repeat(self):
        g = Grammar('root "A"{1,10}')
        lengths = set()
        for _ in range(1000):
            w = g.generate()
            self.assertEqual(len(set(w)), 1)
            self.assertEqual(w[0], "A")
            self.assertIn(len(w), range(1, 11))
            lengths.add(len(w))
        self.assertEqual(len(lengths), 10)
        g = Grammar('root ("A" "B" ","){ 0 , 10 } "AB"')
        lengths = set()
        for _ in range(1000):
            w = g.generate().split(",")
            self.assertEqual(len(set(w)), 1)
            self.assertEqual(w[0], "AB")
            self.assertIn(len(w), range(1, 12))
            lengths.add(len(w))
        self.assertEqual(len(lengths), 11)

    def test_repeat_sample(self):
        with self.assertRaises(IntegrityError):
            Grammar('root "A" <1,10>')
        with self.assertRaises(IntegrityError):
            Grammar('root (a a) <1,10>\n'
                    'a 1 "A"')
        w = Grammar('root a<1,10>\n'
                    'a 1 "A"')
        for _ in range(100):
            self.assertEqual(w.generate(), "A")
        w = Grammar('root ("a" a)<1,10>\n'
                    'a 1 "A"')
        for _ in range(100):
            self.assertEqual(w.generate(), "aA")
        w = Grammar('root a<1,10>\n'
                    'a   "a" b\n'
                    'b 1 "A"')
        for _ in range(100):
            self.assertEqual(w.generate(), "aA")
        w = Grammar('root a <1,10>\n'
                    'a 9 "A"\n'
                    ' 1 "B"')
        outs = {"A": 0, "B": 0, "BA": 0, "AB": 0}
        for _ in range(1000):
            outs[w.generate()] += 1
        self.assertGreater(outs["AB"] + outs["BA"], outs["A"] + outs["B"])
        self.assertGreater(outs["AB"], outs["BA"])
        self.assertGreater(outs["A"], outs["B"])

    def test_unicode_in_hex(self):
        with self.assertRaises(ParseError):
            Grammar("root x'000ü'")

    def test_unicode(self):
        w = Grammar("root 'ü'")
        self.assertEqual(w.generate(), "ü")

    def test_impl_concat(self):
        w = Grammar("root ('a' 'b') 'c'")
        self.assertEqual(w.generate(), "abc")
        w = Grammar("root 'a' ('b') 'c'")
        self.assertEqual(w.generate(), "abc")
        w = Grammar("root 'a' ('b' 'c')")
        self.assertEqual(w.generate(), "abc")

    def test_maybe(self):
        g = Grammar('root "A"?')
        lengths = set()
        for _ in range(100):
            w = g.generate()
            self.assertIn(w, {"", "A"})
            lengths.add(len(w))
        self.assertEqual(len(lengths), 2)
        g = Grammar('root ("A" "B")?')
        lengths = set()
        for _ in range(100):
            w = g.generate()
            self.assertIn(w, {"", "AB"})
            lengths.add(len(w))
        self.assertEqual(len(lengths), 2)

    def test_regex(self):
        with self.assertRaises(ParseError):
            Grammar('root /[+-*]/')

    def test_plus_text(self):
        iters = 2000
        g = Grammar("root a\n"
                    "a + (b 'X')\n"
                    "  1 'c'\n"
                    "b 1 'a'\n"
                    "  1 'b'")
        r = {"c": 0, "aX": 0, "bX": 0}
        for _ in range(iters):
            r[g.generate()] += 1
        for v in r.values():
            self.assertAlmostEqual(float(v)/iters, 1.0/3, delta=0.04)

    def test_repeat_star(self):
        self.balanced_choice("root a<*>\n"
                             "a 1 'a'\n"
                             "  1 'b'",
                             ["ab", "ba"])
        g = Grammar("root a<0,*>\n"
                    "a 1 'a'\n"
                    "  1 'b'")
        r = {"ab": 0, "ba": 0, "a": 0, "b": 0, "": 0}
        for _ in range(1000):
            r[g.generate()] += 1
        self.assertGreater(r["a"] + r["b"], r["ab"] + r["ba"])
        self.assertGreater(r[""], r["a"] + r["b"])
        with self.assertRaises(IntegrityError):
            Grammar("root 'a'{*}")
        with self.assertRaises(IntegrityError):
            Grammar("root 'a'<*>")
        with self.assertRaises(IntegrityError):
            Grammar("root a{*,0}\n"
                    "a 1 'a'")
        g = Grammar("root a{*}\n"
                    "a 1 'a'\n")
        w = g.generate()
        self.assertEqual(set(w), {"a"})
        self.assertEqual(len(w), 1)

    def test_tracked_repeatsample(self):
        g = Grammar("root b<*> @b\n"
                    "a 1 /[0-9]/\n"
                    "b a 'A'")
        for _ in range(100):
            w = g.generate()
            self.assertEqual(len(w), 4)
            self.assertEqual(w[:2], w[2:])
        g = Grammar("root a<*> @a\n"
                    "a 1 b\n"
                    "b /[0-9]/")
        for _ in range(100):
            w = g.generate()
            self.assertEqual(len(w), 2)
            self.assertEqual(w[0], w[1])

    def test_altstart(self):
        "test that starting symbols other than 'root' work"
        gmr = Grammar("root a 'B'\n"
                      "a 'A'")
        self.assertEqual(gmr.generate(start='a'), 'A')

    def test_incomplete_sym_defn(self):
        "test incomplete symbol definitions raise ParseError"
        with self.assertRaises(ParseError):
            Grammar("root a\n"
                    "a")
        with self.assertRaises(ParseError):
            Grammar("root a\n"
                    "a  ")
        # just being mean here
        with self.assertRaises(ParseError):
            Grammar("root a\n"
                    "a\r\t")

    def balanced_choice(self, grammar, values, iters=2000):
        r = {v: 0 for v in values}
        g = Grammar(grammar)
        for _ in range(iters):
            r[g.generate()] += 1
        log.debug("balanced_repeat(%s) -> %s", values, r)
        for v in r.values():
            self.assertAlmostEqual(float(v)/iters, 1.0/len(values), delta=0.04)


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


class Backrefs(TestCase):

    def test_0(self):
        "test that basic backreferences work, generate a single digit and reference to it, make sure they match"
        gmr = Grammar("root  (/[0-9]/) @1")
        for _ in range(100):
            x1, x2 = gmr.generate()
            self.assertEqual(x1, x2)

    def test_1(self):
        "negative tests for backreferences, check use without declaration and use before declaration"
        with self.assertRaises(IntegrityError):
            Grammar("root  'a' @1")
        with self.assertRaises(IntegrityError):
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


class Imports(TestCase):

    def setUp(self):
        self.tmpd = tempfile.mkdtemp(prefix='gmrtesttmp')
        self.cwd = os.getcwd()
        os.chdir(self.tmpd)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmpd)

    def test_import_reserved(self):
        with self.assertRaises(ParseError):
            Grammar('import blah "blah.gmr"')

    def test_unused_import(self):
        open('blah.gmr', 'w').close()
        with self.assertRaisesRegex(IntegrityError, r'^Unused import'):
            Grammar("root 'a'\n"
                    "unused import('blah.gmr')")

    def test_use_before_import(self):
        with self.assertRaisesRegex(ParseError, r'^Attempt to use symbol from unknown prefix'):
            Grammar("root a.b")

    def test_notfound_import(self):
        with self.assertRaises(ParseError):
            Grammar("a import()")
        with self.assertRaisesRegex(IntegrityError, r'^Could not find imported grammar'):
            Grammar("a import('')")

    def test_simple(self):
        with open('a.gmr', 'w') as g:
            g.write('a "A"')
        w = Grammar("b import('a.gmr')\n"
                    "root b.a")
        self.assertEqual(w.generate(), 'A')

    def test_nested(self):
        with open('a.gmr', 'w') as g:
            g.write('b import("b.gmr")\n'
                    'root a b.a\n'
                    'a "A"')
        with open('b.gmr', 'w') as g:
            g.write('x import("a.gmr")\n'
                    'a @x.a')
        with open('a.gmr') as a:
            w = Grammar(a)
        self.assertEqual(w.generate(), "AA")

    def test_recursive_defn(self):
        with open('b.gmr', 'w') as g:
            g.write('b import("b.gmr")\n'
                    'root b.a\n'
                    'a b.a')
        with self.assertRaises(IntegrityError):
            with open('b.gmr') as b:
                Grammar(b)

    def test_unused_import_sym(self):
        with open('a.gmr', 'w') as g:
            g.write('a "A"\n'
                    'b "B"')
        w = Grammar('a import("a.gmr")\n'
                    'root a.a')
        self.assertEqual(w.generate(), "A")

    def test_imported_choice(self):
        with open('a.gmr', 'w') as g:
            g.write('a 1 "A"')
        w = Grammar("b import('a.gmr')\n"
                    "root a<*>\n"
                    "a b.a")
        self.assertEqual(w.generate(), 'A')


suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(t) for t in (Tests,
                                                                                         Inputs,
                                                                                         Backrefs,
                                                                                         Imports))

