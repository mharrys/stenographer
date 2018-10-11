//line parser.y:16

// Copyright 2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package query

import __yyfmt__ "fmt"

//line parser.y:30
import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

//line parser.y:43
type parserSymType struct {
	yys   int
	num   int
	ip    net.IP
	str   string
	query Query
	dur   time.Duration
	time  time.Time
}

const HOST = 57346
const PORT = 57347
const PROTO = 57348
const AND = 57349
const OR = 57350
const NET = 57351
const MASK = 57352
const TCP = 57353
const UDP = 57354
const ICMP = 57355
const BEFORE = 57356
const AFTER = 57357
const IPP = 57358
const AGO = 57359
const VLAN = 57360
const MPLS = 57361
const BETWEEN = 57362
const IP = 57363
const NUM = 57364
const DURATION = 57365
const TIME = 57366

var parserToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"HOST",
	"PORT",
	"PROTO",
	"AND",
	"OR",
	"NET",
	"MASK",
	"TCP",
	"UDP",
	"ICMP",
	"BEFORE",
	"AFTER",
	"IPP",
	"AGO",
	"VLAN",
	"MPLS",
	"BETWEEN",
	"IP",
	"NUM",
	"DURATION",
	"TIME",
	"'/'",
	"'('",
	"')'",
}
var parserStatenames = [...]string{}

const parserEofCode = 1
const parserErrCode = 2
const parserInitialStackSize = 16

//line parser.y:185
func ipsFromNet(ip net.IP, mask net.IPMask) (from, to net.IP, _ error) {
	if len(ip) != len(mask) || (len(ip) != 4 && len(ip) != 16) {
		return nil, nil, fmt.Errorf("bad IP or mask: %v %v", ip, mask)
	}
	from = make(net.IP, len(ip))
	to = make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		from[i] = ip[i] & mask[i]
		to[i] = ip[i] | ^mask[i]
	}
	return
}

// parserLex is used by the parser as a lexer.
// It must be named <prefix>Lex (where prefix is passed into go tool yacc with
// the -p flag).
type parserLex struct {
	now       time.Time // guarantees consistent time differences
	in        string
	pos       int
	out       Query
	err       error
	startTime time.Time
	stopTime  time.Time
}

// tokens provides a simple map for adding new keywords and mapping them
// to token types.
var tokens = map[string]int{
	"after":   AFTER,
	"ago":     AGO,
	"&&":      AND,
	"and":     AND,
	"before":  BEFORE,
	"host":    HOST,
	"icmp":    ICMP,
	"ip":      IPP,
	"mask":    MASK,
	"net":     NET,
	"||":      OR,
	"or":      OR,
	"port":    PORT,
	"vlan":    VLAN,
	"mpls":    MPLS,
	"proto":   PROTO,
	"tcp":     TCP,
	"udp":     UDP,
	"between": BETWEEN,
}

// Lex is called by the parser to get each new token.  This implementation
// is currently quite simplistic, but it seems to work pretty well for our
// needs.
//
// The type of the input argument must be *<prefix>SymType.
func (x *parserLex) Lex(yylval *parserSymType) (ret int) {
	for x.pos < len(x.in) && unicode.IsSpace(rune(x.in[x.pos])) {
		x.pos++
	}
	for t, i := range tokens {
		if strings.HasPrefix(x.in[x.pos:], t) {
			x.pos += len(t)
			return i
		}
	}
	s := x.pos
	var isIP, isDuration, isTime bool
L:
	for x.pos < len(x.in) {
		switch c := x.in[x.pos]; c {
		case ':', '.':
			isIP = true
			x.pos++
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f':
			x.pos++
		case 'm', 'h':
			x.pos++
			isDuration = true
			break L
		case '-', 'T', '+', 'Z':
			x.pos++
			isTime = true
		default:
			break L
		}
	}
	part := x.in[s:x.pos]
	switch {
	case isTime:
		t, err := time.Parse(time.RFC3339, part)
		if err != nil {
			x.Error(fmt.Sprintf("bad time %q", part))
		}
		yylval.time = t
		return TIME
	case isIP:
		yylval.ip = net.ParseIP(part)
		if yylval.ip == nil {
			x.Error(fmt.Sprintf("bad IP %q", part))
			return -1
		}
		if ip4 := yylval.ip.To4(); ip4 != nil {
			yylval.ip = ip4
		}
		return IP
	case isDuration:
		duration, err := time.ParseDuration(part)
		if err != nil {
			x.Error(fmt.Sprintf("bad duration %q", part))
		}
		yylval.dur = duration
		return DURATION
	case x.pos != s:
		n, err := strconv.Atoi(part)
		if err != nil {
			return -1
		}
		yylval.num = n
		return NUM
	case x.pos >= len(x.in):
		return 0
	}
	switch c := x.in[x.pos]; c {
	case ':', '.', '(', ')', '/':
		x.pos++
		return int(c)
	}
	return -1
}

// Error is called by the parser on a parse error.
func (x *parserLex) Error(s string) {
	if x.err == nil {
		x.err = fmt.Errorf("%v at character %v (%q HERE %q)", s, x.pos, x.in[:x.pos], x.in[x.pos:])
	}
}
func (x *parserLex) HandleBetween(startTime time.Time, stopTime time.Time) {
	if x.startTime.IsZero() || x.startTime.After(startTime) {
		x.startTime = startTime
	}
	if x.stopTime.IsZero() || x.stopTime.Before(stopTime) {
		x.stopTime = stopTime
	}
}
func (x *parserLex) HandleAfter(after time.Time) {
	if x.startTime.IsZero() || x.startTime.After(after) {
		x.startTime = after
	}
}
func (x *parserLex) HandleBefore(before time.Time) {
	if x.stopTime.IsZero() || x.stopTime.Before(before) {
		x.stopTime = before
	}
}

// parse parses an input string into a Query.
func parse(in string) (Query, time.Time, time.Time, error) {
	lex := &parserLex{in: in, now: time.Now(), startTime: time.Time{}, stopTime: time.Time{}}
	parserParse(lex)
	if lex.err != nil {
		return nil, time.Time{}, time.Time{}, lex.err
	}
	return lex.out, lex.startTime, lex.stopTime, nil
}

//line yacctab:1
var parserExca = [...]int{
	-1, 1,
	1, -1,
	-2, 0,
}

const parserPrivate = 57344

const parserLast = 44

var parserAct = [...]int{

	26, 28, 27, 39, 35, 33, 17, 18, 22, 21,
	20, 40, 24, 4, 5, 3, 29, 30, 9, 34,
	11, 12, 13, 14, 15, 8, 36, 6, 7, 16,
	37, 19, 2, 31, 32, 10, 17, 18, 38, 41,
	23, 1, 0, 25,
}
var parserPact = [...]int{

	9, -1000, 29, -1000, 10, -12, -13, -14, 34, -9,
	9, -1000, -1000, -1000, -22, -22, -22, 9, 9, -1000,
	-1000, -1000, -1000, -17, -6, -1, -1000, -1000, 13, -1000,
	31, -1000, -1000, -1000, -19, -10, -1000, -1000, -22, -1000,
	-1000, -1000,
}
var parserPgo = [...]int{

	0, 41, 32, 15, 0,
}
var parserR1 = [...]int{

	0, 1, 2, 2, 2, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 4,
	4,
}
var parserR2 = [...]int{

	0, 1, 1, 3, 3, 2, 2, 2, 2, 3,
	4, 4, 3, 1, 1, 1, 2, 2, 4, 1,
	2,
}
var parserChk = [...]int{

	-1000, -1, -2, -3, 4, 5, 18, 19, 16, 9,
	26, 11, 12, 13, 14, 15, 20, 7, 8, 21,
	22, 22, 22, 6, 21, -2, -4, 24, 23, -4,
	-4, -3, -3, 22, 25, 10, 27, 17, 7, 22,
	21, -4,
}
var parserDef = [...]int{

	0, -2, 1, 2, 0, 0, 0, 0, 0, 0,
	0, 13, 14, 15, 0, 0, 0, 0, 0, 5,
	6, 7, 8, 0, 0, 0, 16, 19, 0, 17,
	0, 3, 4, 9, 0, 0, 12, 20, 0, 10,
	11, 18,
}
var parserTok1 = [...]int{

	1, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	26, 27, 3, 3, 3, 3, 3, 25,
}
var parserTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24,
}
var parserTok3 = [...]int{
	0,
}

var parserErrorMessages = [...]struct {
	state int
	token int
	msg   string
}{}

//line yaccpar:1

/*	parser for yacc output	*/

var (
	parserDebug        = 0
	parserErrorVerbose = false
)

type parserLexer interface {
	Lex(lval *parserSymType) int
	Error(s string)
	HandleBetween(startTime time.Time, stopTime time.Time)
	HandleAfter(after time.Time)
	HandleBefore(before time.Time)
}

type parserParser interface {
	Parse(parserLexer) int
	Lookahead() int
}

type parserParserImpl struct {
	lval  parserSymType
	stack [parserInitialStackSize]parserSymType
	char  int
}

func (p *parserParserImpl) Lookahead() int {
	return p.char
}

func parserNewParser() parserParser {
	return &parserParserImpl{}
}

const parserFlag = -1000

func parserTokname(c int) string {
	if c >= 1 && c-1 < len(parserToknames) {
		if parserToknames[c-1] != "" {
			return parserToknames[c-1]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func parserStatname(s int) string {
	if s >= 0 && s < len(parserStatenames) {
		if parserStatenames[s] != "" {
			return parserStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func parserErrorMessage(state, lookAhead int) string {
	const TOKSTART = 4

	if !parserErrorVerbose {
		return "syntax error"
	}

	for _, e := range parserErrorMessages {
		if e.state == state && e.token == lookAhead {
			return "syntax error: " + e.msg
		}
	}

	res := "syntax error: unexpected " + parserTokname(lookAhead)

	// To match Bison, suggest at most four expected tokens.
	expected := make([]int, 0, 4)

	// Look for shiftable tokens.
	base := parserPact[state]
	for tok := TOKSTART; tok-1 < len(parserToknames); tok++ {
		if n := base + tok; n >= 0 && n < parserLast && parserChk[parserAct[n]] == tok {
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}
	}

	if parserDef[state] == -2 {
		i := 0
		for parserExca[i] != -1 || parserExca[i+1] != state {
			i += 2
		}

		// Look for tokens that we accept or reduce.
		for i += 2; parserExca[i] >= 0; i += 2 {
			tok := parserExca[i]
			if tok < TOKSTART || parserExca[i+1] == 0 {
				continue
			}
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}

		// If the default action is to accept or reduce, give up.
		if parserExca[i+1] != 0 {
			return res
		}
	}

	for i, tok := range expected {
		if i == 0 {
			res += ", expecting "
		} else {
			res += " or "
		}
		res += parserTokname(tok)
	}
	return res
}

func parserlex1(lex parserLexer, lval *parserSymType) (char, token int) {
	token = 0
	char = lex.Lex(lval)
	if char <= 0 {
		token = parserTok1[0]
		goto out
	}
	if char < len(parserTok1) {
		token = parserTok1[char]
		goto out
	}
	if char >= parserPrivate {
		if char < parserPrivate+len(parserTok2) {
			token = parserTok2[char-parserPrivate]
			goto out
		}
	}
	for i := 0; i < len(parserTok3); i += 2 {
		token = parserTok3[i+0]
		if token == char {
			token = parserTok3[i+1]
			goto out
		}
	}

out:
	if token == 0 {
		token = parserTok2[1] /* unknown char */
	}
	if parserDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", parserTokname(token), uint(char))
	}
	return char, token
}

func parserParse(parserlex parserLexer) int {
	return parserNewParser().Parse(parserlex)
}

func (parserrcvr *parserParserImpl) Parse(parserlex parserLexer) int {
	var parsern int
	var parserVAL parserSymType
	var parserDollar []parserSymType
	_ = parserDollar // silence set and not used
	parserS := parserrcvr.stack[:]

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	parserstate := 0
	parserrcvr.char = -1
	parsertoken := -1 // parserrcvr.char translated into internal numbering
	defer func() {
		// Make sure we report no lookahead when not parsing.
		parserstate = -1
		parserrcvr.char = -1
		parsertoken = -1
	}()
	parserp := -1
	goto parserstack

ret0:
	return 0

ret1:
	return 1

parserstack:
	/* put a state and value onto the stack */
	if parserDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", parserTokname(parsertoken), parserStatname(parserstate))
	}

	parserp++
	if parserp >= len(parserS) {
		nyys := make([]parserSymType, len(parserS)*2)
		copy(nyys, parserS)
		parserS = nyys
	}
	parserS[parserp] = parserVAL
	parserS[parserp].yys = parserstate

parsernewstate:
	parsern = parserPact[parserstate]
	if parsern <= parserFlag {
		goto parserdefault /* simple state */
	}
	if parserrcvr.char < 0 {
		parserrcvr.char, parsertoken = parserlex1(parserlex, &parserrcvr.lval)
	}
	parsern += parsertoken
	if parsern < 0 || parsern >= parserLast {
		goto parserdefault
	}
	parsern = parserAct[parsern]
	if parserChk[parsern] == parsertoken { /* valid shift */
		parserrcvr.char = -1
		parsertoken = -1
		parserVAL = parserrcvr.lval
		parserstate = parsern
		if Errflag > 0 {
			Errflag--
		}
		goto parserstack
	}

parserdefault:
	/* default state action */
	parsern = parserDef[parserstate]
	if parsern == -2 {
		if parserrcvr.char < 0 {
			parserrcvr.char, parsertoken = parserlex1(parserlex, &parserrcvr.lval)
		}

		/* look through exception table */
		xi := 0
		for {
			if parserExca[xi+0] == -1 && parserExca[xi+1] == parserstate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			parsern = parserExca[xi+0]
			if parsern < 0 || parsern == parsertoken {
				break
			}
		}
		parsern = parserExca[xi+1]
		if parsern < 0 {
			goto ret0
		}
	}
	if parsern == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			parserlex.Error(parserErrorMessage(parserstate, parsertoken))
			Nerrs++
			if parserDebug >= 1 {
				__yyfmt__.Printf("%s", parserStatname(parserstate))
				__yyfmt__.Printf(" saw %s\n", parserTokname(parsertoken))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for parserp >= 0 {
				parsern = parserPact[parserS[parserp].yys] + parserErrCode
				if parsern >= 0 && parsern < parserLast {
					parserstate = parserAct[parsern] /* simulate a shift of "error" */
					if parserChk[parserstate] == parserErrCode {
						goto parserstack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if parserDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", parserS[parserp].yys)
				}
				parserp--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if parserDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", parserTokname(parsertoken))
			}
			if parsertoken == parserEofCode {
				goto ret1
			}
			parserrcvr.char = -1
			parsertoken = -1
			goto parsernewstate /* try again in the same state */
		}
	}

	/* reduction by production parsern */
	if parserDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", parsern, parserStatname(parserstate))
	}

	parsernt := parsern
	parserpt := parserp
	_ = parserpt // guard against "declared and not used"

	parserp -= parserR2[parsern]
	// parserp is now the index of $0. Perform the default action. Iff the
	// reduced production is ε, $1 is possibly out of range.
	if parserp+1 >= len(parserS) {
		nyys := make([]parserSymType, len(parserS)*2)
		copy(nyys, parserS)
		parserS = nyys
	}
	parserVAL = parserS[parserp+1]

	/* consult goto table to find next state */
	parsern = parserR1[parsern]
	parserg := parserPgo[parsern]
	parserj := parserg + parserS[parserp].yys + 1

	if parserj >= parserLast {
		parserstate = parserAct[parserg]
	} else {
		parserstate = parserAct[parserj]
		if parserChk[parserstate] != -parsern {
			parserstate = parserAct[parserg]
		}
	}
	// dummy call; replaced with literal code
	switch parsernt {

	case 1:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:65
		{
			parserlex.(*parserLex).out = parserDollar[1].query
		}
	case 3:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:72
		{
			parserVAL.query = intersectQuery{parserDollar[1].query, parserDollar[3].query}
		}
	case 4:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:76
		{
			parserVAL.query = unionQuery{parserDollar[1].query, parserDollar[3].query}
		}
	case 5:
		parserDollar = parserS[parserpt-2 : parserpt+1]
		//line parser.y:82
		{
			parserVAL.query = ipQuery{parserDollar[2].ip, parserDollar[2].ip}
		}
	case 6:
		parserDollar = parserS[parserpt-2 : parserpt+1]
		//line parser.y:86
		{
			if parserDollar[2].num < 0 || parserDollar[2].num >= 65536 {
				parserlex.Error(fmt.Sprintf("invalid port %v", parserDollar[2].num))
			}
			parserVAL.query = portQuery(parserDollar[2].num)
		}
	case 7:
		parserDollar = parserS[parserpt-2 : parserpt+1]
		//line parser.y:93
		{
			if parserDollar[2].num < 0 || parserDollar[2].num >= 65536 {
				parserlex.Error(fmt.Sprintf("invalid vlan %v", parserDollar[2].num))
			}
			parserVAL.query = vlanQuery(parserDollar[2].num)
		}
	case 8:
		parserDollar = parserS[parserpt-2 : parserpt+1]
		//line parser.y:100
		{
			if parserDollar[2].num < 0 || parserDollar[2].num >= (1<<20) {
				parserlex.Error(fmt.Sprintf("invalid mpls %v", parserDollar[2].num))
			}
			parserVAL.query = mplsQuery(parserDollar[2].num)
		}
	case 9:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:107
		{
			if parserDollar[3].num < 0 || parserDollar[3].num >= 256 {
				parserlex.Error(fmt.Sprintf("invalid proto %v", parserDollar[3].num))
			}
			parserVAL.query = protocolQuery(parserDollar[3].num)
		}
	case 10:
		parserDollar = parserS[parserpt-4 : parserpt+1]
		//line parser.y:114
		{
			mask := net.CIDRMask(parserDollar[4].num, len(parserDollar[2].ip)*8)
			if mask == nil {
				parserlex.Error(fmt.Sprintf("bad cidr: %v/%v", parserDollar[2].ip, parserDollar[4].num))
			}
			from, to, err := ipsFromNet(parserDollar[2].ip, mask)
			if err != nil {
				parserlex.Error(err.Error())
			}
			parserVAL.query = ipQuery{from, to}
		}
	case 11:
		parserDollar = parserS[parserpt-4 : parserpt+1]
		//line parser.y:126
		{
			from, to, err := ipsFromNet(parserDollar[2].ip, net.IPMask(parserDollar[4].ip))
			if err != nil {
				parserlex.Error(err.Error())
			}
			parserVAL.query = ipQuery{from, to}
		}
	case 12:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:134
		{
			parserVAL.query = parserDollar[2].query
		}
	case 13:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:138
		{
			parserVAL.query = protocolQuery(6)
		}
	case 14:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:142
		{
			parserVAL.query = protocolQuery(17)
		}
	case 15:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:146
		{
			parserVAL.query = protocolQuery(1)
		}
	case 16:
		parserDollar = parserS[parserpt-2 : parserpt+1]
		//line parser.y:150
		{
			parserlex.HandleBefore(parserDollar[2].time)
			var t timeQuery
			t[1] = parserDollar[2].time
			parserVAL.query = t
		}
	case 17:
		parserDollar = parserS[parserpt-2 : parserpt+1]
		//line parser.y:157
		{
			parserlex.HandleAfter(parserDollar[2].time)
			var t timeQuery
			t[0] = parserDollar[2].time
			parserVAL.query = t
		}
	case 18:
		parserDollar = parserS[parserpt-4 : parserpt+1]
		//line parser.y:164
		{
			if parserDollar[2].time.After(parserDollar[4].time) {
				parserlex.Error(fmt.Sprintf("first timestamp %s must be less than or equal to second timestamp %s", parserDollar[2].time, parserDollar[4].time))
			}
			parserlex.HandleBetween(parserDollar[2].time, parserDollar[4].time)
			var t timeQuery
			t[0] = parserDollar[2].time
			t[1] = parserDollar[4].time
			parserVAL.query = t
		}
	case 19:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:177
		{
			parserVAL.time = parserDollar[1].time
		}
	case 20:
		parserDollar = parserS[parserpt-2 : parserpt+1]
		//line parser.y:181
		{
			parserVAL.time = parserlex.(*parserLex).now.Add(-parserDollar[1].dur)
		}
	}
	goto parserstack /* stack new state and value */
}
