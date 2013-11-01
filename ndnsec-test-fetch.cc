/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <iostream>
#include <fstream>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/bind.hpp>
#include <cryptopp/base64.h>

#include "ndn.cxx/security/keychain.h"
#include "ndn.cxx/security/policy/simple-policy-manager.h"
#include "ndn.cxx/security/policy/identity-policy-rule.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/wrapper/wrapper.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

//fake ndn dsk
const string TrustAnchor("BIICqgOyEIVThxc06RYumoYxgALOwwUynYHB1eod4Vh8OjjTTfPMZlwXQm67RU+n\n\
/JmYpQFCFEWFhERXKht04287YVbuamIl4SXpegnreMt2u2Aa3O5acSVjSdYJJZL+\n\
JmzKhmzzs2RP1j/yUfhjyuz8sh8NMDXjUuSQV/vqkTMWEVY6UZCw5qQjICQ+GZlI\n\
keedCmMBwiJxiaVS6QT3fYaiMrpxh6IzhIwQviUAH0hWqYKde4ntlcN34JhEwVBI\n\
c6nVFcyu0d+cjA+Mgb2MWU2Uuk9JWUQQqJ8GOlv5nOOF7LIHeDE8AQHQzyHSR0Wt\n\
yvPwXsXK69v2sLWkoALWqRrJpJfPigp/AADy+p1uZG4A+p1LRVkA+vVkc2stMTM4\n\
MjkzNDE5OQD6vUlELUNFUlQA+s39/////95rgD4AAAGiA+IChVIS35j29MVc/U4Q\n\
MSWdgCkhTqee64j7OWDpMCFtYfGfAAK6tQUm3muAPwAB4gHq8vqdbmRuAPqdS0VZ\n\
APr1a3NrLTEzODI5MzQxOTgA+r1JRC1DRVJUAAAAAAABmhblMIIBaDAiGA8yMDEz\n\
MTAyODAwMDAwMFoYDzIwMzMxMDI4MDAwMDAwWjAcMBoGA1UEKRMTL25kbi9kc2st\n\
MTM4MjkzNDE5OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALdIZxR9\n\
3ue1Ne6Hd7DcMDByOoKpZJG+tbK6kRi9rHvb611vTTbevhl2CYMqKx0XihgBTX0v\n\
Dwz9dP+q0JXA8nmbHSQsk0xDq9Z01iwrUZ9OMDlyQzyg0eYmkZLKkFNsVgH4vjfK\n\
4jVHsdL5ukpTITzH8uxyAmTxhdkvsrNMRDop2F7zHEpELNHvgYZuP8FOLe9wFYzV\n\
B4hqupGk+yoTbnckXjqd20XKs9hOKPwP5TcSLCh8VBEWwtMCA1RVOMG+FG/QDRIv\n\
502gfbdT4upYvpT8f9R62DYVu5RO8q3Zhiv9Dlo+SkoexFqRTQTHl7dzkZAC3RPT\n\
1JdtPEZZ9fhavPMCAwEAAQAA");

//fake yingdi dsk
const string TrustAnchor2("BIICqgOyEIVKoOQc2xkFz35uN98Cjd1wkhOLu/LDCkRN6YW/xoODy/G0/KeKS3yB\n\
I6hYaxOnuAx38V/ZwU2Mha1YXiGhdZfyu3pJYtkikPG3clJP2Xm+OaxhVcGdZODw\n\
W9x0cOCOIDsYT2MKOauaMJdOrAj9iXIMDWT60qKvGl48fEsv3aRE998VQg6S5B4V\n\
addIWm/uM1n7QKX70UJFj5BB0mJsPL/3+djsEmHmdBncntOIafglFibFrBNVTZW4\n\
p99V29PZZ3MGVnCKYCnzi2RmjGARGCpMehBACEtC08NhDO5yQVG93DToRKB+lyHI\n\
Wev3SheZ1JgkB91N5Y8gMV87s2u03c+VAADy+p1uZG4A+p1LRVkA+p1lZHUA+qV1\n\
Y2xhAPqVY3MA+rV5aW5nZGkA+vVkc2stMTM4Mjk5MDE5MgD6vUlELUNFUlQA+q39\n\
M+qZRAAAAaID4gKFUhLfmPb0xVz9ThAxJZ2AKSFOp57riPs5YOkwIW1h8Z8AArq1\n\
BScz6plEAAHiAery+p1uZG4A+p1LRVkA+vVkc2stMTM4MjkzNDE5OQD6vUlELUNF\n\
UlQAAAAAAAGaFf0wggFbMCIYDzIwMTMxMTAxMDUzOTUzWhgPMjAxNDExMDEwNTM5\n\
NTNaMA8wDQYDVQQpEwZ5aW5nZGkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
AoIBAQC0IIZBY24PaN3vsquYhgWSKP5RaEJsM1RgzofZ/tgnU3EpTMbvL4QQnMke\n\
2edbs+ZGcgarXiEL489Bqahyla4QDVuf3/UBaN+7ewxT/3kQMuu4J6tBhQ/JlbtO\n\
kS9uWDKULTmPchUxkZK8mtwIv6CPpvxoc831u6BmX3iGPUwqGOIAVy9Rtv/Pgzvp\n\
3jbUqhsUAuGDf0sFz5ITxZNRXTGds4i30TWSQTj/zBIWaBd3EjXxFO6OA7Nw2Q/+\n\
tBBTIaibU+2KQIiBZe8E3zT6By5aOywe7a70HWzg8McyWRBKhTVpWW8qcI9Q/bri\n\
LHEPFRLvc0A6Wlr0N6YBhD4A3bJtAgMBAAEAAA==");

//ucla ksk
// const string TrustAnchor("BIICqgOyEIXFgp2L4jkwfE2j9sCAPTjR5Ng4ORcp6Gz0At6W6hQD5n50raHbbOoL\n\
// rh0eAl0yBttNFfXcSPatvt6lhEbLCBdSnrO3yw8fQizVEIX8SlgCXKtOHciayZSa\n\
// HobSyu2YoqAQ67BJb5mg7Q386mJ62mh69BO7/yQdvPxzP9DBydCoOSzG5Z6QmEqI\n\
// r5TREo63C7gDljQh6FOI1SRoRbM0OZjO0IIgEPJA/l57+yyBzCx6gKgItieA+WMT\n\
// rH9/y6tGM+2yzmaDWRSa3WW36SuE2LYw4nWlUCKDx4HRtS0iozTkH1c0t6iMfr6w\n\
// i1Yi2qRYM6OXR5wA50WL1Fl0br0QJpXaAADy+p1uZG4A+p1LRVkA+p1lZHUA+qV1\n\
// Y2xhAPr1a3NrLTEzODI5ODE3MzUA+r1JRC1DRVJUAPrN/f/////q8KARAAABogPi\n\
// AoWH1VkfWrBdSqM7xvLHgsYCdmnSsjMMEOqIRgiVGNqHYAACurUFJurwoBIAAeIB\n\
// 6vL6nW5kbgD6nUtFWQD69WRzay0xMzgyOTg1MTUzAPq9SUQtQ0VSVAAAAAAAAZoX\n\
// 5TCCAXgwIhgPMjAxMzEwMjYwMDAwMDBaGA8yMDE0MTIzMTIzNTk1OVowLjAsBgNV\n\
// BCkTJVVuaXZlcnNpdHkgb2YgQ2FsaWZvcm5pYSwgTG9zIEFuZ2VsZXMwggEgMA0G\n\
// CSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQDO5RChXbLlBDBJxTj0Rpg9B6ZYHaax\n\
// /HdMqDB6gP3DCd8oNnriRaCbpTopw9nndc2SYzxaFQ9ivBiuc6UowuO+fS2qOCHo\n\
// biSXCzE/1pDgZaKP9qdMCOt1EchnoVZ7THMI9sJ7UOz6fgv/aLnni3bXckpGKcw2\n\
// zpiT3d6KW1rbr93rjWRBSrvI4L0tl8TTtobfVb0Lm7k9fW/0a7ZQDBdBMNnnyKmh\n\
// 2Z8mFeY6PfwhDIlfJ3N26/yfRNBXMu1NPkDZSuxvkO/DJt97R8lQWtk1fR8GcrX6\n\
// VeU/wHFGhiTD6rhNP7zK5sE6LfQcQUFVxJYdrCLRctik/kPz0IQLCGhLAgERAAA=");

//ucla dsk
// const string TrustAnchor2("BIICqgOyEIUGFFQ197c/dxgQdRsOMakUb8izkjhHbmh+BoVFp1pYk7HXg9uQUsma\n\
// J6xLSyqotCX8WGPpAU3EYXFewPNpqu/M5OKIU6tLP1oLsz2peVki453svWZ9WWf+\n\
// tmbqLh1xpq0wCD/Xyy6I8sp1NBoMocJRfLHfRVaW1UxeD5Juqw5fgYHC2NV1t/wS\n\
// CA/bfe9dqqtK2ut/FT7OOoTUW6+z6sL0crVERuyGfxS+Xg4jFPrq/Q6gqYguXZTq\n\
// o5VvQW4fDBxs+nB8NtFFkN8NTgw3Xy8VkSi6V3tGpPJAEO3+AK0UQzASO57rJ/hi\n\
// dXeqRNY7nU5mJrbTxudo6U3RLYuZl0hbAADy+p1uZG4A+p1lZHUA+qV1Y2xhAPqd\n\
// S0VZAPr1ZHNrLTEzODI5ODU2NzkA+r1JRC1DRVJUAPrN/f/////q/QTlAAABogPi\n\
// AoXh6z6HBMjKp9Dnbqxwz7U/PVgLd8laFNFYwQbo14wI0gACurUFJur9BOYAAeIB\n\
// 6vL6nW5kbgD6nUtFWQD6nWVkdQD6pXVjbGEA+vVrc2stMTM4Mjk4MTczNQD6vUlE\n\
// LUNFUlQAAAAAAAGaF+UwggF4MCIYDzIwMTMxMDI2MDAwMDAwWhgPMjAxNDEyMzEy\n\
// MzU5NTlaMC4wLAYDVQQpEyVVbml2ZXJzaXR5IG9mIENhbGlmb3JuaWEsIExvcyBB\n\
// bmdlbGVzMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAwEjmVERJe/DH\n\
// /c7Cb/KR2hngewPt9fXTi6KmuGTYvNHuIQ3DOvQ7CIc+la+t5ij0Hgh/HVMJEh1G\n\
// Mm+qYpa+ULagmuU1CnSzaC43Xv/ljrNweH2wGc7OHPqjH4tnYqPHBSA4fTUBXb+K\n\
// 4jmk4BwaIayxWJ2SrwJQz1yxtS31r9Q8BjL/6BTzEyaYvuHGsgH+qwwjbnvBSOsC\n\
// jhEZDNE+A4h2t506WSOSZgh/dZwLDuIcWBZ63gSuXFFh2FCHOso30zOXy0gWuDdS\n\
// J+u4cfUVF0l04OHTHlJaAqZnP5Hp7PJJD/4BvCrGccdA1lBvU7Hu2vXoh8pu4lNh\n\
// zhPPDRc7gQIBEQAA");

//yingdi ksk
// const string TrustAnchor2("BIICqgOyEIV//JAhxtWh+tbx6kw0XflIHNN937Lu3/ftZOYSoePwBjqSRTdrGWui\n\
// TonzKdXO803cOukvkKZz/B1nlpnkBqMXT8mnQwytyDLgQKzdQDNu4lOJ0/EYm4Nn\n\
// dh/W7ck4v+FmKp3IruuQU7qgCQ2y/WVHgoWzvY82VlNfn+ZLMaipE0kNInKDY9Xb\n\
// dD289fmPFEaeNmDMigFmBkYGceI9VV4J2G3Q6SZ6PzxjKhZzmAO2IDRsw07RM6/6\n\
// 8veTU6Ki8yL117QnF1SBZuPDp2nshh5xbtyXX6z0xdj28RpyaIGZvxYi8KEtPPUt\n\
// EdAywzKlrvzOrM82wHUYRNdvdK670N3vAADy+p1uZG4A+p1lZHUA+qV1Y2xhAPqd\n\
// S0VZAPqVY3MA+rV5aW5nZGkA+vVrc2stMTM4Mjk4NjQzNAD6vUlELUNFUlQA+s39\n\
// /////+s4KRoAAAGiA+IChex+Odvz1s5qxSfeg6hRMu8+ZTgnlPG+6B1pzeeSMUvk\n\
// AAK6tQUm6zgpGgAB4gHq8vqdbmRuAPqdZWR1APqldWNsYQD6nUtFWQD69WRzay0x\n\
// MzgyOTg1Njc5APq9SUQtQ0VSVAAAAAAAAZog5TCCAggwIhgPMjAxMzEwMjcxODU3\n\
// MDZaGA8yMDE0MTAyODE4NTcwNlowgbswEAYDVQQpEwlZaW5nZGkgWXUwHwYJKoZI\n\
// hvcNAQkBExJ5aW5nZGlAY3MudWNsYS5lZHUwLAYDVQQLEyVVbml2ZXJzaXR5IG9m\n\
// IENhbGlmb3JuaWEsIExvcyBBbmdlbGVzMBwGA1UEARMVSW50ZXJuZXQgUmVzZWFy\n\
// Y2ggTGFiMCYGA1UEAxMfaHR0cDovL2lybC5jcy51Y2xhLmVkdS9+eWluZ2RpLzAS\n\
// BgNVBFATC0xpeGlhIFpoYW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n\
// AQEAsO0Jvt3I/0p2w/93RylU2pmbqHMzrjn7NAiTBLIFI0NZRHwJ2XedrtdEEC2d\n\
// NPd+auhX/h9q9xzlLQuEx6wekgvLHbwpr9sbV7ZKpDiluyvtXsemZWnYr8jRs4rb\n\
// I1f1PYGJY0bfRhXlPVjDOSlAqL6jBAhF5SY2aRKJ47z7PiJ21nTGz7T+3hxMU4CW\n\
// Rr6TpwnJ+USB2++LIcmrNHyJ0W+C3ZQkGH/ddUsAan063SRL9SAmNqrBPlBuhNb4\n\
// mUyjAu0VtOB7rj7tcJTSSdkYZ5tR/4FjupdvlQbcELa5uraytKVgBvCFU2EBoqJK\n\
// h7bEV6G02Rxv4ELWbxXz2GiHfwIDAQABAAA=");

//yingdi ksk
// const string TrustAnchor("BIICqgOyEIV//JAhxtWh+tbx6kw0XflIHNN937Lu3/ftZOYSoePwBjqSRTdrGWui\n\
// TonzKdXO803cOukvkKZz/B1nlpnkBqMXT8mnQwytyDLgQKzdQDNu4lOJ0/EYm4Nn\n\
// dh/W7ck4v+FmKp3IruuQU7qgCQ2y/WVHgoWzvY82VlNfn+ZLMaipE0kNInKDY9Xb\n\
// dD289fmPFEaeNmDMigFmBkYGceI9VV4J2G3Q6SZ6PzxjKhZzmAO2IDRsw07RM6/6\n\
// 8veTU6Ki8yL117QnF1SBZuPDp2nshh5xbtyXX6z0xdj28RpyaIGZvxYi8KEtPPUt\n\
// EdAywzKlrvzOrM82wHUYRNdvdK670N3vAADy+p1uZG4A+p1lZHUA+qV1Y2xhAPqd\n\
// S0VZAPqVY3MA+rV5aW5nZGkA+vVrc2stMTM4Mjk4NjQzNAD6vUlELUNFUlQA+s39\n\
// /////+s4KRoAAAGiA+IChex+Odvz1s5qxSfeg6hRMu8+ZTgnlPG+6B1pzeeSMUvk\n\
// AAK6tQUm6zgpGgAB4gHq8vqdbmRuAPqdZWR1APqldWNsYQD6nUtFWQD69WRzay0x\n\
// MzgyOTg1Njc5APq9SUQtQ0VSVAAAAAAAAZog5TCCAggwIhgPMjAxMzEwMjcxODU3\n\
// MDZaGA8yMDE0MTAyODE4NTcwNlowgbswEAYDVQQpEwlZaW5nZGkgWXUwHwYJKoZI\n\
// hvcNAQkBExJ5aW5nZGlAY3MudWNsYS5lZHUwLAYDVQQLEyVVbml2ZXJzaXR5IG9m\n\
// IENhbGlmb3JuaWEsIExvcyBBbmdlbGVzMBwGA1UEARMVSW50ZXJuZXQgUmVzZWFy\n\
// Y2ggTGFiMCYGA1UEAxMfaHR0cDovL2lybC5jcy51Y2xhLmVkdS9+eWluZ2RpLzAS\n\
// BgNVBFATC0xpeGlhIFpoYW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n\
// AQEAsO0Jvt3I/0p2w/93RylU2pmbqHMzrjn7NAiTBLIFI0NZRHwJ2XedrtdEEC2d\n\
// NPd+auhX/h9q9xzlLQuEx6wekgvLHbwpr9sbV7ZKpDiluyvtXsemZWnYr8jRs4rb\n\
// I1f1PYGJY0bfRhXlPVjDOSlAqL6jBAhF5SY2aRKJ47z7PiJ21nTGz7T+3hxMU4CW\n\
// Rr6TpwnJ+USB2++LIcmrNHyJ0W+C3ZQkGH/ddUsAan063SRL9SAmNqrBPlBuhNb4\n\
// mUyjAu0VtOB7rj7tcJTSSdkYZ5tR/4FjupdvlQbcELa5uraytKVgBvCFU2EBoqJK\n\
// h7bEV6G02Rxv4ELWbxXz2GiHfwIDAQABAAA=");

//yingdi dsk
// const string TrustAnchor2("BIICqgOyEIWOZfhME/VrrrvZ/scOVRah4ru75vB4HpA2iJlCHaUzZmnPcbIkbwT2\n\
// c/vTrChlInF5YIk3dWRIIVgj14WBXu6wGFpc2HJs7QfbXRKfoAKmlXVLywKif4nV\n\
// dwffNwzXXGFd/wdnUobox/hIBEuTkf9aALJZGy8nI2MZdxIeVbSM39yA4yPTAj8s\n\
// DloqBrnglaRhhDFqquMTA8dm9y4fP7YTMD2GTgUuw3w3ipd6Hjj96NVC+u8LoC9b\n\
// H8/Wh8JImTHa1SYya5FQjorubKkpI383S8uxvDuAy7GcRl2VX+mpD7/RfmeN4yJC\n\
// tPhLzD3GE1c2l2UEULHLq9vZIDYX6vrLAADy+p1uZG4A+p1lZHUA+qV1Y2xhAPqV\n\
// Y3MA+rV5aW5nZGkA+p1LRVkA+vVkc2stMTM4Mjk5MDE5MgD6vUlELUNFUlQA+s39\n\
// /////+wXGXwAAAGiA+IChdHNS5nrnly5pDilotHEh6sDmyfNyfuD18aCztLavWoj\n\
// AAK6tQUm7BcZgQAB4gHq8vqdbmRuAPqdZWR1APqldWNsYQD6nUtFWQD6lWNzAPq1\n\
// eWluZ2RpAPr1a3NrLTEzODI5ODY0MzQA+r1JRC1DRVJUAAAAAAABmiDlMIICCDAi\n\
// GA8yMDEzMTAyNzE4NTcwNloYDzIwMTQxMDI4MTg1NzA2WjCBuzAQBgNVBCkTCVlp\n\
// bmdkaSBZdTAfBgkqhkiG9w0BCQETEnlpbmdkaUBjcy51Y2xhLmVkdTAsBgNVBAsT\n\
// JVVuaXZlcnNpdHkgb2YgQ2FsaWZvcm5pYSwgTG9zIEFuZ2VsZXMwHAYDVQQBExVJ\n\
// bnRlcm5ldCBSZXNlYXJjaCBMYWIwJgYDVQQDEx9odHRwOi8vaXJsLmNzLnVjbGEu\n\
// ZWR1L355aW5nZGkvMBIGA1UEUBMLTGl4aWEgWmhhbmcwggEiMA0GCSqGSIb3DQEB\n\
// AQUAA4IBDwAwggEKAoIBAQC0IIZBY24PaN3vsquYhgWSKP5RaEJsM1RgzofZ/tgn\n\
// U3EpTMbvL4QQnMke2edbs+ZGcgarXiEL489Bqahyla4QDVuf3/UBaN+7ewxT/3kQ\n\
// Muu4J6tBhQ/JlbtOkS9uWDKULTmPchUxkZK8mtwIv6CPpvxoc831u6BmX3iGPUwq\n\
// GOIAVy9Rtv/Pgzvp3jbUqhsUAuGDf0sFz5ITxZNRXTGds4i30TWSQTj/zBIWaBd3\n\
// EjXxFO6OA7Nw2Q/+tBBTIaibU+2KQIiBZe8E3zT6By5aOywe7a70HWzg8McyWRBK\n\
// hTVpWW8qcI9Q/briLHEPFRLvc0A6Wlr0N6YBhD4A3bJtAgMBAAEAAA==");

//ndn ksk
// const string TrustAnchor("BIICqgOyEIVO5SFmlSEpRvKsTe3yXxAwqLev8nDH9kCp2D9fjirz/pMqt6YIiit7\n\
// KXdPOtY8uY5W5jAhXRfdoyV4Wc3jwTo0mvwWFPgB/4xE1FaQprEWffp8DKLW9HgN\n\
// PSHymhDSpMyNnE2uY0cAhom9JSnLu6qBr5W0qZFaY4anU8bYnVRV5t7W9UkYc8m9\n\
// edFAYwM32yrr/b00XZoGD/uPZDIonHP8jFPj9HFRXrt1JaMrH0Ytod4kxenR1DLG\n\
// GXvx8uFECDOvKA/JJfYSycTtuE87unuhwFlxmZbPU4gxdeUCgoM6THwJUnrNdGYb\n\
// 6dQsh/2xx0c4y4/xnQy5eHvlZ7pPq7S6AADy+p1uZG4A+p1LRVkA+vVrc2stMTM4\n\
// Mjk4NTAxMwD6vUlELUNFUlQA+s39/////+rX8d8AAAGiA+IChboOmvqcHWFFXPiQ\n\
// 5on1ysux2pjziB3GogWxiMYNtGpzAAK6tQUm6tfx4gAB4gHq8vqdbmRuAPqdS0VZ\n\
// APr1a3NrLTEzODI5ODUwMTMA+r1JRC1DRVJUAAAAAAABmhbVMIIBZjAiGA8yMDEz\n\
// MTAyODAwMDAwMFoYDzIwMzMxMDI4MDAwMDAwWjAcMBoGA1UEKRMTL25kbi9rc2st\n\
// MTM4Mjk4NTAxMzCCASAwDQYJKoZIhvcNAQEBBQADggENADCCAQgCggEBAM3/nfsZ\n\
// mIFyKO2Zo1uCJl+22iiKtxdlpYx3cYzJpNTP3p/SILL6Xmq2II6T0Zi+9LIAO+rU\n\
// gqxJ02Phltz77JjfTP5ZfSBd+woBPynY8EvCPPBdi5zub3NyHT+9ITyA99wR8e/P\n\
// B04OuJoWX86o3Yirn9FpPsQ1IWyNPkqEbW61m6w333UfpA0RKQiDzQzNKVUJ5K7A\n\
// z606GJRJjrvdePChnKcmgdutD2rbpcl700Nw/16u1FHgZsCYI/smZMeaLPWId4Y+\n\
// 4O+OhlFfWejEFkObr6mZeYrx/aV5qsPeFaVcg2toYW9iTrYWtd9HdUVyzcXlF6va\n\
// knBiwJLBYNLAkA0CAREAAA==");

//ndn dsk;
// const string TrustAnchor2("BIICqgOyEIUyI3oFcK3Yxq7i48RXSDV/v8yiVPgMst7WR/0lOrDffywG5vQO2aSb\n\
// Vqd3EzY97xuCs0ocevOeR7WSIv8gNqexC4E/2kCJEQp3JGZfc0r6MQVB2jp4YKws\n\
// A7fUSpeAEILSQ/d3LCPObrcH4DdS9GvnWtTUdzW3tbB/20Efu794a8Xzso+XUVpx\n\
// 3EqFr7vFa+y7d/rkNvwPlcQYI/okd1JLV27TwIdtr7EJxuJXTptZmyBg2/Qqrb6J\n\
// CrtBRIfH38z7vIhcLd6wsFBYofqBKi0k9Mzv6BEqERwraqeEkUh6cfyjoWdlFnsk\n\
// g/4CCuJ8BqgX22afBSVRS5ri48GPXwUXAADy+p1uZG4A+p1LRVkA+vVkc2stMTM4\n\
// Mjk4NTE1MwD6vUlELUNFUlQA+s39/////+rej+4AAAGiA+IChboOmvqcHWFFXPiQ\n\
// 5on1ysux2pjziB3GogWxiMYNtGpzAAK6tQUm6t6P7QAB4gHq8vqdbmRuAPqdS0VZ\n\
// APr1a3NrLTEzODI5ODUwMTMA+r1JRC1DRVJUAAAAAAABmhaVMIIBXjAiGA8yMDEz\n\
// MTAyNjAwMDAwMFoYDzIwMTQxMjMxMjM1OTU5WjAUMBIGA1UEKRMLTkROIFRlc3Ri\n\
// ZWQwggEgMA0GCSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQDlLtVS9MrNvJg2N0e8\n\
// B8FeHPT07Dma3oRP4gMXNGSPW+vxHgxXO8zS+LAJjZwY2UMIO8qQMYN9pTMmG31q\n\
// 0UohBWL0NHz0l+53KGa25ZAV4sIpvF8e8GfFyP0Ng0M1zlzCtrZKlmdaMkCoLBej\n\
// cMd0qABnpUVpRDReATQVqbxDpGoAASUKBtMPxKikIFuSzmUz/EJ1IofMRw4KhLBN\n\
// 47B0vfbxIKdSxgosgx/O0Ma3rthch7pCAFVjCSDRF04gmY/6uxb5mljvV8XPc3AO\n\
// YNaH4pRWMtAZ3k4w42TxO0eItTCn94dGAgu1AggGrx8Zkb/xVsZ+ljBgnx+5+hMr\n\
// AvENAgERAAA=");

Ptr<security::IdentityCertificate> 
getRoot()
{
  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(TrustAnchor.c_str()), 
			     TrustAnchor.size(), 
			     true,
                             new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  Ptr<Blob> blob = Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
  Ptr<Data> data = Data::decodeFromWire(blob);
  return Ptr<security::IdentityCertificate>(new security::IdentityCertificate(*data));
}

Ptr<security::IdentityCertificate> 
getRoot2()
{
  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(TrustAnchor2.c_str()), 
			     TrustAnchor2.size(), 
			     true,
                             new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  Ptr<Blob> blob = Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
  Ptr<Data> data = Data::decodeFromWire(blob);
  return Ptr<security::IdentityCertificate>(new security::IdentityCertificate(*data));
}

static void 
onVerified(Ptr<Data> data)
{ 
  string str(data->content().buf(), data->content().size());
  cerr << "receive data " << data->getName().toUri() << " with content: " << str << endl;
}

static void 
onUnverified(Ptr<Data> data)
{
  cerr << "received data cannot be verified!" << endl;
}

static void 
onTimeout(Ptr<Closure> closure, Ptr<Interest> interest)
{
  cerr << "interest timeout!" << endl;
}

int main(int argc, char** argv)	
{
  string name;
  string data;

  po::options_description desc("General Usage\n  ndnsec-test-fetch [-h] name\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("name,n", po::value<string>(&name), "data name, /ndn/ucla.edu/alice/chat")
    ;

  po::positional_options_description p;
  p.add("name", 1);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << endl;
      return 1;
    }

  try{
    using namespace ndn::security;
    
    Ptr<IdentityManager> identityManager = Ptr<IdentityManager>::Create();
    Ptr<SimplePolicyManager> policyManager = Ptr<SimplePolicyManager>(new SimplePolicyManager());
    Ptr<IdentityPolicyRule> rule1 = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>",
                                                                                  "^([^<KEY>]*)<KEY><dsk-.*><ID-CERT>$",
                                                                                  ">", "\\1\\2", "\\1", true));
    Ptr<IdentityPolicyRule> rule2 = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^([^<KEY>]*)<KEY><dsk-.*><ID-CERT>",
                                                                                   "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$",
                                                                                   "==", "\\1", "\\1\\2", true));
    Ptr<IdentityPolicyRule> rule3 = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^(<>*)$", 
                                                                                   "^([^<KEY>]*)<KEY><dsk-.*><ID-CERT>$", 
                                                                                   ">", "\\1", "\\1", true));

    policyManager->addVerificationPolicyRule(rule1);
    policyManager->addVerificationPolicyRule(rule2);
    policyManager->addVerificationPolicyRule(rule3);
    
    Ptr<IdentityCertificate> root = getRoot();
    Ptr<IdentityCertificate> root2 = getRoot2();
    
    if(PolicyManager::verifySignature(*root2, root->getPublicKeyInfo()))
      cerr << "verified" << endl;
    else
      cerr << "no" << endl;

    policyManager->addTrustAnchor(root);

    Ptr<Keychain> keychain = Ptr<Keychain>(new Keychain(identityManager,
							policyManager,
							NULL));

    Wrapper wrapper(keychain);
    
    Name interestName(name);
    Ptr<Interest> interest = Ptr<Interest>(new Interest(interestName));
    interest->setChildSelector(Interest::CHILD_RIGHT);

    Ptr<Closure> closure = Ptr<Closure>(new Closure(boost::bind(onVerified, _1),
						    boost::bind(onTimeout, _1, _2),
						    boost::bind(onUnverified, _1))
					);

    wrapper.sendInterest(interest, closure);

    sleep(10);
  }catch(exception& e){
    cerr << e.what() << endl;
  }
  return 0;
}
